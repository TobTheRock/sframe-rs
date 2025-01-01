#![allow(dead_code)]

use std::{
    fmt::Write,
    io::{self, BufRead, Write as _},
};

mod counter_generator;
mod receiver;
mod sender;

use clap::{Parser, ValueEnum};
use receiver::{Receiver, ReceiverOptions};
use sender::{Sender, SenderOptions};
use sframe::{
    header::SframeHeader,
    ratchet::{RatchetingBaseKey, RatchetingKeyId},
    CipherSuiteVariant,
};

fn main() {
    let Args {
        cipher_suite,
        key_id,
        log_level,
        max_counter,
        secret,
        n_ratchet_bits,
    } = Args::parse();

    println!(
        "- Using cipher suite {:?}, key id {}, secret {}",
        cipher_suite, key_id, secret
    );

    if let Some(log_level) = log_level {
        println!("- Using log level {}", log_level);
        simple_logger::init_with_level(log_level).unwrap();
    }

    let cipher_suite_variant = cipher_suite.into();

    let (mut base_key, key_id) = if let Some(n_ratchet_bits) = n_ratchet_bits {
        // just to demonstrate the functionality, ratcheting should only take place if a new receiver joins
        println!("- Using {} bits for the ratcheting step", n_ratchet_bits);

        let r = RatchetingKeyId::new(key_id, n_ratchet_bits);
        let base_key =
            RatchetingBaseKey::ratchet_forward(r, secret.as_bytes(), cipher_suite_variant).unwrap();

        (Some(base_key), r.into())
    } else {
        (None, key_id)
    };

    let sender_options = SenderOptions {
        key_id,
        cipher_suite_variant,
        max_counter,
    };
    let mut sender = Sender::from(sender_options);
    sender.set_encryption_key(&secret).unwrap();

    let receiver_options = ReceiverOptions {
        cipher_suite_variant,
        frame_validation: None,
        n_ratchet_bits,
    };
    let mut receiver = Receiver::from(receiver_options);
    receiver.set_encryption_key(key_id, &secret).unwrap();

    let print_before_input = || {
        println!("--------------------------------------------------------------------------");
        println!("- Enter a phrase to be encrypted, confirm with [ENTER], abort with [CTRL+C]");
        print!("- To be encrypted:  ");
        std::io::stdout().flush().unwrap();
    };

    print_before_input();

    let stdin = io::stdin();
    let lines = stdin
        .lock()
        .lines()
        .take_while(Result::is_ok)
        .map(Result::unwrap);

    lines.for_each(|line| {
        if n_ratchet_bits.is_some() {
            let base_key = base_key.as_mut().unwrap();
            let (new_key_id, key_material) = base_key.next_base_key().unwrap();
            println!(
                "- Ratcheting sender key, ratcheting step: {}",
                new_key_id.ratchet_step()
            );
            sender
                .ratchet_encryption_key(new_key_id, &key_material)
                .unwrap();
        }

        println!("- Encrypting {}", bin2string(line.as_bytes()));
        let encrypted = sender.encrypt(line, 0).unwrap();
        display_encrypted(encrypted);

        let decrypted = receiver.decrypt(encrypted, 0).unwrap();
        println!("- Decrypted {}", bin2string(decrypted));

        print_before_input();
    });
}

fn display_encrypted(encrypted: &[u8]) {
    let header = SframeHeader::deserialize(encrypted).unwrap();
    println!("- Sframe Header: {}", header);

    let header_len = header.len();
    let payload = bin2string(&encrypted[header_len..]);
    println!("- Encrypted Payload: {}", payload)
}

fn bin2string(bin: &[u8]) -> String {
    bin.iter().fold(String::new(), |mut output, x| {
        let _ = write!(output, "{x:08b} ");
        output
    })
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(value_enum, short, long, default_value_t = ArgCipherSuiteVariant::AesGcm128Sha256)]
    cipher_suite: ArgCipherSuiteVariant,
    #[arg(short, long, default_value_t = 3)]
    key_id: u64,
    #[arg(short, long)]
    log_level: Option<log::Level>,
    #[arg(short, long, default_value_t = u64::MAX)]
    max_counter: u64,
    #[arg(short, long, default_value = "SUPER_SECRET")]
    secret: String,
    #[arg(short, long)]
    n_ratchet_bits: Option<u8>,
}

// We need to redeclare here, as we need to derive ValueEnum to use it with clap...
#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum ArgCipherSuiteVariant {
    #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
    AesCtr128HmacSha256_80,
    #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
    AesCtr128HmacSha256_64,
    #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
    AesCtr128HmacSha256_32,
    AesGcm128Sha256,
    AesGcm256Sha512,
}

impl From<ArgCipherSuiteVariant> for CipherSuiteVariant {
    fn from(val: ArgCipherSuiteVariant) -> Self {
        match val {
            #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
            ArgCipherSuiteVariant::AesCtr128HmacSha256_80 => {
                CipherSuiteVariant::AesCtr128HmacSha256_80
            }
            #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
            ArgCipherSuiteVariant::AesCtr128HmacSha256_64 => {
                CipherSuiteVariant::AesCtr128HmacSha256_64
            }
            #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
            ArgCipherSuiteVariant::AesCtr128HmacSha256_32 => {
                CipherSuiteVariant::AesCtr128HmacSha256_32
            }
            ArgCipherSuiteVariant::AesGcm128Sha256 => CipherSuiteVariant::AesGcm128Sha256,
            ArgCipherSuiteVariant::AesGcm256Sha512 => CipherSuiteVariant::AesGcm256Sha512,
        }
    }
}
