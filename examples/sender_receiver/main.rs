#![allow(dead_code)]

use std::{
    fmt::Write,
    io::{self, BufRead, Write as _},
};

mod receiver;
mod sender;

/// Bits of the key id which hold the ratchet step, see [RFC 9605 5.1](https://www.rfc-editor.org/rfc/rfc9605.html#section-5.1).
///
/// Four leaves the ratchet step in the low nibble of the key id and wraps into the
/// next key generation after 16 steps, so a short session already shows a rollover.
pub const N_RATCHET_BITS: u8 = 4;

use clap::{Parser, ValueEnum};
use receiver::{Receiver, ReceiverOptions};
use sender::{Sender, SenderOptions};
use sframe::{
    CipherSuite,
    header::SframeHeader,
    ratchet::{RatchetingBaseKey, RatchetingKeyId},
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

    println!("- Using cipher suite {cipher_suite:?}, key id {key_id}, secret {secret}");

    if let Some(log_level) = log_level {
        println!("- Using log level {log_level}");
        simple_logger::init_with_level(log_level).unwrap();
    }

    let cipher_suite = cipher_suite.into();

    println!("- Using {n_ratchet_bits} bits for the ratcheting step");
    let ratcheting_key_id = RatchetingKeyId::new(key_id, n_ratchet_bits);
    let mut base_key =
        RatchetingBaseKey::ratchet_forward(ratcheting_key_id, secret.as_bytes(), cipher_suite)
            .unwrap();
    let key_id = ratcheting_key_id.into();

    let sender_options = SenderOptions {
        key_id,
        cipher_suite,
        max_counter,
    };
    let mut sender = Sender::from(sender_options);
    sender.set_encryption_key(&secret).unwrap();

    let receiver_options = ReceiverOptions {
        cipher_suite,
        n_ratchet_bits,
        ..Default::default()
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
        // just to demonstrate the functionality, ratcheting should only take place if a new receiver joins
        let (new_key_id, key_material) = base_key.next_base_key().unwrap();
        println!(
            "- Ratcheting sender key, ratcheting step: {}",
            new_key_id.ratchet_step()
        );
        sender
            .ratchet_encryption_key(new_key_id, &key_material)
            .unwrap();

        println!("- Encrypting {}", bin2string(line.as_bytes()));
        let encrypted = sender.encrypt(line, 0).unwrap();
        display_encrypted(encrypted);

        decrypt_and_display(&mut receiver, encrypted);
        // just to demonstrate the replay protection, the very same frame is fed in again
        decrypt_and_display(&mut receiver, encrypted);

        print_before_input();
    });
}

fn decrypt_and_display(receiver: &mut Receiver, encrypted: &[u8]) {
    match receiver.decrypt(encrypted, 0).unwrap() {
        Some(decrypted) => println!("- Decrypted {}", bin2string(decrypted)),
        None => println!("- Dropped replayed frame"),
    }
}

fn display_encrypted(encrypted: &[u8]) {
    let header = SframeHeader::deserialize(encrypted).unwrap();
    println!("- Sframe Header: {header}");

    let header_len = header.len();
    let payload = bin2string(&encrypted[header_len..]);
    println!("- Encrypted Payload: {payload}")
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
    #[arg(short, long, default_value_t = N_RATCHET_BITS)]
    n_ratchet_bits: u8,
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

impl From<ArgCipherSuiteVariant> for CipherSuite {
    fn from(val: ArgCipherSuiteVariant) -> Self {
        match val {
            #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
            ArgCipherSuiteVariant::AesCtr128HmacSha256_80 => CipherSuite::AesCtr128HmacSha256_80,
            #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
            ArgCipherSuiteVariant::AesCtr128HmacSha256_64 => CipherSuite::AesCtr128HmacSha256_64,
            #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
            ArgCipherSuiteVariant::AesCtr128HmacSha256_32 => CipherSuite::AesCtr128HmacSha256_32,
            ArgCipherSuiteVariant::AesGcm128Sha256 => CipherSuite::AesGcm128Sha256,
            ArgCipherSuiteVariant::AesGcm256Sha512 => CipherSuite::AesGcm256Sha512,
        }
    }
}
