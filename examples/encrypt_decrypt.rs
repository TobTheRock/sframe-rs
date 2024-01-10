use std::{
    fmt::Write,
    io::{self, BufRead, Write as _},
};

use clap::{Parser, ValueEnum};
use sframe::{
    header::SframeHeader,
    receiver::{Receiver, ReceiverOptions},
    sender::{Sender, SenderOptions},
    CipherSuiteVariant,
};

fn main() {
    let Args {
        cipher_suite,
        key_id,
        log_level,
        max_frame_count,
        secret,
    } = Args::parse();

    println!(
        "- Using cipher suite {:?}, key id {}, secret {}",
        cipher_suite, key_id, secret
    );

    if let Some(log_level) = log_level {
        println!("- Using log level {}", log_level);
        simple_logger::init_with_level(log_level).unwrap();
    }

    let sender_options = SenderOptions {
        key_id,
        cipher_suite_variant: cipher_suite.into(),
        max_frame_count,
    };

    let mut sender = Sender::from(sender_options);
    sender.set_encryption_key(&secret).unwrap();

    let receiver_options = ReceiverOptions {
        cipher_suite_variant: cipher_suite.into(),
        frame_validation: None,
    };
    let mut receiver = Receiver::from(receiver_options);
    receiver
        .set_encryption_key(key_id, secret.as_bytes())
        .unwrap();

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

    lines.for_each(|l| {
        println!("- Encrypting {}", bin2string(l.as_bytes()));
        let encrypted = sender.encrypt(l, 0).unwrap();
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
    max_frame_count: u64,
    #[arg(short, long, default_value = "SUPER_SECRET")]
    secret: String,
}

// We need to redeclare here, as we need to derive ValueEnum to use it with clap...
#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum ArgCipherSuiteVariant {
    #[cfg(feature = "openssl")]
    AesCtr128HmacSha256_80,
    #[cfg(feature = "openssl")]
    AesCtr128HmacSha256_64,
    #[cfg(feature = "openssl")]
    AesCtr128HmacSha256_32,
    AesGcm128Sha256,
    AesGcm256Sha512,
}

impl From<ArgCipherSuiteVariant> for CipherSuiteVariant {
    fn from(val: ArgCipherSuiteVariant) -> Self {
        match val {
            #[cfg(feature = "openssl")]
            ArgCipherSuiteVariant::AesCtr128HmacSha256_80 => {
                CipherSuiteVariant::AesCtr128HmacSha256_80
            }
            #[cfg(feature = "openssl")]
            ArgCipherSuiteVariant::AesCtr128HmacSha256_64 => {
                CipherSuiteVariant::AesCtr128HmacSha256_64
            }
            #[cfg(feature = "openssl")]
            ArgCipherSuiteVariant::AesCtr128HmacSha256_32 => {
                CipherSuiteVariant::AesCtr128HmacSha256_32
            }
            ArgCipherSuiteVariant::AesGcm128Sha256 => CipherSuiteVariant::AesGcm128Sha256,
            ArgCipherSuiteVariant::AesGcm256Sha512 => CipherSuiteVariant::AesGcm256Sha512,
        }
    }
}
