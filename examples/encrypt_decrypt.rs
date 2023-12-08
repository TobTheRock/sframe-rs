// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use std::{
    fmt::Write,
    io::{self, BufRead, Write as _},
};

use clap::{Parser, ValueEnum};
use sframe::{
    receiver::Receiver,
    sender::Sender,
    CipherSuiteVariant, header::SframeHeader,
};

fn main() {
    let Args {
        cipher_suite,
        key_id,
        secret,
        log_level,
    } = Args::parse();

    println!(
        "- Using cipher suite {:?}, key id {}, secret {}",
        cipher_suite, key_id, secret
    );

    if let Some(log_level) = log_level {
        println!("- Using log level {}", log_level);
        simple_logger::init_with_level(log_level).unwrap();
    }

    let mut sender = Sender::with_cipher_suite(key_id, cipher_suite.into());
    sender.set_encryption_key(&secret).unwrap();

    let mut receiver = Receiver::with_cipher_suite(cipher_suite.into());
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
    let header_len = header.len();
    // let first_byte = bin2string(&encrypted[0..1]);

    println!("- Sframe Header: ");
    // TODO 
    // match header {
    //     Header::Basic(_) => {
    //         let frame_count = bin2string(&encrypted[1..header_len]);
    //         let ctr_field_len = frame_count.len() + 1;

    //         println!("+-+-+-+-+-+-+-+-+{:-^1$}+", "", ctr_field_len);
    //         println!("|R| LEN |0| KID |{:^1$}|", "CTR", ctr_field_len);
    //         println!(
    //             "|{}|{:^5}|{}|{:^5}| {:^}|",
    //             first_byte.get(0..1).unwrap(),
    //             first_byte.get(1..4).unwrap(),
    //             first_byte.get(4..5).unwrap(),
    //             first_byte.get(5..8).unwrap(),
    //             frame_count
    //         );
    //         println!("+-+-+-+-+-+-+-+-+{:-^1$}+", "", ctr_field_len);
    //     }

    //     Header::Extended(_) => {
    //         let frame_count_len = header.frame_count().length_in_bytes() as usize;
    //         let frame_count = bin2string(&encrypted[header_len - frame_count_len..header_len]);
    //         let ctr_field_len = frame_count.len() + 1;

    //         let key_id = bin2string(&encrypted[1..header_len - frame_count_len]);
    //         let kid_field_len = key_id.len() + 1;

    //         println!(
    //             "+-+-+-+-+-+-+-+--+{:-^2$}+{:-^3$}+",
    //             "", "", kid_field_len, ctr_field_len
    //         );
    //         println!(
    //             "|R| LEN |1| KLEN |{:^2$}|{:^3$}|",
    //             "KID", "CTR", kid_field_len, ctr_field_len
    //         );
    //         println!(
    //             "|{}|{:^5}|{}|{:^6}| {:^}| {:^}|",
    //             first_byte.get(0..1).unwrap(),
    //             first_byte.get(1..4).unwrap(),
    //             first_byte.get(4..5).unwrap(),
    //             first_byte.get(5..8).unwrap(),
    //             key_id,
    //             frame_count
    //         );
    //         println!(
    //             "+-+-+-+-+-+-+-+--+{:-^2$}+{:-^3$}+",
    //             "", "", ctr_field_len, kid_field_len
    //         );
    //     }
    // }

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
    #[arg(short, long, default_value = "SUPER_SECRET")]
    secret: String,
    #[arg(short, long)]
    log_level: Option<log::Level>,
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
