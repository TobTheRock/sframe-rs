// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use sframe::header::SframeHeader;
use std::fmt::Write;

fn bin2string(bin: &[u8]) -> String {
    bin.iter().fold(String::new(), |mut output, x| {
        let _ = write!(output, "{x:08b} ");
        output
    })
}

fn main() {
    let limit = std::env::args()
        .nth(1)
        .and_then(|x| x.parse::<u16>().ok())
        .unwrap_or(10);

    for k in 0..limit as u64 {
        let header = SframeHeader::new(k, k);
        let mut buffer = vec![0u8; 4];
        header.serialize(&mut buffer).unwrap();
        println!("{:}", bin2string(&buffer));
        println!("{:?}", SframeHeader::deserialize(&buffer));
    }
}
