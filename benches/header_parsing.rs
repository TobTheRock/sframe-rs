// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use criterion::{black_box, criterion_group, Criterion};

use sframe::header::{SframeHeader};

fn header_serialization(c: &mut Criterion) {
    c.bench_function("serialize header with short key", |b| {
        let mut buffer = vec![0_u8; 4];
        let basic_header = SframeHeader::new(7, 0);
        b.iter(|| black_box(basic_header.serialize(&mut buffer)))
    });

    c.bench_function("serialize extended header", |b| {
        let mut buffer = vec![0_u8; 4];
        let extended_header = SframeHeader::new(128, 0);
        b.iter(|| black_box(extended_header.serialize(&mut buffer)))
    });

    c.bench_function("deserialize 1000 headers", |b| {
        let serialized_headers = (0..1000_u64)
            .map(|i| {
                let header = SframeHeader::new(i, i);
                let mut buffer = vec![0_u8; 4];
                header.serialize(&mut buffer).unwrap();
                buffer
            })
            .collect::<Vec<_>>();

        b.iter(move || {
            serialized_headers.iter().for_each(|header| {
                let h = SframeHeader::deserialize(header).unwrap();
                black_box(h);
            })
        })
    });
}

criterion_group!(benches, header_serialization);
