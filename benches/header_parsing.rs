// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use criterion::{black_box, criterion_group, Criterion};

use rand::{thread_rng, Rng};
use sframe::header::SframeHeader;

fn create_random_values(size: usize) -> Vec<u64> {
    let mut values = vec![0; size];
    thread_rng().fill(values.as_mut_slice());
    values
}

fn create_random_headers(size: usize) -> impl Iterator<Item = SframeHeader> {
    let random_key_ids = create_random_values(size);
    let random_frame_counts = create_random_values(size);

    random_key_ids
        .into_iter()
        .zip(random_frame_counts)
        .map(|(key_id, frame_count)| SframeHeader::new(key_id, frame_count))
}

fn header_serialization(c: &mut Criterion) {
    c.bench_function("serialize 1000 random headers", |b| {
        let headers = create_random_headers(1000);
        let mut headers_buffers = headers
            .map(|header| {
                let buffer = vec![0_u8; header.len()];
                (header, buffer)
            })
            .collect::<Vec<_>>();
        b.iter(move || {
            headers_buffers
                .iter_mut()
                .for_each(|(header, ref mut buffer)| header.serialize(buffer).unwrap())
        })
    });

    c.bench_function("deserialize 1000 random headers", |b| {
        let serialized_headers = create_random_headers(1000)
            .map(|header| {
                let mut buffer = vec![0_u8; header.len()];
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
