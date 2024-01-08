use criterion::criterion_main;

mod crypto;
mod header_parsing;

criterion_main!(header_parsing::benches, crypto::benches);
