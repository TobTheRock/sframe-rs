#![allow(clippy::unit_arg)]

use criterion::{black_box, criterion_group, BatchSize, Bencher, BenchmarkId, Criterion};
use rand::{thread_rng, Rng};
use sframe::{
    frame::{EncryptedFrame, MediaFrame, MediaFrameView},
    header::Counter,
    key::{DecryptionKey, EncryptionKey},
    CipherSuiteVariant,
};

const KEY_MATERIAL: &str = "THIS_IS_SOME_MATERIAL";
const KEY_ID: u64 = 42;
const BUF_OVERHEAD: usize = 128; //for tag+header, to avoid reallocation

fn payload_sizes() -> &'static [usize] {
    let ci = std::env::var("CI").ok();
    // TODO rather filter in the CI job instead of the env check
    if ci.is_some_and(|ci| ci == "true") {
        return &[5120];
    }

    &[512, 5120, 51200, 512000]
}

struct CryptoBenches {
    counter: Counter,

    crypt_buffer: Vec<u8>,
    enc_key: EncryptionKey,
    dec_key: DecryptionKey,

    variant: CipherSuiteVariant,
}

impl From<CipherSuiteVariant> for CryptoBenches {
    fn from(variant: CipherSuiteVariant) -> Self {
        let counter = rand::random();

        let enc_key = EncryptionKey::derive_from(variant, KEY_ID, KEY_MATERIAL).unwrap();
        let dec_key = DecryptionKey::derive_from(variant, KEY_ID, KEY_MATERIAL).unwrap();

        let max_payload_size = payload_sizes().iter().max().unwrap();
        let crypt_buffer = Vec::with_capacity(max_payload_size + BUF_OVERHEAD);

        Self {
            enc_key,
            dec_key,
            counter,
            crypt_buffer,
            variant,
        }
    }
}

impl CryptoBenches {
    fn run_benches(&mut self, c: &mut Criterion) {
        bench_over_payload_sizes(
            c,
            &format!("encrypt with {:?}", self.variant),
            |b, &payload_size| {
                b.iter_batched(
                    || create_random_media_frame(payload_size),
                    |unencrypted_payload| {
                        let media_frame =
                            MediaFrameView::new(self.counter, &unencrypted_payload);
                        let encrypted_frame = media_frame
                            .encrypt_into(&self.enc_key, &mut self.crypt_buffer)
                            .unwrap();
                        black_box(encrypted_frame);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        bench_over_payload_sizes(
            c,
            &format!("decrypt with {:?}", self.variant),
            |b, &payload_size| {
                b.iter_batched(
                    || encrypt_random_frame(payload_size, self.counter, &self.enc_key),
                    |encrypted_frame| {
                        let decrypted_frame = encrypted_frame
                            .decrypt_into(&self.dec_key, &mut self.crypt_buffer)
                            .unwrap();
                        black_box(decrypted_frame);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        c.bench_function(&format!("expand key with {:?}", self.variant), |b| {
            b.iter(|| {
                let key = EncryptionKey::derive_from(self.variant, KEY_ID, KEY_MATERIAL).unwrap();
                black_box(key);
            })
        });
    }
}

fn bench_over_payload_sizes<F>(c: &mut Criterion, name: &str, mut bench: F)
where
    F: FnMut(&mut Bencher, &usize),
{
    let mut group = c.benchmark_group(name);
    for payload_size in payload_sizes().iter() {
        group.throughput(criterion::Throughput::Bytes(*payload_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(payload_size),
            payload_size,
            &mut bench,
        );
    }
}

fn create_random_media_frame(size: usize) -> MediaFrame {
    let mut unencrypted_payload = vec![0; size];
    thread_rng().fill(unencrypted_payload.as_mut_slice());
    MediaFrame::new(thread_rng().gen::<Counter>(), unencrypted_payload)
}

fn encrypt_random_frame(
    size: usize,
    counter: Counter,
    enc_key: &EncryptionKey,
) -> EncryptedFrame {
    let unencrypted_payload = create_random_media_frame(size);
    let media_frame = MediaFrameView::new(counter, &unencrypted_payload);
    media_frame.encrypt(enc_key).unwrap()
}

fn crypto_benches(c: &mut Criterion) {
    for variant in [
        CipherSuiteVariant::AesGcm128Sha256,
        CipherSuiteVariant::AesGcm256Sha512,
        #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
        CipherSuiteVariant::AesCtr128HmacSha256_80,
        #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
        CipherSuiteVariant::AesCtr128HmacSha256_64,
        #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
        CipherSuiteVariant::AesCtr128HmacSha256_32,
    ] {
        let mut ctx = CryptoBenches::from(variant);
        ctx.run_benches(c);
    }
}

criterion_group!(benches, crypto_benches);
