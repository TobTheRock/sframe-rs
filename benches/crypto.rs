#![allow(clippy::unit_arg)]
use criterion::{black_box, criterion_group, BatchSize, Bencher, BenchmarkId, Criterion};
use rand::{thread_rng, Rng};
use sframe::{receiver::Receiver, sender::Sender, CipherSuiteVariant};

const KEY_MATERIAL: &str = "THIS_IS_SOME_MATERIAL";
const PARTICIPANT_ID: u64 = 42;
const SKIP: usize = 0;
const PAYLOAD_SIZES: [usize; 4] = [512, 5120, 51200, 512000];

fn create_random_payload(size: usize) -> Vec<u8> {
    let mut unencrypted_payload = vec![0; size];
    thread_rng().fill(unencrypted_payload.as_mut_slice());
    unencrypted_payload
}
fn create_random_encrypted_payload(size: usize, sender: &mut Sender) -> Vec<u8> {
    sender
        .encrypt(create_random_payload(size), SKIP)
        .unwrap()
        .into()
}

struct CryptoBenches {
    sender: Sender,
    receiver: Receiver,
    variant: CipherSuiteVariant,
}

impl From<CipherSuiteVariant> for CryptoBenches {
    fn from(variant: CipherSuiteVariant) -> Self {
        let mut sender = Sender::with_cipher_suite(PARTICIPANT_ID, variant);
        let mut receiver = Receiver::with_cipher_suite(variant);

        sender.set_encryption_key(KEY_MATERIAL).unwrap();
        receiver
            .set_encryption_key(PARTICIPANT_ID, KEY_MATERIAL)
            .unwrap();

        Self {
            sender,
            receiver,
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
                    || create_random_payload(payload_size),
                    |unencrypted_payload| {
                        let encrypted_frame =
                            self.sender.encrypt(&unencrypted_payload, SKIP).unwrap();
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
                    || create_random_encrypted_payload(payload_size, &mut self.sender),
                    |encrypted_frame| {
                        let decrypted_frame =
                            self.receiver.decrypt(&encrypted_frame, SKIP).unwrap();
                        black_box(decrypted_frame);
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        c.bench_function(&format!("expand key with {:?}", self.variant), |b| {
            b.iter(|| {
                black_box(self.sender.set_encryption_key(KEY_MATERIAL).unwrap());
            })
        });
    }
}

fn bench_over_payload_sizes<F>(c: &mut Criterion, name: &str, mut bench: F)
where
    F: FnMut(&mut Bencher, &usize),
{
    let mut group = c.benchmark_group(name);
    for payload_size in PAYLOAD_SIZES.iter() {
        group.throughput(criterion::Throughput::Bytes(*payload_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(payload_size),
            payload_size,
            &mut bench,
        );
    }
}

fn crypto_benches(c: &mut Criterion) {
    for variant in [
        CipherSuiteVariant::AesGcm128Sha256,
        CipherSuiteVariant::AesGcm256Sha512,
        #[cfg(feature = "openssl")]
        CipherSuiteVariant::AesCtr128HmacSha256_80,
        #[cfg(feature = "openssl")]
        CipherSuiteVariant::AesCtr128HmacSha256_64,
        #[cfg(feature = "openssl")]
        CipherSuiteVariant::AesCtr128HmacSha256_32,
    ] {
        let mut ctx = CryptoBenches::from(variant);
        ctx.run_benches(c);
    }
}

criterion_group!(benches, crypto_benches);
