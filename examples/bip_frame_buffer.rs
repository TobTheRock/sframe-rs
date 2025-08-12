use bbqueue::{
    BBBuffer,
    framed::{FrameConsumer, FrameGrantW, FrameProducer},
};
use cgisf_lib::{SentenceConfigBuilder, gen_sentence};
use rand::{Rng, rng};
use sframe::{
    CipherSuite,
    error::SframeError,
    frame::{EncryptedFrameView, FrameBuffer, MediaFrameView, MonotonicCounter, Truncate},
    key::{DecryptionKey, EncryptionKey},
};
use std::{thread, time::Duration};

const BUF_SIZE: usize = 1024;
static BIP_BUFFER: BBBuffer<BUF_SIZE> = BBBuffer::<1024>::new();

const SECRET: &[u8] = b"SUPER SECRET PW";
const KEY_ID: u64 = 42;
const CIPHER_SUITE: CipherSuite = CipherSuite::AesGcm256Sha512;
struct ProducerBuffer<'a, const N: usize> {
    producer: FrameProducer<'a, N>,
    samples_to_commit: usize,
    grant: Option<FrameGrantW<'a, N>>,
}

impl<const N: usize> FrameBuffer for ProducerBuffer<'_, N> {
    type BufferSlice = Self;

    fn allocate(&mut self, size: usize) -> sframe::error::Result<&mut Self::BufferSlice> {
        let grant = self
            .producer
            .grant(size)
            .map_err(|err| SframeError::Other(format!("Could not acquire grant {err:?}")))?;
        self.grant = Some(grant);
        self.samples_to_commit = size;

        Ok(self)
    }
}

impl<const N: usize> AsRef<[u8]> for ProducerBuffer<'_, N> {
    fn as_ref(&self) -> &[u8] {
        if let Some(grant) = &self.grant {
            grant
        } else {
            &[]
        }
    }
}

impl<const N: usize> AsMut<[u8]> for ProducerBuffer<'_, N> {
    fn as_mut(&mut self) -> &mut [u8] {
        if let Some(grant) = &mut self.grant {
            grant
        } else {
            &mut []
        }
    }
}

impl<const N: usize> Truncate for ProducerBuffer<'_, N> {
    fn truncate(&mut self, size: usize) {
        // note: not strictly necessary, truncate is only used for decryption
        self.samples_to_commit -= size;
    }
}
impl<const N: usize> ProducerBuffer<'_, N> {
    fn commit(&mut self) {
        if let Some(grant) = self.grant.take() {
            grant.commit(self.samples_to_commit);
        }
    }
}

fn sleep(name: &str) {
    // Sleep for a random time to simulate load
    let t = Duration::from_millis(rng().random_range(100..2000));
    println!("[{}] : Sleeping for {} ms", name, t.as_millis());
    thread::sleep(t);
}

fn producer_task(producer: FrameProducer<BUF_SIZE>) {
    let key = EncryptionKey::derive_from(CIPHER_SUITE, KEY_ID, SECRET).unwrap();
    let mut counter = MonotonicCounter::default();
    let mut buffer = ProducerBuffer {
        producer,
        samples_to_commit: 0,
        grant: None,
    };
    loop {
        let payload = gen_sentence(SentenceConfigBuilder::random().build());
        println!(
            "[Producer] Commiting frame # {} with payload '{}'",
            counter.current(),
            payload
        );

        let media_frame = MediaFrameView::new(&mut counter, &payload);

        if let Err(err) = media_frame.encrypt_into(&key, &mut buffer) {
            println!(
                "[Producer] Failed to encrypt frame # {} due to {}",
                counter.current(),
                err
            );
        }

        buffer.commit();

        sleep("Producer");
    }
}

fn consumer_task(mut consumer: FrameConsumer<BUF_SIZE>) {
    let key = DecryptionKey::derive_from(CIPHER_SUITE, KEY_ID, SECRET).unwrap();
    loop {
        // Read data from the buffer
        if let Some(grant) = consumer.read() {
            if let Ok(encrypted_frame) = EncryptedFrameView::try_new(grant.as_ref()) {
                let decrypted = encrypted_frame.decrypt(&key);
                if let Err(err) = decrypted {
                    println!(
                        "[Consumer] Failed to encrypt frame # {} due to {}",
                        encrypted_frame.header().counter(),
                        err
                    );
                    continue;
                }

                let decrypted = decrypted.unwrap();

                let payload = std::str::from_utf8(decrypted.payload()).unwrap();
                println!(
                    "[Consumer] Consumed frame # {}: {}",
                    encrypted_frame.header().counter(),
                    payload
                );

                grant.release();
            } else {
                println!("[Consumer] Invalid frame in buffer!");
            }
        } else {
            println!("[Consumer] No frame available!");
        }

        sleep("Consumer");
    }
}

fn main() {
    // Convert the buffer to a constant buffer for the producer thread
    let (producer, consumer) = BIP_BUFFER.try_split_framed().unwrap();

    // Spawn the producer thread
    let producer_thread = thread::spawn(move || {
        producer_task(producer);
    });

    // Spawn the consumer thread
    let consumer_thread = thread::spawn(move || {
        consumer_task(consumer);
    });

    // Wait for both threads to finish
    producer_thread.join().unwrap();
    consumer_thread.join().unwrap();
}
