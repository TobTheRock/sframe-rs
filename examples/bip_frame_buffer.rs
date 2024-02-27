use bbqueue::{
    framed::{FrameConsumer, FrameGrantW, FrameProducer},
    BBBuffer,
};
use cgisf_lib::{gen_sentence, SentenceConfigBuilder};
use rand::{thread_rng, Rng};
use sframe::{
    error::SframeError,
    frame::{
        encrypted_frame::EncryptedFrameView, frame_buffer::Truncate, media_frame::MediaFrameView,
        FrameBuffer,
    },
    key::SframeKey,
    CipherSuiteVariant,
};
use std::{thread, time::Duration};

const BUF_SIZE: usize = 1024;
static BIP_BUFFER: BBBuffer<BUF_SIZE> = BBBuffer::<1024>::new();

const SECRET: &[u8] = b"SUPER SECRET PW";
const KEY_ID: u64 = 42;
const VARIANT: CipherSuiteVariant = CipherSuiteVariant::AesGcm256Sha512;
struct ProducerBuffer<'a, const N: usize> {
    producer: FrameProducer<'a, N>,
    samples_to_commit: usize,
    grant: Option<FrameGrantW<'a, N>>,
}

impl<'a, const N: usize> FrameBuffer for ProducerBuffer<'a, N> {
    type BufferSlice = Self;

    fn allocate(&mut self, size: usize) -> sframe::error::Result<&mut Self::BufferSlice> {
        let grant = self
            .producer
            .grant(size)
            .map_err(|err| SframeError::Other(format!("Could not acquire grant {:?}", err)))?;
        self.grant = Some(grant);
        self.samples_to_commit = size;

        Ok(self)
    }
}

impl<'a, const N: usize> AsRef<[u8]> for ProducerBuffer<'a, N> {
    fn as_ref(&self) -> &[u8] {
        if let Some(grant) = &self.grant {
            grant
        } else {
            &[]
        }
    }
}

impl<'a, const N: usize> AsMut<[u8]> for ProducerBuffer<'a, N> {
    fn as_mut(&mut self) -> &mut [u8] {
        if let Some(grant) = &mut self.grant {
            grant
        } else {
            &mut []
        }
    }
}

impl<'a, const N: usize> Truncate for ProducerBuffer<'a, N> {
    fn truncate(&mut self, size: usize) {
        // note: not strictly necessary, truncate is only used for decryption
        self.samples_to_commit -= size;
    }
}
impl<'a, const N: usize> ProducerBuffer<'a, N> {
    fn commit(&mut self) {
        if let Some(grant) = self.grant.take() {
            grant.commit(self.samples_to_commit);
        }
    }
}

fn sleep(name: &str) {
    // Sleep for a random time to simulate load
    let t = Duration::from_millis(thread_rng().gen_range(100..2000));
    println!("[{}] : Sleeping for {} ms", name, t.as_millis());
    thread::sleep(t);
}

fn producer_task(producer: FrameProducer<BUF_SIZE>) {
    let key = SframeKey::expand_from(VARIANT, KEY_ID, SECRET).unwrap();
    let mut frame_count: u64 = 0;
    let mut buffer = ProducerBuffer {
        producer,
        samples_to_commit: 0,
        grant: None,
    };
    loop {
        let payload = gen_sentence(SentenceConfigBuilder::random().build());
        println!(
            "[Producer] Commiting frame # {} with payload '{}'",
            frame_count, payload
        );

        let media_frame = MediaFrameView::new(frame_count, &payload);

        if let Err(err) = media_frame.encrypt_into(&key, &mut buffer) {
            println!(
                "[Producer] Failed to encrypt frame # {} due to {}",
                frame_count, err
            );
        }

        buffer.commit();
        frame_count += 1;

        sleep("Producer");
    }
}

fn consumer_task(mut consumer: FrameConsumer<BUF_SIZE>) {
    let mut key = SframeKey::expand_from(VARIANT, KEY_ID, SECRET).unwrap();
    loop {
        // Read data from the buffer
        if let Some(grant) = consumer.read() {
            if let Ok(encrypted_frame) = EncryptedFrameView::new(grant.as_ref()) {
                let decrypted = encrypted_frame.decrypt(&mut key);
                if let Err(err) = decrypted {
                    println!(
                        "[Consumer] Failed to encrypt frame # {} due to {}",
                        encrypted_frame.header().frame_count(),
                        err
                    );
                    continue;
                }

                let decrypted = decrypted.unwrap();

                // note: on could also use the MediaFrameView result from decrypt_into to access the data
                let payload = std::str::from_utf8(decrypted.payload()).unwrap();
                println!(
                    "[Consumer] Consumed frame # {}: {}",
                    encrypted_frame.header().frame_count(),
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
