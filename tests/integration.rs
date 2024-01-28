use pretty_assertions::assert_eq;
use rand::{thread_rng, Rng};

use sframe::{
    ratchet::{RatchetingBaseKey, RatchetingKeyId},
    receiver::{Receiver, ReceiverOptions},
    sender::Sender,
};

fn encrypt_decrypt_1000_frames(participant_id: u64, skipped_payload: usize) {
    let mut sender = Sender::new(participant_id);
    let key_material = "THIS_IS_SOME_MATERIAL";
    sender.set_encryption_key(key_material.as_bytes()).unwrap();

    let mut receiver = Receiver::default();
    receiver
        .set_encryption_key(participant_id, key_material.as_bytes())
        .unwrap();

    (0..1000)
        .for_each(|_| encrypt_decrypt_random_frame(&mut sender, &mut receiver, skipped_payload));
}

fn encrypt_decrypt_random_frame(
    sender: &mut Sender,
    receiver: &mut Receiver,
    skipped_payload: usize,
) {
    let mut media_frame = vec![0u8; 64];
    thread_rng().fill(media_frame.as_mut_slice());

    let encrypted_frame = sender
        .encrypt(media_frame.as_slice(), skipped_payload)
        .unwrap();

    let decrypted_frame = receiver.decrypt(encrypted_frame, skipped_payload).unwrap();

    assert_eq!(media_frame, decrypted_frame);
}

#[test]
fn decrypt_encrypted_frames_with_basic_key_id() {
    let sender_id = 4;
    let skipped_payload = 0;
    encrypt_decrypt_1000_frames(sender_id, skipped_payload);
}

#[test]
fn decrypt_encrypted_frames_with_basic_key_id_and_skipped_payload() {
    let sender_id = 4;
    let skipped_payload = 10;
    encrypt_decrypt_1000_frames(sender_id, skipped_payload);
}

#[test]
fn decrypt_encrypted_frames_with_extended_key_id() {
    let sender_id = 40;
    let skipped_payload = 0;
    encrypt_decrypt_1000_frames(sender_id, skipped_payload);
}

#[test]
fn decrypt_encrypted_frames_with_extended_key_id_and_skipped_payload() {
    let sender_id = 40;
    let skipped_payload = 10;
    encrypt_decrypt_1000_frames(sender_id, skipped_payload);
}

#[test]
fn ratchet_sender_key() {
    const N_RATCHET_BITS: u8 = 2;
    const GENERATION: u64 = 42;
    const SECRET: &[u8] = b"PSSST";
    let variant = sframe::CipherSuiteVariant::AesGcm256Sha512;

    let key_id = RatchetingKeyId::new(GENERATION, N_RATCHET_BITS);
    let mut base_key = RatchetingBaseKey::ratchet_forward(key_id, SECRET, variant)
        .expect("Failed to ratched forward");

    let mut sender = Sender::new(key_id);
    sender.set_encryption_key(SECRET).unwrap();

    let receiver_options = ReceiverOptions {
        cipher_suite_variant: variant,
        n_ratchet_bits: Some(N_RATCHET_BITS),
        frame_validation: Default::default(),
    };
    let mut receiver = Receiver::from(receiver_options);
    receiver.set_encryption_key(key_id, SECRET).unwrap();

    encrypt_decrypt_random_frame(&mut sender, &mut receiver, 0);

    // go for 2 full ratchet rounds
    for _i in 0..(2u64.pow(N_RATCHET_BITS as u32 + 1)) {
        // ratchet
        let (key_id, key_material) = base_key.next_base_key().unwrap();
        sender
            .ratchet_encryption_key(key_id, &key_material)
            .unwrap();

        // receiver should ratchet internally
        encrypt_decrypt_random_frame(&mut sender, &mut receiver, 0);
    }
}
