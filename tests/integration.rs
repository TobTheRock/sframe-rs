use pretty_assertions::assert_eq;
use rand::{thread_rng, Rng};

use sframe::{receiver::Receiver, sender::Sender};

fn encrypt_decrypt_1000_frames(participant_id: u64, skipped_payload: usize) {
    let mut sender = Sender::new(participant_id);
    let key_material = "THIS_IS_SOME_MATERIAL";
    sender.set_encryption_key(key_material.as_bytes()).unwrap();

    let mut receiver = Receiver::default();
    receiver
        .set_encryption_key(participant_id, key_material.as_bytes())
        .unwrap();

    (0..1000).for_each(|_| {
        let mut media_frame = vec![0u8; 64];
        thread_rng().fill(media_frame.as_mut_slice());

        let encrypted_frame = sender
            .encrypt(media_frame.as_slice(), skipped_payload)
            .unwrap();

        let decrypted_frame = receiver.decrypt(encrypted_frame, skipped_payload).unwrap();

        assert_eq!(media_frame, decrypted_frame);
    });
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
