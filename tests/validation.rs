//! Covers the validation interface as the frame API drives it: a frame is screened before it is
//! decrypted and only recorded once it authenticated.

#![cfg(crypto_backend)]

use pretty_assertions::assert_eq;
use sframe::frame::validation::NoValidation;

mod common;
use common::{KEY_ID, PAYLOAD, encrypt_once, keys_of_sender};

#[test]
fn decrypts_a_frame_a_validator_accepts() {
    let (enc_key, dec_key) = keys_of_sender(KEY_ID);
    let (media_frame, encrypted_frame) = encrypt_once(PAYLOAD, &enc_key);

    // `NoValidation` accepts everything - RFC 9605 leaves anti-replay to the receiver.
    let mut validator = NoValidation;
    let decrypted_media_frame = encrypted_frame
        .validated_decrypt(&dec_key, &mut validator)
        .expect("Expected to decrypt and validate");

    assert_eq!(decrypted_media_frame, media_frame);
}
