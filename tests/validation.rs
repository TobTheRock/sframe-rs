//! Covers the validation interface as the frame API drives it: a frame is screened before it is
//! decrypted and only recorded once it authenticated, so a forged frame cannot move the replay
//! window a genuine one is measured against.

#![cfg(crypto_backend)]

use pretty_assertions::assert_eq;
use sframe::{
    error::SframeError,
    frame::validation::{NoValidation, ReplayAttackProtection, Tolerance},
    header::KeyId,
};

mod common;
use common::{KEY_ID, PAYLOAD, encrypt_once, keys_of_sender, tamper_with};

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

#[test]
fn a_frame_which_does_not_decrypt_leaves_the_replay_window_untouched() {
    let (enc_key, dec_key) = keys_of_sender(KEY_ID);
    let (media_frame, genuine_frame) = encrypt_once(PAYLOAD, &enc_key);
    // the frame as an attacker replays it off the wire: the header, and with it the counter the
    // validator screens on, is untouched - only the auth tag no longer matches
    let tampered_frame = tamper_with(&genuine_frame);

    let mut validator = ReplayAttackProtection::new(KeyId::from(KEY_ID), Tolerance::new(128));
    let error = tampered_frame
        .validated_decrypt(&dec_key, &mut validator)
        .unwrap_err();

    assert!(matches!(error, SframeError::DecryptionFailure));

    // screening the forged frame did not record its counter, so the genuine frame carrying that
    // same counter is not mistaken for a replay of it
    let decrypted = genuine_frame
        .validated_decrypt(&dec_key, &mut validator)
        .expect("Expected the genuine frame to still decrypt");

    assert_eq!(decrypted, media_frame);
}
