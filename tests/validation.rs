//! Covers the validation interface as the frame API drives it: a frame is screened before it is
//! decrypted and only recorded once it authenticated, so a forged frame cannot move the replay
//! window a genuine one is measured against.

#![cfg(crypto_backend)]

use std::convert::Infallible;

use mockall::{Sequence, mock};
use pretty_assertions::assert_eq;
use sframe::{
    error::SframeError,
    frame::validation::{
        FrameValidation, NoValidation, ReplayAttackProtection, Tolerance, UnvalidatedFrame,
    },
    header::KeyId,
};

mod common;
use common::{KEY_ID, PAYLOAD, encrypt_once, keys_of_sender, tamper_with};

mock! {
    Validation {}

    impl FrameValidation for Validation {
        type Token = ();
        type Error = Infallible;

        fn screen<'a>(&self, unvalidated: UnvalidatedFrame<'a>) -> Result<(), Infallible>;
        fn record(&mut self, token: ());
    }
}

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
fn screens_a_frame_before_decryption_and_records_it_after() {
    let (enc_key, dec_key) = keys_of_sender(KEY_ID);
    let (_, encrypted_frame) = encrypt_once(PAYLOAD, &enc_key);

    let mut order = Sequence::new();
    let mut validator = MockValidation::new();
    validator
        .expect_screen()
        .once()
        .in_sequence(&mut order)
        .returning(|_| Ok(()));
    validator
        .expect_record()
        .once()
        .in_sequence(&mut order)
        .return_const(());

    encrypted_frame
        .validated_decrypt(&dec_key, &mut validator)
        .expect("Expected to decrypt and validate");
}

#[test]
fn does_not_record_a_frame_which_did_not_decrypt() {
    let (enc_key, dec_key) = keys_of_sender(KEY_ID);
    let (_, encrypted_frame) = encrypt_once(PAYLOAD, &enc_key);
    let tampered_frame = tamper_with(&encrypted_frame);

    // screened, so the validator could have rejected it - but never recorded
    let mut validator = MockValidation::new();
    validator.expect_screen().once().returning(|_| Ok(()));
    validator.expect_record().never();

    tampered_frame
        .validated_decrypt(&dec_key, &mut validator)
        .unwrap_err();
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
