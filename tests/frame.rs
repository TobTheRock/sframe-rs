//! Covers encrypting and decrypting through the frame API: the views which encrypt into a buffer
//! of the caller, the owned frames which allocate it themselves, frames carrying meta data in the
//! clear, and decryption against a key store - including that a store is only asked to keep a key
//! once the frame it was looked up for authenticated.

#![cfg(crypto_backend)]

use std::collections::HashMap;

use pretty_assertions::assert_eq;
use sframe::{
    crypto::{Aead, Kdf},
    frame::{EncryptedFrameView, MediaFrame, MediaFrameView, MonotonicCounter},
    header::KeyId,
    key::{DecryptionKey, KeyStore},
};

mod common;
use common::{
    KEY_ID, META_DATA, OTHER_PAYLOAD, PAYLOAD, encrypt_once, encrypt_once_as_view, keys_of_sender,
};

#[test]
fn encrypt_decrypt_frame_view() {
    let (enc_key, dec_key) = keys_of_sender(KEY_ID);
    let mut encrypt_buffer = Vec::new();
    let mut decrypt_buffer = Vec::new();
    let (media_frame, encrypted_frame) =
        encrypt_once_as_view(PAYLOAD, &enc_key, &mut encrypt_buffer);

    let decrypted_media_frame = encrypted_frame
        .decrypt_into(&dec_key, &mut decrypt_buffer)
        .unwrap();

    assert_eq!(decrypted_media_frame, media_frame);
}

#[test]
fn encrypt_decrypt_frame_view_with_meta_data() {
    let (enc_key, dec_key) = keys_of_sender(KEY_ID);
    let mut encrypt_buffer = Vec::new();
    let mut decrypt_buffer = Vec::new();
    let mut counter = MonotonicCounter::default();

    let media_frame = MediaFrameView::try_with_meta_data(&mut counter, PAYLOAD, META_DATA).unwrap();
    media_frame
        .encrypt_into(&enc_key, &mut encrypt_buffer)
        .unwrap();

    let (meta_data, encrypted) = encrypt_buffer.split_at(META_DATA.len());
    assert_eq!(meta_data, META_DATA);

    let encrypted_frame = EncryptedFrameView::try_with_meta_data(encrypted, META_DATA).unwrap();
    let decrypted_media_frame = encrypted_frame
        .decrypt_into(&dec_key, &mut decrypt_buffer)
        .unwrap();

    assert_eq!(decrypted_media_frame, media_frame);
}

#[test]
fn encrypt_decrypt_frame_with_meta_data() {
    let (enc_key, dec_key) = keys_of_sender(KEY_ID);
    let mut counter = MonotonicCounter::default();

    let media_frame = MediaFrame::try_with_meta_data(&mut counter, PAYLOAD, META_DATA).unwrap();
    let encrypted = media_frame.encrypt(&enc_key).unwrap();

    assert_eq!(encrypted.meta_data(), META_DATA);

    let decrypted_media_frame = encrypted.decrypt(&dec_key).unwrap();

    assert_eq!(decrypted_media_frame, media_frame);
}

#[test]
fn decrypts_with_a_key_store_holding_a_single_key() {
    let (enc_key, dec_key) = keys_of_sender(KEY_ID);
    // a store which only looks keys up is never borrowed mutably, it is passed shared
    let keys = HashMap::from([(KeyId::from(KEY_ID), dec_key)]);
    let mut encrypt_buffer = Vec::new();
    let mut decrypt_buffer = Vec::new();
    let (media_frame, encrypted_frame) =
        encrypt_once_as_view(PAYLOAD, &enc_key, &mut encrypt_buffer);

    let decrypted_media_frame = encrypted_frame
        .decrypt_into(&keys, &mut decrypt_buffer)
        .unwrap();

    assert_eq!(decrypted_media_frame, media_frame);
}

#[test]
fn decrypts_the_frames_of_two_senders_with_a_shared_key_store() {
    let other_key_id = KEY_ID + 1;
    let (enc_key, dec_key) = keys_of_sender(KEY_ID);
    let (other_enc_key, other_dec_key) = keys_of_sender(other_key_id);
    let keys = HashMap::from([
        (KeyId::from(KEY_ID), dec_key),
        (KeyId::from(other_key_id), other_dec_key),
    ]);
    let (media_frame, encrypted_frame) = encrypt_once(PAYLOAD, &enc_key);
    let (other_media_frame, other_encrypted_frame) = encrypt_once(OTHER_PAYLOAD, &other_enc_key);

    // the store is passed shared for both frames, it is still there for the second
    let decrypted = encrypted_frame.decrypt(&keys).unwrap();
    let other_decrypted = other_encrypted_frame.decrypt(&keys).unwrap();

    assert_eq!(decrypted, media_frame);
    assert_eq!(other_decrypted, other_media_frame);
}

struct TestKeyStore {
    recorded: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("burn")]
struct KeyNotAvailable;

impl KeyStore<Aead, Kdf> for &mut TestKeyStore {
    type Key = DecryptionKey;
    type Error = KeyNotAvailable;

    fn lookup(&self, _key_id: KeyId) -> Result<Self::Key, Self::Error> {
        Err(KeyNotAvailable)
    }

    fn record(&mut self, _key: Self::Key) {
        self.recorded = true;
    }
}

#[test]
fn passes_on_why_a_key_store_had_no_key() {
    let (enc_key, _) = keys_of_sender(KEY_ID);
    let (_, encrypted_frame) = encrypt_once(PAYLOAD, &enc_key);
    let mut store = TestKeyStore { recorded: false };

    let error = encrypted_frame.decrypt(&mut store).unwrap_err();

    // the store's own error survives decryption, to be named again by the receiver
    assert!(error.source_as::<KeyNotAvailable>().is_some());
    // a lookup which failed leaves nothing to record
    assert!(!store.recorded);
}
