//! Covers ratcheting: a sender and a receiver stepping forward in lockstep, and a key store which
//! catches up on its own with a sender that ratcheted ahead.

#![cfg(crypto_backend)]

use sframe::{
    CipherSuite,
    frame::{MediaFrame, MonotonicCounter},
    ratchet::{
        RatchetBits, RatchetStepDiff, RatchetingDecryptionKey, RatchetingEncryptionKey,
        RatchetingKeyId, RatchetingKeyStore,
    },
};

const CIPHER_SUITE: CipherSuite = CipherSuite::AesGcm128Sha256;
const SECRET: &[u8] = b"SuperSecret";
const N_RATCHET_STEPS: u64 = 2;

fn n_ratchet_bits() -> RatchetBits {
    RatchetBits::new(4)
}

fn key_id() -> RatchetingKeyId {
    RatchetingKeyId::new(42u8, n_ratchet_bits())
}

#[test]
fn encryption_and_decryption_key_ratchet_in_lockstep() {
    let mut counter = MonotonicCounter::default();
    let mut enc_key = RatchetingEncryptionKey::derive_from(CIPHER_SUITE, key_id(), SECRET).unwrap();
    for _ in 0..N_RATCHET_STEPS {
        enc_key = enc_key.ratchet().unwrap();
    }
    // the receiver catches up with the Ratchet Step of the sender in one go
    let dec_key = RatchetingDecryptionKey::derive_from(CIPHER_SUITE, key_id(), SECRET)
        .unwrap()
        .ratchet_to(enc_key.key_id(), RatchetStepDiff::from(N_RATCHET_STEPS))
        .unwrap();

    let media_frame = MediaFrame::try_new(&mut counter, b"ratcheted payload").unwrap();
    let encrypted_frame = media_frame.encrypt(enc_key.as_ref()).unwrap();

    assert_eq!(media_frame, encrypted_frame.decrypt(&dec_key).unwrap());
}

#[test]
fn catches_up_with_the_senders_ratchet_step_and_keeps_that_key() {
    let mut counter = MonotonicCounter::default();
    let enc_key = RatchetingEncryptionKey::derive_from(CIPHER_SUITE, key_id(), SECRET)
        .unwrap()
        .ratchet()
        .unwrap();
    let mut keys = RatchetingKeyStore::new(n_ratchet_bits(), RatchetStepDiff::from(2));
    keys.insert(RatchetingDecryptionKey::derive_from(CIPHER_SUITE, key_id(), SECRET).unwrap());

    let media_frame = MediaFrame::try_new(&mut counter, b"ratcheted payload").unwrap();
    let encrypted_frame = media_frame.encrypt(enc_key.as_ref()).unwrap();

    // the sender is one Ratchet Step ahead of the stored key, which the store follows on
    // its own to decrypt the frame
    let decrypted = encrypted_frame.decrypt(&mut keys).unwrap();

    assert_eq!(media_frame, decrypted);
    // and it keeps the key it ratcheted forward to, for the frames to come
    assert_eq!(
        enc_key.key_id(),
        keys.get(key_id().generation()).unwrap().key_id()
    );
}
