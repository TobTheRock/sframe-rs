//! Helpers shared by the integration test targets.

#![allow(dead_code)]

use sframe::{
    CipherSuite,
    frame::{EncryptedFrame, EncryptedFrameView, MediaFrame, MediaFrameView, MonotonicCounter},
    key::{DecryptionKey, EncryptionKey},
};

pub const CIPHER_SUITE: CipherSuite = CipherSuite::AesGcm256Sha512;
pub const SECRET: &str = "SECRET";
pub const PAYLOAD: &[u8] = b"TIME TO PAY";
pub const OTHER_PAYLOAD: &[u8] = b"ALSO WORTH PAYING FOR";
pub const META_DATA: &[u8] = b"META";
pub const KEY_ID: u64 = 666;

/// the key pair of a sender, which its Key ID tells apart from the others
pub fn keys_of_sender(key_id: u64) -> (EncryptionKey, DecryptionKey) {
    (
        EncryptionKey::derive_from(CIPHER_SUITE, key_id, SECRET).unwrap(),
        DecryptionKey::derive_from(CIPHER_SUITE, key_id, SECRET).unwrap(),
    )
}

pub fn encrypt_once_as_view<'buf>(
    payload: &'buf [u8],
    key: &EncryptionKey,
    buffer: &'buf mut Vec<u8>,
) -> (MediaFrameView<'buf>, EncryptedFrameView<'buf>) {
    let mut counter = MonotonicCounter::default();
    let media_frame = MediaFrameView::try_new(&mut counter, payload).unwrap();
    media_frame.encrypt_into(key, &mut *buffer).unwrap();

    (media_frame, EncryptedFrameView::try_new(&*buffer).unwrap())
}

/// The owning counterpart of [`encrypt_once_as_view`], which allocates the frames itself.
pub fn encrypt_once(payload: &[u8], key: &EncryptionKey) -> (MediaFrame, EncryptedFrame) {
    let mut counter = MonotonicCounter::default();
    let media_frame = MediaFrame::try_new(&mut counter, payload).unwrap();
    let encrypted_frame = media_frame.encrypt(key).unwrap();

    (media_frame, encrypted_frame)
}

/// Flips a bit of the auth tag, so the frame no longer decrypts while its header - and with it
/// the counter and Key ID a receiver screens on - stays exactly as the sender wrote it.
pub fn tamper_with(frame: &EncryptedFrame) -> EncryptedFrame {
    let mut tampered = frame.as_ref().to_vec();
    *tampered.last_mut().unwrap() ^= 0x01;

    EncryptedFrame::try_new(tampered).unwrap()
}
