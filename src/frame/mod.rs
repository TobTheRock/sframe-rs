//! # Frame-based API
//!
//! This API provides low-level access to encryption and decryption at the frame level, offering more granular control.
//!
//! ## Usage
//!
//! It allows the use of arbitrary buffers, enabling the creation of views to avoid unnecessary copies:
//! - [`MediaFrameView`] for unencrypted data
//! - [`EncryptedFrameView`] for encrypted data
//!
//! For encryption and decryption, a buffer must be provided implementing the [`FrameBuffer`] trait to allocate the necessary memory.
//! For convenience, this trait has already been implemented for `Vec<u8>`.
//!
//! Additionally, owning variants with an internal buffer are available, which dynamically allocate the necessary memory for encryption and decryption:
//! - [`MediaFrame`] for unencrypted data
//! - [`EncryptedFrame`] for encrypted data
//!
//! ## Example
//!
//! ```rust
//! # use sframe::{CipherSuite, frame::MonotonicCounter, key::{DecryptionKey, EncryptionKey}};
//! # fn main() -> sframe::error::Result<()> {
//! # const CIPHER_SUITE: CipherSuite = CipherSuite::AesGcm256Sha512;
//! # let enc_key = EncryptionKey::derive_from(CIPHER_SUITE, 42u64, "pw123")?;
//! # let dec_key = DecryptionKey::derive_from(CIPHER_SUITE, 42u64, "pw123")?;
//! # let mut counter = MonotonicCounter::default();
//! use sframe::frame::MediaFrameView;
//!
//! // the buffers belong to the caller, sframe never allocates one of its own here
//! let mut encrypt_buffer = Vec::new();
//! let mut decrypt_buffer = Vec::new();
//!
//! let media_frame = MediaFrameView::try_new(&mut counter, "Something secret")?;
//! let encrypted_frame = media_frame.encrypt_into(&enc_key, &mut encrypt_buffer)?;
//! let decrypted_media_frame = encrypted_frame.decrypt_into(&dec_key, &mut decrypt_buffer)?;
//!
//! assert_eq!(decrypted_media_frame, media_frame);
//! # Ok(())
//! # }
//! ```
//!
//! Additionally, to see how the API is used with another buffer type,
//! you can check out the [bip_frame_buffer example](https://github.com/TobTheRock/sframe-rs/blob/main/examples/bip_frame_buffer.rs).
//!

mod encrypted_frame;
mod frame_buffer;
mod frame_counter;
mod media_frame;

pub mod validation;

pub use encrypted_frame::{EncryptedFrame, EncryptedFrameView};
pub use frame_buffer::{FrameBuffer, Truncate};
pub use frame_counter::{
    CounterExhausted, FrameCounter, MonotonicCounter, PanickingMonotonicCounter,
};
pub use media_frame::{MediaFrame, MediaFrameView};

#[cfg(all(test, crypto_backend))]
mod test {
    use std::collections::HashMap;

    use super::media_frame::MediaFrameView;
    use crate::{
        CipherSuite,
        frame::{
            MonotonicCounter, encrypted_frame::EncryptedFrameView, media_frame::MediaFrame,
            validation::NoValidation,
        },
        header::KeyId,
        key::{DecryptionKey, EncryptionKey},
        util::test::assert_bytes_eq,
    };
    use pretty_assertions::assert_eq;

    const CIPHER_SUITE: CipherSuite = CipherSuite::AesGcm256Sha512;
    const PAYLOAD: &[u8] = b"TIME TO PAY";
    const OTHER_PAYLOAD: &[u8] = b"ALSO WORTH PAYING FOR";
    const META_DATA: &[u8] = b"META";
    const KEY_ID: u64 = 666u64;

    /// the key pair of a sender, which its Key ID tells apart from the others
    fn keys_of_sender(key_id: u64) -> (EncryptionKey, DecryptionKey) {
        (
            EncryptionKey::derive_from(CIPHER_SUITE, key_id, "SECRET").unwrap(),
            DecryptionKey::derive_from(CIPHER_SUITE, key_id, "SECRET").unwrap(),
        )
    }

    fn encrypt_once_as_view<'buf>(
        payload: &'buf [u8],
        key: &EncryptionKey,
        buffer: &'buf mut Vec<u8>,
    ) -> (MediaFrameView<'buf>, EncryptedFrameView<'buf>) {
        let mut counter = MonotonicCounter::default();
        let media_frame = MediaFrameView::try_new(&mut counter, payload).unwrap();
        media_frame.encrypt_into(key, &mut *buffer).unwrap();

        (media_frame, EncryptedFrameView::try_new(&*buffer).unwrap())
    }

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
        let mut encrypt_buffer = Vec::new();
        let mut other_encrypt_buffer = Vec::new();
        let (media_frame, encrypted_frame) =
            encrypt_once_as_view(PAYLOAD, &enc_key, &mut encrypt_buffer);
        let (other_media_frame, other_encrypted_frame) =
            encrypt_once_as_view(OTHER_PAYLOAD, &other_enc_key, &mut other_encrypt_buffer);

        // the store is passed shared for both frames, it is still there for the second
        let mut decrypt_buffer = Vec::new();
        let decrypted = encrypted_frame
            .decrypt_into(&keys, &mut decrypt_buffer)
            .unwrap();
        let mut other_decrypt_buffer = Vec::new();
        let other_decrypted = other_encrypted_frame
            .decrypt_into(&keys, &mut other_decrypt_buffer)
            .unwrap();

        assert_eq!(decrypted, media_frame);
        assert_eq!(other_decrypted, other_media_frame);
    }

    #[test]
    fn validate_decrypt_frame_view() {
        let (enc_key, dec_key) = keys_of_sender(KEY_ID);
        let mut encrypt_buffer = Vec::new();
        let mut decrypt_buffer = Vec::new();
        let (media_frame, encrypted_frame) =
            encrypt_once_as_view(PAYLOAD, &enc_key, &mut encrypt_buffer);

        // `NoValidation` accepts everything - RFC 9605 leaves anti-replay to the receiver.
        let mut validator = NoValidation;
        let decrypted_media_frame = encrypted_frame
            .validated_decrypt_into(&dec_key, &mut decrypt_buffer, &mut validator)
            .expect("Expected to decrypt and validate");

        assert_eq!(decrypted_media_frame, media_frame);
    }

    #[test]
    fn encrypt_decrypt_frame_view_with_meta_data() {
        let (enc_key, dec_key) = keys_of_sender(KEY_ID);
        let mut encrypt_buffer = Vec::new();
        let mut decrypt_buffer = Vec::new();
        let mut counter = MonotonicCounter::default();

        let media_frame =
            MediaFrameView::try_with_meta_data(&mut counter, PAYLOAD, META_DATA).unwrap();
        media_frame
            .encrypt_into(&enc_key, &mut encrypt_buffer)
            .unwrap();

        let (meta_data, encrypted) = encrypt_buffer.split_at(META_DATA.len());
        assert_bytes_eq(meta_data, META_DATA);

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

        assert_bytes_eq(encrypted.meta_data(), META_DATA);

        let decrypted_media_frame = encrypted.decrypt(&dec_key).unwrap();

        assert_eq!(decrypted_media_frame, media_frame);
    }
}
