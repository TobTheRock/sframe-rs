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
//! use sframe::{
//!     frame::{EncryptedFrameView, MediaFrameView, MonotonicCounter},
//!     key::{DecryptionKey, EncryptionKey},
//!     CipherSuiteVariant,
//! };
//!
//! let key_id = 42u64;
//! let enc_key = EncryptionKey::derive_from(CipherSuiteVariant::AesGcm256Sha512, key_id, "pw123").unwrap();
//! let mut counter = MonotonicCounter::default();
//! let payload = "Something secret";
//!
//! let mut encrypt_buffer = Vec::new();
//! let mut decrypt_buffer = Vec::new();
//! let media_frame = MediaFrameView::new(&mut counter, payload);
//!
//! let encrypted_frame = media_frame.encrypt_into(&enc_key, &mut encrypt_buffer).unwrap();
//!
//! let mut dec_key = DecryptionKey::derive_from(CipherSuiteVariant::AesGcm256Sha512, key_id, "pw123").unwrap();
//! let decrypted_media_frame = encrypted_frame
//!     .decrypt_into(&mut dec_key, &mut decrypt_buffer)
//!     .unwrap();
//!
//! assert_eq!(decrypted_media_frame, media_frame);
//! ```
//!
//! Additionally, to see how the API is used with another buffer type,
//! you can check out the [bip_frame_buffer example](https://github.com/TobTheRock/sframe-rs/blob/main/examples/bip_frame_buffer.rs).
//!

mod encrypted_frame;
mod frame_buffer;
mod frame_counter;
mod media_frame;
mod validation;

pub use encrypted_frame::{EncryptedFrame, EncryptedFrameView};
pub use frame_buffer::{FrameBuffer, Truncate};
pub use frame_counter::*;
pub use media_frame::{MediaFrame, MediaFrameView};
pub use validation::*;

#[cfg(test)]
mod test {
    use super::media_frame::MediaFrameView;
    use crate::{
        frame::{encrypted_frame::EncryptedFrameView, media_frame::MediaFrame, MonotonicCounter},
        key::{DecryptionKey, EncryptionKey},
        util::test::assert_bytes_eq,
        CipherSuiteVariant,
    };
    use pretty_assertions::assert_eq;

    const PAYLOAD: &[u8] = b"TIME TO PAY";
    const META_DATA: &[u8] = b"META";
    const KEY_ID: u64 = 666u64;

    fn expand_keys() -> (EncryptionKey, DecryptionKey) {
        (
            EncryptionKey::derive_from(CipherSuiteVariant::AesGcm256Sha512, KEY_ID, "SECRET")
                .unwrap(),
            DecryptionKey::derive_from(CipherSuiteVariant::AesGcm256Sha512, KEY_ID, "SECRET")
                .unwrap(),
        )
    }

    #[test]
    fn encrypt_decrypt_frame_view() {
        let (enc_key, dec_key) = expand_keys();
        let mut encrypt_buffer = Vec::new();
        let mut decrypt_buffer = Vec::new();
        let mut counter = MonotonicCounter::default();

        let media_frame = MediaFrameView::new(&mut counter, PAYLOAD);
        media_frame
            .encrypt_into(&enc_key, &mut encrypt_buffer)
            .unwrap();

        let encrypted_frame = EncryptedFrameView::try_new(&encrypt_buffer).unwrap();
        let decrypted_media_frame = encrypted_frame
            .decrypt_into(&dec_key, &mut decrypt_buffer)
            .unwrap();

        assert_eq!(decrypted_media_frame, media_frame);
    }

    #[test]
    fn encrypt_decrypt_frame_view_with_meta_data() {
        let (enc_key, dec_key) = expand_keys();
        let mut encrypt_buffer = Vec::new();
        let mut decrypt_buffer = Vec::new();
        let mut counter = MonotonicCounter::default();

        let media_frame = MediaFrameView::with_meta_data(&mut counter, PAYLOAD, META_DATA);
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
        let (enc_key, dec_key) = expand_keys();
        let mut counter = MonotonicCounter::default();

        let media_frame = MediaFrame::with_meta_data(&mut counter, PAYLOAD, META_DATA);
        let encrypted = media_frame.encrypt(&enc_key).unwrap();

        assert_bytes_eq(encrypted.meta_data(), META_DATA);

        let decrypted_media_frame = encrypted.decrypt(&dec_key).unwrap();

        assert_eq!(decrypted_media_frame, media_frame);
    }
}
