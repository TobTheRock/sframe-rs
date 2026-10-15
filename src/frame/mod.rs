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

mod aad;
mod encrypted_frame;
mod frame_buffer;
mod frame_counter;
mod media_frame;

pub mod validation;

pub use encrypted_frame::{EncryptedFrame, EncryptedFrameView};
pub use frame_buffer::{FrameBuffer, Truncate};
pub use frame_counter::{
    CounterExhausted, CounterUsed, FrameCounter, MonotonicCounter, PanickingMonotonicCounter,
    PanickingSingleUseCounter, SingleUseCounter,
};
pub use media_frame::{MediaFrame, MediaFrameView};

#[cfg(all(test, crypto_backend))]
mod test {
    use super::{EncryptedFrame, MediaFrame, SingleUseCounter};
    use crate::{
        CipherSuite,
        key::{DecryptionKey, EncryptionKey},
        test_vectors::get_sframe_test_vector,
        util::test::assert_bytes_eq,
    };
    use test_case::test_case;

    #[test_case(CipherSuite::AesGcm128Sha256; "AesGcm128Sha256")]
    #[test_case(CipherSuite::AesGcm256Sha512; "AesGcm256Sha512")]
    #[cfg_attr(aes_ctr, test_case(CipherSuite::AesCtr128HmacSha256_80; "AesCtr128HmacSha256_80"))]
    #[cfg_attr(aes_ctr, test_case(CipherSuite::AesCtr128HmacSha256_64; "AesCtr128HmacSha256_64"))]
    #[cfg_attr(aes_ctr, test_case(CipherSuite::AesCtr128HmacSha256_32; "AesCtr128HmacSha256_32"))]
    fn encrypt_test_vector(cipher_suite: CipherSuite) {
        let test_vec = get_sframe_test_vector(&cipher_suite.to_string());
        let enc_key = EncryptionKey::from_test_vector(cipher_suite, test_vec);
        let mut counter = SingleUseCounter::new(test_vec.counter);

        let media_frame =
            MediaFrame::try_with_meta_data(&mut counter, &test_vec.plain_text, &test_vec.metadata)
                .unwrap();
        let encrypted_frame = media_frame.encrypt(&enc_key).unwrap();

        let sframe = &encrypted_frame.as_ref()[test_vec.metadata.len()..];
        assert_bytes_eq(sframe, &test_vec.cipher_text);
    }

    #[test_case(CipherSuite::AesGcm128Sha256; "AesGcm128Sha256")]
    #[test_case(CipherSuite::AesGcm256Sha512; "AesGcm256Sha512")]
    #[cfg_attr(aes_ctr, test_case(CipherSuite::AesCtr128HmacSha256_80; "AesCtr128HmacSha256_80"))]
    #[cfg_attr(aes_ctr, test_case(CipherSuite::AesCtr128HmacSha256_64; "AesCtr128HmacSha256_64"))]
    #[cfg_attr(aes_ctr, test_case(CipherSuite::AesCtr128HmacSha256_32; "AesCtr128HmacSha256_32"))]
    fn decrypt_test_vector(cipher_suite: CipherSuite) {
        let test_vec = get_sframe_test_vector(&cipher_suite.to_string());
        let dec_key = DecryptionKey::from_test_vector(cipher_suite, test_vec);

        let encrypted_frame =
            EncryptedFrame::try_with_meta_data(&test_vec.cipher_text, &test_vec.metadata).unwrap();
        let media_frame = encrypted_frame.decrypt(&dec_key).unwrap();

        assert_bytes_eq(media_frame.payload(), &test_vec.plain_text);
    }
}
