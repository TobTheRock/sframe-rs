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
