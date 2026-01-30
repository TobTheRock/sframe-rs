//! Cryptographic primitives and traits for SFrame as defined in [RFC 9605](https://www.rfc-editor.org/rfc/rfc9605.html).
//!
//! This module exposes the traits needed to implement custom crypto backends:
//! - [`AeadEncrypt`] and [`AeadDecrypt`] for AEAD encryption/decryption ([Section 4.4.3/4.4.4](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.3))
//! - [`KeyDerivation`] for key derivation from base key material ([Section 4.4.2](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.2))
//! - [`Secret`] for storing derived key material (`sframe_key` and `sframe_salt`)

/// AEAD encryption and decryption traits ([RFC 9605 Section 4.4.3](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.3)).
pub mod aead;
/// Buffer types for AEAD operations ([RFC 9605 Section 4.4](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4)).
pub mod buffer;
/// Cipher suite definitions and parameters ([RFC 9605 Section 4.5](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.5)).
pub mod cipher_suite;
/// Key derivation traits and HKDF label functions ([RFC 9605 Section 4.4.2](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.2)).
pub mod key_derivation;
/// Secret key material storage ([RFC 9605 Section 4.4.2](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.2)).
pub mod secret;

// Re-export commonly used types
pub use aead::{AeadDecrypt, AeadEncrypt};
pub use cipher_suite::CipherSuite;
pub use key_derivation::KeyDerivation;
pub use secret::Secret;

// Backend modules, selectable via features
cfg_if::cfg_if! {
    if #[cfg(all(feature = "ring", not(feature = "openssl"), not(feature = "rust-crypto")))] {
        pub(crate) mod ring;
    } else if #[cfg(all(feature = "openssl", not(feature = "ring"), not(feature = "rust-crypto")))] {
        mod common;
        pub(crate) mod openssl;
    } else if #[cfg(all(feature = "rust-crypto", not(feature = "ring"), not(feature = "openssl")))] {
        mod common;
        pub(crate) mod rust_crypto;
    } else {
        compile_error!("Cannot configure multiple crypto backends at the same time.");
    }
}
