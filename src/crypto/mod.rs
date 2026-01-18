//! Cryptographic primitives and traits for SFrame.
//!
//! This module exposes the traits needed to implement custom crypto backends:
//! - [`AeadEncrypt`] and [`AeadDecrypt`] for AEAD encryption/decryption
//! - [`KeyDerivation`] for key derivation from base key material
//! - [`Secret`] for storing derived key material

pub mod aead;
pub mod buffer;
pub mod cipher_suite;
pub mod key_derivation;
pub mod secret;

// Re-export commonly used types
pub use aead::{AeadDecrypt, AeadEncrypt};
pub use cipher_suite::{CipherSuite, CipherSuiteParams};
pub use key_derivation::KeyDerivation;
pub use secret::Secret;

// Backend modules - exposed publicly for custom backend implementations
cfg_if::cfg_if! {
    if #[cfg(all(feature = "ring", not(feature = "openssl"), not(feature = "rust-crypto")))] {
        pub mod ring;
    } else if #[cfg(all(feature = "openssl", not(feature = "ring"), not(feature = "rust-crypto")))] {
        mod common;
        pub mod openssl;
    } else if #[cfg(all(feature = "rust-crypto", not(feature = "ring"), not(feature = "openssl")))] {
        mod common;
        pub mod rust_crypto;
    } else {
        compile_error!("Cannot configure multiple crypto backends at the same time.");
    }
}
