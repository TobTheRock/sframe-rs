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

// Re-export the traits and types needed to implement a custom crypto backend.
pub use aead::{AeadDecrypt, AeadEncrypt};
pub use key_derivation::{KeyDerivation, Ratcheting};
pub use secret::Secret;

// Backend modules, selectable via features. None is also valid: in that case only the
// generic traits are exposed and a custom crypto backend has to be provided.
cfg_if::cfg_if! {
    if #[cfg(ring_backend)] {
        pub(crate) mod ring;
        /// AEAD implementation of the default (ring) crypto backend.
        pub type Aead = ring::Aead;
        /// Key derivation implementation of the default (ring) crypto backend.
        pub type Kdf = ring::Kdf;
    } else if #[cfg(openssl_backend)] {
        mod common;
        pub(crate) mod openssl;
        /// AEAD implementation of the default (OpenSSL) crypto backend.
        pub type Aead = openssl::Aead;
        /// Key derivation implementation of the default (OpenSSL) crypto backend.
        pub type Kdf = openssl::Kdf;
    } else if #[cfg(rust_crypto_backend)] {
        mod common;
        pub(crate) mod rust_crypto;
        /// AEAD implementation of the default (`RustCrypto`) crypto backend.
        pub type Aead = rust_crypto::Aead;
        /// Key derivation implementation of the default (`RustCrypto`) crypto backend.
        pub type Kdf = rust_crypto::Kdf;
    }
}

#[cfg(any(
    all(feature = "ring", feature = "openssl"),
    all(feature = "ring", feature = "rust-crypto"),
    all(feature = "openssl", feature = "rust-crypto"),
))]
compile_error!("Cannot configure multiple crypto backends at the same time.");
