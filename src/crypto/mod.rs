//! Cryptographic primitives and traits for SFrame as defined in [RFC 9605](https://www.rfc-editor.org/rfc/rfc9605.html).
//!
//! This module exposes the traits needed to implement custom crypto backends:
//! - [`AeadEncrypt`](crate::crypto::AeadEncrypt) and [`AeadDecrypt`](crate::crypto::AeadDecrypt) for AEAD encryption/decryption ([Section 4.4.3/4.4.4](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.3))
//! - [`KeyDerivation`](crate::crypto::KeyDerivation) for key derivation from base key material ([Section 4.4.2](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.2))

/// AEAD encryption and decryption traits ([RFC 9605 Section 4.4.3](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.3)).
pub(crate) mod aead;
/// Buffer types for AEAD operations ([RFC 9605 Section 4.4](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4)).
pub(crate) mod buffer;
/// Cipher suite definitions and parameters ([RFC 9605 Section 4.5](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.5)).
pub(crate) mod cipher_suite;
/// Key derivation traits and HKDF label functions ([RFC 9605 Section 4.4.2](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.2)).
pub(crate) mod key_derivation;

// Re-export everything a custom crypto backend needs to name: the traits and the buffer view
// types that appear in their method signatures. The modules themselves stay crate-private so the
// layout is an implementation detail.
pub use aead::{AeadDecrypt, AeadEncrypt};
pub use buffer::{DecryptionBufferView, EncryptionBufferView};
pub use key_derivation::{
    KeyDerivation, Ratcheting, get_hkdf_key_expand_label, get_hkdf_ratchet_expand_label,
    get_hkdf_salt_expand_label,
};

// Backend modules, selectable via features. None is also valid: in that case only the
// generic traits are exposed and a custom crypto backend has to be provided.
cfg_if::cfg_if! {
    if #[cfg(crypto_backend)] {
        /// Secret key material used by the built-in backends ([RFC 9605 Section 4.4.2](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.2)).
        /// Only present when a built-in backend is selected; custom backends define their own secret type.
        pub(crate) mod secret;
        // `Secret` is the default backends' associated secret type and must be exposed as a part of public the trait impls
        pub use secret::Secret;
    }
}
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
