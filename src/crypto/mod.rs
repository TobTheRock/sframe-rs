//! # Crypto backends
//!
//! Only needed to bring your own crypto: with one of the `ring`, `openssl` or `rust-crypto`
//! features enabled, the backend is already wired up and nothing here has to be named.
//!
//! Without a backend feature, implement these three traits and parameterize
//! [`GenericEncryptionKey`](crate::key::GenericEncryptionKey) /
//! [`GenericDecryptionKey`](crate::key::GenericDecryptionKey) with your types:
//!
//! - [`AeadEncrypt`] and [`AeadDecrypt`] - encrypting and decrypting a frame in place
//!   ([RFC 9605 Section 4.4.3/4.4.4](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.3))
//! - [`KeyDerivation`] - expanding base key material into a secret
//!   ([RFC 9605 Section 4.4.2](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.2))
//! - [`Ratcheting`] - additionally, to support [`crate::ratchet`]
//!
//! All three receive the [`CipherSuite`](crate::CipherSuite) the key was derived with and take
//! their own associated secret type, so a backend is free to carry whatever its algorithm needs.
//! `get_hkdf_key_expand_label`, `get_hkdf_salt_expand_label` and `get_hkdf_ratchet_expand_label`
//! build the HKDF labels the RFC prescribes - use them to stay interoperable with other `SFrame`
//! implementations.
//!
//! The `custom-crypto-backend` example implements a (deliberately insecure) Caesar cipher backend
//! end to end.

/// AEAD encryption and decryption traits ([RFC 9605 Section 4.4.3](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.3)).
pub(crate) mod aead;
/// Buffer types for AEAD operations ([RFC 9605 Section 4.4](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4)).
pub(crate) mod buffer;
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
