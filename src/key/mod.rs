//! # Keys
//!
//! `SFrame` keys as of [RFC 9605 Section 4.4.2](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.2):
//! derived from key material shared out of band, and carrying the Key ID that goes into the
//! `SFrame` header.
//!
//! With one of the backend features enabled, use `EncryptionKey` and `DecryptionKey`. They are
//! pinned to that backend, so the type parameters never have to be spelled out. Only when you
//! bring your own crypto (see [`crate::crypto`]) do you reach for [`GenericEncryptionKey`] and
//! [`GenericDecryptionKey`], which the two are aliases of.
//!
//! A receiver provides its keys to the frame API through the [`KeyStore`] trait, which every
//! shared reference to a [`KeyLookup`] is. For convenience [`KeyLookup`] is implemented for a
//! decryption key itself, so a call with a single sender needs nothing else, and for a
//! `HashMap<KeyId, DecryptionKey>`, which tells the senders of a call apart by their Key ID.
//!
//! ## Example
//!
//! ```rust
//! use std::collections::HashMap;
//! use sframe::{
//!     CipherSuite,
//!     header::KeyId,
//!     key::{DecryptionKey, EncryptionKey, KeyLookup},
//! };
//!
//! # fn main() -> sframe::error::Result<()> {
//! const CIPHER_SUITE: CipherSuite = CipherSuite::AesGcm256Sha512;
//!
//! let enc_key = EncryptionKey::derive_from(CIPHER_SUITE, 42u64, "pw123")?;
//!
//! // a receiver tells the senders of a call apart by their Key ID
//! let mut keys: HashMap<KeyId, DecryptionKey> = HashMap::new();
//! keys.insert(42, DecryptionKey::derive_from(CIPHER_SUITE, 42u64, "pw123")?);
//! keys.insert(43, DecryptionKey::derive_from(CIPHER_SUITE, 43u64, "pw456")?);
//!
//! assert!(keys.get_key(enc_key.key_id()).is_some());
//! assert!(keys.get_key(44u64).is_none());
//! # Ok(())
//! # }
//! ```

pub(crate) mod generic;
pub(crate) mod key_store;

pub use key_store::{KeyLookup, KeyNotFound, KeyStore};

pub use generic::{GenericDecryptionKey, GenericEncryptionKey};

// With a backend feature enabled the generic keys are additionally exposed as aliases pinned to
// that backend, so callers never spell out the type parameters.
cfg_if::cfg_if! {
    if #[cfg(crypto_backend)] {
        /// Encryption key using the crypto backend selected via feature flags.
        ///
        /// An alias of [`GenericEncryptionKey`], which documents the methods.
        pub type EncryptionKey = GenericEncryptionKey<crate::crypto::Aead, crate::crypto::Kdf>;
        /// Decryption key using the crypto backend selected via feature flags.
        ///
        /// An alias of [`GenericDecryptionKey`], which documents the methods.
        pub type DecryptionKey = GenericDecryptionKey<crate::crypto::Aead, crate::crypto::Kdf>;
    }
}
