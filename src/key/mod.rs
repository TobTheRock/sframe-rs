//! SFrame key definitions as of [RFC 9605 4.4.2](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.2)

pub(crate) mod generic;
pub(crate) mod key_store;

pub use key_store::KeyStore;

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
