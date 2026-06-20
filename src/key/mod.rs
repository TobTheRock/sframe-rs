//! SFrame key definitions as of [RFC 9605 4.4.2](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.2)

/// Generic key implementation, which can be used with any crypto backend
pub mod crypto_key;
mod key_store;

pub use key_store::KeyStore;

// Re-exports for the crypto backend selected via feature flags. When no backend feature
// is enabled, only the generic types in [`crypto_key`] are exposed, so a custom crypto
// implementation can be plugged in.
cfg_if::cfg_if! {
    if #[cfg(crypto_backend)] {
        /// Encryption key using the crypto backend selected via feature flags.
        pub type EncryptionKey = crypto_key::EncryptionKey<crate::crypto::Aead, crate::crypto::Kdf>;
        /// Decryption key using the crypto backend selected via feature flags.
        pub type DecryptionKey = crypto_key::DecryptionKey<crate::crypto::Aead, crate::crypto::Kdf>;
    }
}
