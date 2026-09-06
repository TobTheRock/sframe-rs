//! Ratcheting keys and key store as of [RFC 9605 Section 5.1](https://www.rfc-editor.org/rfc/rfc9605.html#section-5.1)

/// Generic ratcheting key implementations, usable with any crypto backend.
pub mod key;
mod key_id;
/// Generic ratcheting key material implementation, usable with any crypto backend.
pub mod key_material;
/// Generic ratcheting key store implementation, usable with any crypto backend.
pub mod key_store;
pub use key_id::{Generation, RatchetBits, RatchetStep, RatchetStepDiff, RatchetingKeyId};

// Default-backend aliases. When no backend feature is enabled only the generic types in the
// submodules are exposed, so a custom crypto backend can be plugged in.
cfg_if::cfg_if! {
    if #[cfg(crypto_backend)] {
        /// Ratcheting key store using the crypto backend selected via feature flags.
        pub type RatchetingKeyStore =
            key_store::RatchetingKeyStore<crate::crypto::Aead, crate::crypto::Kdf>;
        /// Ratcheting encryption key using the crypto backend selected via feature flags.
        pub type RatchetingEncryptionKey =
            key::RatchetingEncryptionKey<crate::crypto::Aead, crate::crypto::Kdf>;
        /// Ratcheting decryption key using the crypto backend selected via feature flags.
        pub type RatchetingDecryptionKey =
            key::RatchetingDecryptionKey<crate::crypto::Aead, crate::crypto::Kdf>;
        /// Ratcheting key material using the crypto backend selected via feature flags.
        pub type RatchetingKeyMaterial = key_material::RatchetingKeyMaterial<crate::crypto::Kdf>;
    }
}
