//! Ratcheting key store and base key as of [RFC 9605 Section 5.1](https://www.rfc-editor.org/rfc/rfc9605.html#section-5.1)

/// Generic base key implementation, usable with any crypto backend.
pub mod ratcheting_base_key;
mod ratcheting_key_id;
/// Generic ratcheting key store implementation, usable with any crypto backend.
pub mod ratcheting_key_store;

pub use ratcheting_key_id::RatchetingKeyId;

// Default-backend aliases. When no backend feature is enabled only the generic types in the
// submodules are exposed, so a custom crypto backend can be plugged in.
cfg_if::cfg_if! {
    if #[cfg(crypto_backend)] {
        /// Ratcheting key store using the crypto backend selected via feature flags.
        pub type RatchetingKeyStore =
            ratcheting_key_store::RatchetingKeyStore<crate::crypto::Aead, crate::crypto::Kdf>;
        /// Ratcheting keys using the crypto backend selected via feature flags.
        pub type RatchetingKeys =
            ratcheting_key_store::RatchetingKeys<crate::crypto::Aead, crate::crypto::Kdf>;
        /// Ratcheting base key using the crypto backend selected via feature flags.
        pub type RatchetingBaseKey = ratcheting_base_key::RatchetingBaseKey<crate::crypto::Kdf>;
    }
}
