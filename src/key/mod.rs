//! SFrame key definitions as of [RFC 9605 4.4.2](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.2)

/// Generic key implementation
pub mod crypto_key;
mod key_store;

pub use key_store::KeyStore;

// Type aliases for the selected crypto backend
cfg_if::cfg_if! {
    if #[cfg(all(feature = "ring", not(feature = "openssl"), not(feature = "rust-crypto")))] {
        /// AEAD implementation using the ring crypto backend.
        pub type Aead = crate::crypto::ring::Aead;
        /// Key derivation implementation using the ring crypto backend.
        pub type Kdf = crate::crypto::ring::Kdf;
        /// Encryption key using the ring crypto backend.
        pub type EncryptionKey = crypto_key::EncryptionKey<Aead, Kdf>;
        /// Decryption key using the ring crypto backend.
        pub type DecryptionKey = crypto_key::DecryptionKey<Aead, Kdf>;
    } else if #[cfg(all(feature = "openssl", not(feature = "ring"), not(feature = "rust-crypto")))] {
        /// AEAD implementation using the OpenSSL crypto backend.
        pub type Aead = crate::crypto::openssl::Aead;
        /// Key derivation implementation using the OpenSSL crypto backend.
        pub type Kdf = crate::crypto::openssl::Kdf;
        /// Encryption key using the OpenSSL crypto backend.
        pub type EncryptionKey = crypto_key::EncryptionKey<Aead, Kdf>;
        /// Decryption key using the OpenSSL crypto backend.
        pub type DecryptionKey = crypto_key::DecryptionKey<Aead, Kdf>;
    } else if #[cfg(all(feature = "rust-crypto", not(feature = "ring"), not(feature = "openssl")))] {
        /// AEAD implementation using the RustCrypto crypto backend.
        pub type Aead = crate::crypto::rust_crypto::Aead;
        /// Key derivation implementation using the RustCrypto crypto backend.
        pub type Kdf = crate::crypto::rust_crypto::Kdf;
        /// Encryption key using the RustCrypto backend.
        pub type EncryptionKey = crypto_key::EncryptionKey<Aead, Kdf>;
        /// Decryption key using the RustCrypto backend.
        pub type DecryptionKey = crypto_key::DecryptionKey<Aead, Kdf>;
    }
}
