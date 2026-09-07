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

#[cfg(all(test, crypto_backend))]
mod test {
    use crate::{
        CipherSuite,
        frame::{MediaFrame, MonotonicCounter},
        ratchet::{
            RatchetBits, RatchetStepDiff, RatchetingDecryptionKey, RatchetingEncryptionKey,
            RatchetingKeyId,
        },
    };
    use pretty_assertions::assert_eq;

    const SECRET: &[u8] = b"SuperSecret";
    const CIPHER_SUITE: CipherSuite = CipherSuite::AesGcm128Sha256;
    const N_RATCHET_STEPS: u64 = 2;

    fn key_id() -> RatchetingKeyId {
        RatchetingKeyId::new(42u8, RatchetBits::new(4))
    }

    #[test]
    fn encryption_and_decryption_key_ratchet_in_lockstep() {
        let mut counter = MonotonicCounter::default();
        let mut enc_key =
            RatchetingEncryptionKey::derive_from(CIPHER_SUITE, key_id(), SECRET).unwrap();
        for _ in 0..N_RATCHET_STEPS {
            enc_key = enc_key.ratchet().unwrap();
        }
        // the receiver catches up with the Ratchet Step of the sender in one go
        let dec_key = RatchetingDecryptionKey::derive_from(CIPHER_SUITE, key_id(), SECRET)
            .unwrap()
            .ratchet_to(enc_key.key_id(), RatchetStepDiff::from(N_RATCHET_STEPS))
            .unwrap();

        let media_frame = MediaFrame::try_new(&mut counter, b"ratcheted payload").unwrap();
        let encrypted_frame = media_frame.encrypt(enc_key.as_ref()).unwrap();

        assert_eq!(media_frame, encrypted_frame.decrypt(&dec_key).unwrap());
    }
}
