//! Ratcheting keys and key store as of [RFC 9605 Section 5.1](https://www.rfc-editor.org/rfc/rfc9605.html#section-5.1)

pub(crate) mod key;
pub(crate) mod key_id;
pub(crate) mod key_material;
pub(crate) mod key_store;

pub use key::{GenericRatchetingDecryptionKey, GenericRatchetingEncryptionKey};
pub use key_id::{Generation, RatchetBits, RatchetStep, RatchetStepDiff, RatchetingKeyId};
pub use key_material::GenericRatchetingKeyMaterial;
pub use key_store::GenericRatchetingKeyStore;

// With a backend feature enabled the generic ratcheting types are additionally exposed as aliases
// pinned to that backend, so callers never spell out the type parameters.
cfg_if::cfg_if! {
    if #[cfg(crypto_backend)] {
        /// Ratcheting key store using the crypto backend selected via feature flags.
        ///
        /// An alias of [`GenericRatchetingKeyStore`], which documents the methods.
        pub type RatchetingKeyStore =
            GenericRatchetingKeyStore<crate::crypto::Aead, crate::crypto::Kdf>;
        /// Ratcheting encryption key using the crypto backend selected via feature flags.
        ///
        /// An alias of [`GenericRatchetingEncryptionKey`], which documents the methods.
        pub type RatchetingEncryptionKey =
            GenericRatchetingEncryptionKey<crate::crypto::Aead, crate::crypto::Kdf>;
        /// Ratcheting decryption key using the crypto backend selected via feature flags.
        ///
        /// An alias of [`GenericRatchetingDecryptionKey`], which documents the methods.
        pub type RatchetingDecryptionKey =
            GenericRatchetingDecryptionKey<crate::crypto::Aead, crate::crypto::Kdf>;
        /// Ratcheting key material using the crypto backend selected via feature flags.
        ///
        /// An alias of [`GenericRatchetingKeyMaterial`], which documents the methods.
        pub type RatchetingKeyMaterial = GenericRatchetingKeyMaterial<crate::crypto::Kdf>;
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
