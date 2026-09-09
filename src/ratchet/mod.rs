//! # Ratcheting
//!
//! Ratcheting keys as of [RFC 9605 Section 5.1](https://www.rfc-editor.org/rfc/rfc9605.html#section-5.1):
//! the sender derives the next key from the current one instead of distributing a new one, so a
//! member who left the call cannot decrypt what follows.
//!
//! A [`RatchetingKeyId`] splits the 64 bit `SFrame` Key ID in two, using `R` bits
//! ([`RatchetBits`]) for the Ratchet Step and the rest for the Key Generation:
//!
//! ```text
//!  64-R bits          R bits
//! <-----------------><------>
//! +------------------+------+
//! |  Key Generation  | Step |
//! +------------------+------+
//! ```
//!
//! - the **Key Generation** ([`Generation`]) changes when the application distributes new key
//!   material, and is what a receiver stores a key under
//! - the **Ratchet Step** ([`RatchetStep`]) changes on every `ratchet` of a
//!   `RatchetingEncryptionKey` and wraps around after `2^R - 1`
//!
//! Receivers keep one key per Key Generation in a `RatchetingKeyStore` and catch up with the
//! Ratchet Step of an incoming frame. That step comes from an unauthenticated header, so the
//! store bounds how far it will catch up per frame and only keeps the ratcheted key once the
//! frame decrypted. It is a [`KeyStore`](crate::key::KeyStore) like any other, so the frame API
//! takes it directly - mutably, as it ratchets.
//!
//! ## Example
//!
//! ```rust
//! use sframe::{
//!     CipherSuite,
//!     frame::{MediaFrame, MonotonicCounter},
//!     ratchet::{
//!         Generation, RatchetBits, RatchetStepDiff, RatchetingDecryptionKey,
//!         RatchetingEncryptionKey, RatchetingKeyId, RatchetingKeyStore,
//!     },
//! };
//!
//! # fn main() -> sframe::error::Result<()> {
//! const CIPHER_SUITE: CipherSuite = CipherSuite::AesGcm256Sha512;
//! // how many bits carry the Ratchet Step is agreed on for the session
//! let n_ratchet_bits = RatchetBits::new(4);
//! let key_id = RatchetingKeyId::new(Generation::from(42u64), n_ratchet_bits);
//!
//! let enc_key = RatchetingEncryptionKey::derive_from(CIPHER_SUITE, key_id, "pw123")?;
//!
//! // the receiver stores the key of the Key Generation, catching up at most 2 steps per frame
//! let mut keys = RatchetingKeyStore::new(n_ratchet_bits, RatchetStepDiff::from(2));
//! keys.insert(RatchetingDecryptionKey::derive_from(CIPHER_SUITE, key_id, "pw123")?);
//!
//! // a member leaves: the sender ratchets forward and encrypts with the new key
//! let enc_key = enc_key.ratchet()?;
//!
//! let mut counter = MonotonicCounter::default();
//! let media_frame = MediaFrame::try_new(&mut counter, "Something secret")?;
//! let encrypted_frame = media_frame.encrypt(enc_key.as_ref())?;
//!
//! // the store reads the Ratchet Step off the header and catches up with it, keeping the
//! // ratcheted key only because the frame decrypted
//! let decrypted = encrypted_frame.decrypt(&mut keys)?;
//!
//! assert_eq!(decrypted.payload(), b"Something secret");
//! # Ok(())
//! # }
//! ```
//!
//! The `sender_receiver` example wires this into a full session, including the replay protection
//! a ratcheting receiver needs.
//!
//! As with [`crate::key`], the types are generic over the crypto backend
//! ([`GenericRatchetingEncryptionKey`] and friends). The names used above are aliases pinned to
//! the backend feature in use.

pub(crate) mod key;
pub(crate) mod key_id;
pub(crate) mod key_material;
pub(crate) mod key_store;

pub use key::{GenericRatchetingDecryptionKey, GenericRatchetingEncryptionKey};
pub use key_id::{Generation, RatchetBits, RatchetStep, RatchetStepDiff, RatchetingKeyId};
pub use key_material::GenericRatchetingKeyMaterial;
pub use key_store::{GenericRatchetingKeyStore, RatchetingKeyStoreError};

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
            RatchetingKeyId, RatchetingKeyStore,
        },
    };
    use pretty_assertions::assert_eq;

    const SECRET: &[u8] = b"SuperSecret";
    const CIPHER_SUITE: CipherSuite = CipherSuite::AesGcm128Sha256;
    const N_RATCHET_STEPS: u64 = 2;

    fn n_ratchet_bits() -> RatchetBits {
        RatchetBits::new(4)
    }

    fn key_id() -> RatchetingKeyId {
        RatchetingKeyId::new(42u8, n_ratchet_bits())
    }

    #[test]
    fn catches_up_with_the_senders_ratchet_step_and_keeps_that_key() {
        let mut counter = MonotonicCounter::default();
        let enc_key = RatchetingEncryptionKey::derive_from(CIPHER_SUITE, key_id(), SECRET)
            .unwrap()
            .ratchet()
            .unwrap();
        let mut keys = RatchetingKeyStore::new(n_ratchet_bits(), RatchetStepDiff::from(2));
        keys.insert(RatchetingDecryptionKey::derive_from(CIPHER_SUITE, key_id(), SECRET).unwrap());

        let media_frame = MediaFrame::try_new(&mut counter, b"ratcheted payload").unwrap();
        let encrypted_frame = media_frame.encrypt(enc_key.as_ref()).unwrap();

        // the sender is one Ratchet Step ahead of the stored key, which the store follows on
        // its own to decrypt the frame
        let decrypted = encrypted_frame.decrypt(&mut keys).unwrap();

        assert_eq!(media_frame, decrypted);
        // and it keeps the key it ratcheted forward to, for the frames to come
        assert_eq!(
            enc_key.key_id(),
            keys.get(key_id().generation()).unwrap().key_id()
        );
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
