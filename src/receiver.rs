use std::collections::HashMap;

use crate::{
    crypto::{
        aead::AeadDecrypt,
        cipher_suite::{CipherSuite, CipherSuiteVariant},
        key_derivation::KeyDerivation,
        sframe_key::SframeKey,
    },
    error::{Result, SframeError},
    frame_validation::{FrameValidationBox, ReplayAttackProtection},
    header::{KeyId, SframeHeader},
    ratchet::RatchetingKeyStore,
};

/// options for the decryption block,
/// allows to create a [Receiver] object using [Into]/[From]
pub struct ReceiverOptions {
    /// decryption/ key expansion algorithm used, see [sframe draft 04 4.4](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-04#name-cipher-suites)
    ///
    /// default: [CipherSuiteVariant::AesGcm256Sha512]
    pub cipher_suite_variant: CipherSuiteVariant,
    /// optional frame validation before decryption, e.g to protect agains replay attacks
    ///
    /// default: [ReplayAttackProtection] with tolerance `128`
    pub frame_validation: Option<FrameValidationBox>,
    /// optional ratcheting support as of [sframe draft 04 5.1](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-04#section-5.1),
    /// using `n_ratchet_bits` to depict the Ratchet Step
    ///
    /// default: [None]
    pub n_ratchet_bits: Option<u8>,
}

impl Default for ReceiverOptions {
    fn default() -> Self {
        Self {
            cipher_suite_variant: CipherSuiteVariant::AesGcm256Sha512,
            frame_validation: Some(Box::new(ReplayAttackProtection::with_tolerance(128))),
            n_ratchet_bits: None,
        }
    }
}

/// Models the sframe decryption block in the receiver path, see [sframe draft 04 4.1](https://www.ietf.org/archive/id/draft-ietf-sframe-enc-04.html#name-application-context), by
/// - internally storing a map of encryption keys each associated with a key id ([`KeyId`])
/// - decrypting incoming `SFrame` frames using an internal buffer and the stored keys
/// - performing optional frame validation and ratcheting
pub struct Receiver {
    keys: KeyStore,
    cipher_suite: CipherSuite,
    frame_validation: Option<FrameValidationBox>,
    buffer: Vec<u8>,
}

impl Receiver {
    /// creates a [Receiver] with the given cipher suite variant and the default parameters
    pub fn with_cipher_suite(variant: CipherSuiteVariant) -> Receiver {
        log::debug!("Setting up sframe Receiver using ciphersuite {:?}", variant,);

        let options = ReceiverOptions {
            cipher_suite_variant: variant,
            ..Default::default()
        };

        options.into()
    }

    /// Tries to decrypt an incoming encrypted frame, returning a slice to the decrypted data on success.
    /// The first `skip` bytes are assumed to be not encrypted (e.g. another header) and are only used as AAD for authentification
    /// May fail with
    /// - [`SframeError::MissingDecryptionKey`]
    /// - [`SframeError::DecryptionFailure`]
    /// - [`SframeError::FrameValidationFailed`]
    /// - [`SframeError::InvalidBuffer`]
    pub fn decrypt<F>(&mut self, encrypted_frame: F, skip: usize) -> Result<&[u8]>
    where
        F: AsRef<[u8]>,
    {
        let encrypted_frame = encrypted_frame.as_ref();
        let header = SframeHeader::deserialize(&encrypted_frame[skip..])?;

        log::trace!(
            "Receiver: Frame counter: {:?}, Key id: {:?}",
            header.frame_count(),
            header.key_id()
        );

        if let Some(validator) = &self.frame_validation {
            log::trace!("Receiver: Validating frame");
            validator.validate(&header)?;
        }

        let key_id = header.key_id();

        let sframe_key = match &mut self.keys {
            KeyStore::Standard(key_store) => key_store
                .get(&key_id)
                .ok_or(SframeError::MissingDecryptionKey(key_id)),
            KeyStore::Ratcheting(key_store) => key_store.ratcheting_get(key_id),
        }?;

        let payload_begin = skip + header.len();
        self.buffer.clear();
        self.buffer.extend(&encrypted_frame[..skip]);
        self.buffer.extend(&encrypted_frame[payload_begin..]);

        sframe_key.decrypt(
            &mut self.buffer[skip..],
            &encrypted_frame[..payload_begin],
            header.frame_count(),
        )?;

        let payload_end = self.buffer.len() - self.cipher_suite.auth_tag_len;
        Ok(&self.buffer[..payload_end])
    }

    /// Tries to expand (HKDF) the necessary encryptions key using the key id and the key material,
    /// which is then stored internally, to be used for decryption later on.
    /// May fail with
    /// - [`SframeError::KeyDerivation`]
    pub fn set_encryption_key<K, M>(&mut self, key_id: K, key_material: M) -> Result<()>
    where
        K: Into<KeyId>,
        M: AsRef<[u8]>,
    {
        let key_id = key_id.into();
        match &mut self.keys {
            KeyStore::Standard(key_store) => {
                key_store.insert(
                    key_id,
                    SframeKey::expand_from(&self.cipher_suite, key_material, key_id)?,
                );
            }
            KeyStore::Ratcheting(key_store) => {
                key_store.insert(self.cipher_suite.variant, key_id, key_material)?;
            }
        };

        Ok(())
    }

    /// removes an encryption key associated with the key id, which was stored internally,
    /// returns `true` if a key was present
    pub fn remove_encryption_key<K>(&mut self, key_id: K) -> bool
    where
        K: Into<KeyId>,
    {
        let key_id = key_id.into();
        match &mut self.keys {
            KeyStore::Standard(key_store) => key_store.remove(&key_id).is_some(),
            KeyStore::Ratcheting(key_store) => key_store.remove(key_id),
        }
    }
}

impl From<ReceiverOptions> for Receiver {
    fn from(options: ReceiverOptions) -> Self {
        let keys = match options.n_ratchet_bits {
            Some(n_ratchet_bits) => KeyStore::Ratcheting(RatchetingKeyStore::new(n_ratchet_bits)),
            None => KeyStore::default(),
        };
        Self {
            cipher_suite: options.cipher_suite_variant.into(),
            frame_validation: options.frame_validation,
            keys,
            buffer: Default::default(),
        }
    }
}

impl Default for Receiver {
    fn default() -> Self {
        let options = ReceiverOptions::default();
        options.into()
    }
}

enum KeyStore {
    Standard(HashMap<KeyId, SframeKey>),
    Ratcheting(RatchetingKeyStore),
}

impl Default for KeyStore {
    fn default() -> Self {
        KeyStore::Standard(Default::default())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn remove_key() {
        let mut receiver = Receiver::default();
        assert!(!receiver.remove_encryption_key(1234_u64));

        receiver
            .set_encryption_key(4223_u64, "hendrikswaytoshortpassword")
            .unwrap();
        receiver
            .set_encryption_key(4711_u64, "tobismuchbetterpassword;)")
            .unwrap();

        assert!(receiver.remove_encryption_key(4223_u64));
        assert!(!receiver.remove_encryption_key(4223_u64));

        assert!(receiver.remove_encryption_key(4711_u64));
        assert!(!receiver.remove_encryption_key(4711_u64));
    }

    #[test]
    fn fail_on_missing_key() {
        let mut receiver = Receiver::default();
        // do not set the encryption-key
        let decrypted = receiver.decrypt("foobar is unsafe", 0);

        assert_eq!(
            decrypted,
            Err(SframeError::MissingDecryptionKey(KeyId::from(6u8)))
        );
    }
}
