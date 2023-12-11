// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use std::collections::HashMap;

use crate::{
    crypto::{
        aead::AeadDecrypt,
        cipher_suite::{CipherSuite, CipherSuiteVariant},
        key_derivation::KeyDerivation,
        secret::Secret,
    },
    error::{Result, SframeError},
    frame_validation::{FrameValidation, ReplayAttackProtection},
    header::{KeyId, SframeHeader},
};

pub struct ReceiverOptions {
    cipher_suite: CipherSuite,
    frame_validation: Box<dyn FrameValidation>,
}

impl Default for ReceiverOptions {
    fn default() -> Self {
        Self {
            cipher_suite: CipherSuiteVariant::AesGcm256Sha512.into(),
            frame_validation: Box::new(ReplayAttackProtection::with_tolerance(128)),
        }
    }
}

#[derive(Default)]
pub struct Receiver {
    secrets: HashMap<KeyId, Secret>,
    options: ReceiverOptions,
    buffer: Vec<u8>,
}

impl Receiver {
    pub fn with_cipher_suite(variant: CipherSuiteVariant) -> Receiver {
        let cipher_suite: CipherSuite = variant.into();
        let replay_attack_tolerance = 128;
        log::debug!("Setting up sframe Receiver");
        log::trace!(
            "using ciphersuite {:?}, replay_attack_tolerance: {}",
            cipher_suite.variant,
            replay_attack_tolerance
        );
        Self {
            secrets: HashMap::default(),
            options: ReceiverOptions {
                cipher_suite,
                frame_validation: Box::new(ReplayAttackProtection::with_tolerance(
                    replay_attack_tolerance,
                )),
            },
            buffer: Default::default(),
        }
    }

    pub fn decrypt<EncryptedFrame>(
        &mut self,
        encrypted_frame: EncryptedFrame,
        skip: usize,
    ) -> Result<&[u8]>
    where
        EncryptedFrame: AsRef<[u8]>,
    {
        let encrypted_frame = encrypted_frame.as_ref();
        let header = SframeHeader::deserialize(&encrypted_frame[skip..])?;

        self.options.frame_validation.validate(&header)?;
        let key_id = header.key_id();

        if let Some(secret) = self.secrets.get(&key_id) {
            log::trace!(
                "Receiver: Frame counter: {:?}, Key id: {:?}",
                header.frame_count(),
                header.key_id()
            );

            let payload_begin = skip + header.len();
            self.buffer.clear();
            self.buffer.extend(&encrypted_frame[..skip]);
            self.buffer.extend(&encrypted_frame[payload_begin..]);

            self.options.cipher_suite.decrypt(
                &mut self.buffer[skip..],
                secret,
                &encrypted_frame[skip..payload_begin],
                header.frame_count(),
            )?;

            let payload_end = self.buffer.len() - self.options.cipher_suite.auth_tag_len;
            Ok(&self.buffer[..payload_end])
        } else {
            Err(SframeError::MissingDecryptionKey(key_id))
        }
    }

    pub fn set_encryption_key<Id, KeyMaterial>(
        &mut self,
        key_id: Id,
        key_material: &KeyMaterial,
    ) -> Result<()>
    where
        Id: Into<KeyId>,
        KeyMaterial: AsRef<[u8]> + ?Sized,
    {
        let key_id = key_id.into();
        self.secrets.insert(
            key_id,
            Secret::expand_from(&self.options.cipher_suite, key_material, key_id)?,
        );
        Ok(())
    }

    pub fn remove_encryption_key<Id>(&mut self, key_id: Id) -> bool
    where
        Id: Into<KeyId>,
    {
        self.secrets.remove(&key_id.into()).is_some()
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
    fn fail_on_missing_secret() {
        let mut receiver = Receiver::default();
        // do not set the encryption-key
        let decrypted = receiver.decrypt("foobar is unsafe", 0);

        assert_eq!(
            decrypted,
            Err(SframeError::MissingDecryptionKey(KeyId::from(6u8)))
        );
    }
}
