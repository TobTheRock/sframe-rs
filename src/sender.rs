use crate::{
    crypto::{
        aead::AeadEncrypt,
        cipher_suite::{CipherSuite, CipherSuiteVariant},
        key_derivation::KeyDerivation,
        sframe_key::SframeKey,
    },
    error::{Result, SframeError},
    frame_count_generator::FrameCountGenerator,
    header::{FrameCount, KeyId, SframeHeader},
};

#[derive(Clone, Copy, Debug)]
pub struct SenderOptions {
    pub key_id: KeyId,
    pub cipher_suite_variant: CipherSuiteVariant,
    pub max_frame_count: FrameCount,
}

impl Default for SenderOptions {
    fn default() -> Self {
        Self {
            key_id: 0,
            cipher_suite_variant: CipherSuiteVariant::AesGcm256Sha512,
            max_frame_count: u64::MAX,
        }
    }
}

pub struct Sender {
    frame_count: FrameCountGenerator,
    key_id: KeyId,
    cipher_suite: CipherSuite,
    sframe_key: Option<SframeKey>,
    buffer: Vec<u8>,
}

impl Sender {
    pub fn new<K>(key_id: K) -> Sender
    where
        K: Into<KeyId>,
    {
        Self::with_cipher_suite(key_id, CipherSuiteVariant::AesGcm256Sha512)
    }

    pub fn with_cipher_suite<K>(key_id: K, variant: CipherSuiteVariant) -> Sender
    where
        K: Into<KeyId>,
    {
        let cipher_suite: CipherSuite = variant.into();
        let key_id = key_id.into();
        log::debug!("Setting up sframe Sender");
        log::trace!(
            "KeyID {:?} (ciphersuite {:?})",
            key_id,
            cipher_suite.variant
        );
        Sender {
            frame_count: Default::default(),
            key_id,
            cipher_suite,
            sframe_key: None,
            buffer: Default::default(),
        }
    }

    pub fn encrypt<Plaintext>(
        &mut self,
        unencrypted_payload: Plaintext,
        skip: usize,
    ) -> Result<&[u8]>
    where
        Plaintext: AsRef<[u8]>,
    {
        let unencrypted_payload = unencrypted_payload.as_ref();

        log::trace!("Encrypt frame # {:#?}!", self.frame_count);
        if let Some(ref sframe_key) = self.sframe_key {
            log::trace!("Skipping first {} bytes in frame", skip);

            let frame_count = self.frame_count.increment();
            log::trace!("frame count: {:?}", frame_count);

            log::trace!("Creating SFrame Header");
            let header = SframeHeader::new(self.key_id, frame_count);

            log::trace!("Sender: header: {:?}", header);

            let skipped_payload = &unencrypted_payload[0..skip];
            let to_be_encrypted_payload = &unencrypted_payload[skip..];

            self.buffer.clear();
            let frame = &mut self.buffer;
            frame.extend_from_slice(skipped_payload);
            frame.extend(Vec::from(&header));
            frame.extend(to_be_encrypted_payload);

            let (leading_buffer, encrypt_buffer) = frame.split_at_mut(skip + header.len());

            log::trace!("Encrypting Frame of size {}", unencrypted_payload.len(),);
            let tag = sframe_key.encrypt(
                encrypt_buffer,
                &leading_buffer[skip..],
                header.frame_count(),
            )?;

            frame.extend(tag.as_ref());

            Ok(frame)
        } else {
            Err(SframeError::MissingEncryptionKey)
        }
    }

    pub fn set_encryption_key<KeyMaterial>(&mut self, key_material: KeyMaterial) -> Result<()>
    where
        KeyMaterial: AsRef<[u8]>,
    {
        self.sframe_key = Some(SframeKey::expand_from(
            &self.cipher_suite,
            key_material,
            self.key_id,
        )?);
        Ok(())
    }

    pub fn ratchet_encryption_key<K, M>(&mut self, key_id: K, key_material: M) -> Result<()>
    where
        K: Into<KeyId>,
        M: AsRef<[u8]>,
    {
        self.key_id = key_id.into();
        self.set_encryption_key(key_material)
    }
}

impl From<SenderOptions> for Sender {
    fn from(options: SenderOptions) -> Self {
        log::debug!(
            "Creating sframe Sender with keyID {}, ciphersuite {:?}",
            options.key_id,
            options.cipher_suite_variant
        );
        Self {
            key_id: options.key_id,
            cipher_suite: options.cipher_suite_variant.into(),
            sframe_key: None,
            frame_count: FrameCountGenerator::new(options.max_frame_count),
            buffer: Default::default(),
        }
    }
}

impl Default for Sender {
    fn default() -> Self {
        let options = SenderOptions::default();
        options.into()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn fail_on_missing_key() {
        let mut sender = Sender::new(1_u8);
        // do not set the encryption-key
        let encrypted = sender.encrypt("foobar is unsafe", 0);

        assert_eq!(encrypted, Err(SframeError::MissingEncryptionKey));
    }
}
