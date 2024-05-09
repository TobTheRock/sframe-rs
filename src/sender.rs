use crate::{
    crypto::cipher_suite::{CipherSuite, CipherSuiteVariant},
    error::{Result, SframeError},
    frame::MediaFrameView,
    frame_count_generator::FrameCountGenerator,
    header::{FrameCount, KeyId},
    key::EncryptionKey,
};

/// options for the encryption block,
/// allows to create a [Sender] object using [Into]/[From]
#[derive(Clone, Copy, Debug)]
pub struct SenderOptions {
    /// key id associated with the sender
    ///
    /// default: `0`
    pub key_id: KeyId,
    /// encryption/ key expansion algorithm used, see [sframe draft 09 4.4](https://www.ietf.org/archive/id/draft-ietf-sframe-enc-09.html#name-cipher-suites)
    ///
    /// default: [`CipherSuiteVariant::AesGcm256Sha512`]
    pub cipher_suite_variant: CipherSuiteVariant,
    /// maximum frame count, to limit the header ([`crate::header::SframeHeader`]) size
    ///
    /// default: [`u64::MAX`]
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

/// models the sframe encryption block in the sender path, [sframe draft 09 4.1](https://www.ietf.org/archive/id/draft-ietf-sframe-enc-09.html#name-application-context).
/// The [Sender] allows to encrypt outgoing media frames. To do so, it is associated with a
/// single key id ([`KeyId`]). It needs to be initialised with a base key (aka key material) first.
/// For encryption/ key expansion the used algorithms are configurable (see [`CipherSuiteVariant`]).
pub struct Sender {
    frame_count: FrameCountGenerator,
    key_id: KeyId,
    cipher_suite: CipherSuite,
    enc_key: Option<EncryptionKey>,
    buffer: Vec<u8>,
}

impl Sender {
    /// creates a new sender associated with the given key id
    pub fn new<K>(key_id: K) -> Sender
    where
        K: Into<KeyId>,
    {
        Self::with_cipher_suite(key_id, CipherSuiteVariant::AesGcm256Sha512)
    }

    /// creates a new sender associated with the given key id and the given cipher suite variant
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
            enc_key: None,
            buffer: Default::default(),
        }
    }
    /// Tries to encrypt an incoming encrypted frame, returning a slice to the encrypted data on success.
    /// The first `skip` bytes are not going to be encrypted (e.g. for another header), but are used as AAD for authentification
    /// May fail with
    /// - [`SframeError::MissingEncryptionKey`]
    /// - [`SframeError::EncryptionFailure`]
    pub fn encrypt<F>(&mut self, unencrypted_frame: F, skip: usize) -> Result<&[u8]>
    where
        F: AsRef<[u8]>,
    {
        if let Some(enc_key) = &self.enc_key {
            let unencrypted_frame = unencrypted_frame.as_ref();

            let frame_count = self.frame_count.increment();
            let payload = &unencrypted_frame[skip..];
            let meta_data = &unencrypted_frame[..skip];
            let media_frame = MediaFrameView::with_meta_data(frame_count, payload, meta_data);

            media_frame.encrypt_into(enc_key, &mut self.buffer)?;

            Ok(&self.buffer)
        } else {
            Err(SframeError::MissingEncryptionKey)
        }
    }

    /// Tries to create an encryption key for this sender, by expanding the given key material
    /// , which is stored internally for encryption.
    /// May fail with:
    /// - [`SframeError::KeyDerivation`]
    pub fn set_encryption_key<M>(&mut self, key_material: M) -> Result<()>
    where
        M: AsRef<[u8]>,
    {
        self.enc_key = Some(EncryptionKey::derive_from(
            self.cipher_suite.variant,
            self.key_id,
            key_material,
        )?);
        Ok(())
    }

    /// To rachtet sets a new key id and tries to create a new encryption key for this sender, by expanding the given key material.
    /// May fail with:
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
            enc_key: None,
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
    use pretty_assertions::assert_eq;

    #[test]
    fn fail_on_missing_key() {
        let mut sender = Sender::new(1_u8);
        // do not set the encryption-key
        let encrypted = sender.encrypt("foobar is unsafe", 0);

        assert_eq!(encrypted, Err(SframeError::MissingEncryptionKey));
    }
}
