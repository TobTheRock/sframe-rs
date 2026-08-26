use sframe::{
    CipherSuite,
    error::Result,
    frame::{EncryptedFrameView, ReplayAttackProtectionStore},
    header::KeyId,
    ratchet::{RatchetingKeyId, RatchetingKeyStore},
};

use crate::N_RATCHET_BITS;

/// options for the decryption block,
/// allows to create a [Receiver] object using [Into]/[From]
pub struct ReceiverOptions {
    /// decryption/ key expansion algorithm used, see [RFC 9605 4.4](https://www.rfc-editor.org/rfc/rfc9605.html#name-cipher-suites)
    ///
    /// default: [`CipherSuite::AesGcm256Sha512`]
    pub cipher_suite: CipherSuite,
    /// replay protection, screening frames before and recording them after decryption
    ///
    /// default: [`ReplayAttackProtectionStore`] with tolerance `128`
    pub frame_validation: ReplayAttackProtectionStore,
    /// ratcheting as of [RFC 9605 5.1](https://www.rfc-editor.org/rfc/rfc9605.html#section-5.1),
    /// using `n_ratchet_bits` to depict the Ratchet Step
    ///
    /// default: [`N_RATCHET_BITS`]
    pub n_ratchet_bits: u8,
}

impl Default for ReceiverOptions {
    fn default() -> Self {
        Self {
            cipher_suite: CipherSuite::AesGcm256Sha512,
            frame_validation: ReplayAttackProtectionStore::new(128),
            n_ratchet_bits: N_RATCHET_BITS,
        }
    }
}

/// Models the sframe decryption block in the receiver path, see [RFC 9605 4.1](https://www.rfc-editor.org/rfc/rfc9605.html#name-application-context), by
/// - internally storing a map of encryption keys each associated with a key id ([`KeyId`])
/// - decrypting incoming `SFrame` frames using an internal buffer and the stored keys
/// - performing frame validation and ratcheting
pub struct Receiver {
    keys: RatchetingKeyStore,
    cipher_suite: CipherSuite,
    frame_validation: ReplayAttackProtectionStore,
    buffer: Vec<u8>,
}

impl Receiver {
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

        let data = &encrypted_frame[skip..];
        let meta_data = &encrypted_frame[..skip];
        let encrypted_frame = EncryptedFrameView::try_with_meta_data(data, meta_data)?;

        // The header is not authenticated yet, so this only screens it - the
        // replay window is untouched until the frame decrypted.

        let key_id = encrypted_frame.header().key_id();
        // TODO(v2): improve the API, so it is easier to determine which was the previous kid
        let previous_key_id = self.keys.get(key_id).map(|keys| keys.dec_key.key_id());

        let mut ratcheted_away_from = None;
        if self.keys.try_ratchet(key_id)? > 0 {
            ratcheted_away_from = previous_key_id;
        }

        // MediaFrameView can be used to access the payload, meta data and the associated counter of the frame
        let _media_frame = encrypted_frame.validated_decrypt_into(
            &self.keys,
            &mut self.buffer,
            &mut self.frame_validation,
        )?;

        // Remove stale KIDs to avoid memory growth (assuming in order packet delivery)
        if let Some(key_id) = ratcheted_away_from {
            self.frame_validation.remove(key_id);
        }

        Ok(&self.buffer)
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
        self.keys
            .insert(self.cipher_suite, key_id.into(), key_material)
    }

    /// creates a [Receiver] with the given cipher suite variant and the default parameters
    pub fn with_cipher_suite(cipher_suite: CipherSuite) -> Receiver {
        log::debug!("[receiver] Setting up sframe Receiver using CipherSuiteParams {cipher_suite}");

        let options = ReceiverOptions {
            cipher_suite,
            ..Default::default()
        };

        options.into()
    }

    /// removes an encryption key associated with the key id, which was stored internally,
    /// returns `true` if a key was present
    pub fn remove_encryption_key<K>(&mut self, key_id: K) -> bool
    where
        K: Into<KeyId>,
    {
        let key_id = key_id.into();

        // A whole key generation of KIDs is dropped here
        let n_ratchet_bits = self.keys.n_ratchet_bits();
        let removed = RatchetingKeyId::from_key_id(key_id, n_ratchet_bits);
        self.frame_validation
            .retain(|tracked| RatchetingKeyId::from_key_id(tracked, n_ratchet_bits) != removed);

        self.keys.remove(key_id)
    }
}

impl From<ReceiverOptions> for Receiver {
    fn from(options: ReceiverOptions) -> Self {
        Self {
            frame_validation: options.frame_validation,
            cipher_suite: options.cipher_suite,
            keys: RatchetingKeyStore::new(options.n_ratchet_bits),
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

#[cfg(test)]
mod test {
    use sframe::error::SframeError;

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

        assert!(matches!(
            decrypted,
            Err(SframeError::MissingDecryptionKey(key_id)) if key_id == KeyId::from(6u8)
        ));
    }
}
