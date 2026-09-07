use sframe::frame::MonotonicCounter;
use sframe::{
    CipherSuite,
    error::{Result, SframeError},
    frame::MediaFrameView,
    header::Counter,
    ratchet::{Generation, RatchetBits, RatchetingEncryptionKey, RatchetingKeyId},
};

use crate::N_RATCHET_BITS;

/// options for the encryption block,
/// allows to create a [Sender] object using [Into]/[From]
#[derive(Clone, Copy, Debug)]
pub struct SenderOptions {
    /// Key Generation the sender starts with, at Ratchet Step 0
    ///
    /// default: `0`
    pub generation: Generation,
    /// No. bits used to depict the Ratchet Step in the key id
    ///
    /// default: [`N_RATCHET_BITS`]
    pub n_ratchet_bits: RatchetBits,
    /// encryption/ key expansion algorithm used, see [RFC 9605 4.4](https://www.rfc-editor.org/rfc/rfc9605.html#name-cipher-suites)
    ///
    /// default: [`CipherSuite::AesGcm256Sha512`]
    pub cipher_suite: CipherSuite,
    /// maximum frame count, to limit the header ([`crate::header::SframeHeader`]) size
    ///
    /// default: [`u64::MAX`]
    pub max_counter: Counter,
}

impl Default for SenderOptions {
    fn default() -> Self {
        Self {
            generation: Generation::from(0),
            n_ratchet_bits: RatchetBits::new(N_RATCHET_BITS),
            cipher_suite: CipherSuite::AesGcm256Sha512,
            max_counter: u64::MAX,
        }
    }
}

/// models the sframe encryption block in the sender path, [RFC 9605 4.1](https://www.rfc-editor.org/rfc/rfc9605.html#name-application-context).
/// The [Sender] allows to encrypt outgoing media frames. To do so, it is associated with a
/// single Key Generation ([`Generation`]), ratcheting forward through its Ratchet Steps.
/// It needs to be initialised with a base key (aka key material) first.
/// For encryption/ key expansion the used algorithms are configurable (see [`CipherSuite`]).
pub struct Sender {
    counter: MonotonicCounter,
    key_id: RatchetingKeyId,
    cipher_suite: CipherSuite,
    enc_key: Option<RatchetingEncryptionKey>,
    buffer: Vec<u8>,
}

impl Sender {
    /// creates a new sender associated with the given Key Generation
    pub fn new(generation: Generation) -> Sender {
        Self::with_cipher_suite(generation, CipherSuite::AesGcm256Sha512)
    }

    /// creates a new sender associated with the given Key Generation and the given cipher suite variant
    pub fn with_cipher_suite(generation: Generation, cipher_suite: CipherSuite) -> Sender {
        log::debug!("[sender] Setting up sframe Sender");
        log::trace!("[sender] Key Generation {generation} (CipherSuiteParams {cipher_suite})");

        SenderOptions {
            generation,
            cipher_suite,
            ..Default::default()
        }
        .into()
    }
    /// Encrypts a frame into the internal buffer, returning a slice to the encrypted data.
    /// The first `skip` bytes are left unencrypted (e.g. for another header), a
    /// [`MediaFrameView`] takes them as meta data, which is authenticated but not encrypted.
    pub fn encrypt<F>(&mut self, unencrypted_frame: F, skip: usize) -> Result<&[u8]>
    where
        F: AsRef<[u8]>,
    {
        if let Some(enc_key) = &self.enc_key {
            let enc_key = enc_key.as_ref();
            let unencrypted_frame = unencrypted_frame.as_ref();

            let payload = &unencrypted_frame[skip..];
            let meta_data = &unencrypted_frame[..skip];
            let media_frame =
                MediaFrameView::try_with_meta_data(&mut self.counter, payload, meta_data)?;

            media_frame.encrypt_into(enc_key, &mut self.buffer)?;

            Ok(&self.buffer)
        } else {
            Err(SframeError::EncryptionFailure)
        }
    }

    /// Expands (HKDF) the key material into the encryption key of this sender, which is kept
    /// for the frames to come. It starts at Ratchet Step 0 of the senders Key Generation.
    pub fn set_encryption_key<M>(&mut self, key_material: M) -> Result<()>
    where
        M: AsRef<[u8]>,
    {
        self.enc_key = Some(RatchetingEncryptionKey::derive_from(
            self.cipher_suite,
            self.key_id,
            key_material,
        )?);
        Ok(())
    }

    /// returns the key id the next frame is encrypted with
    pub fn key_id(&self) -> RatchetingKeyId {
        self.enc_key
            .as_ref()
            .map_or(self.key_id, RatchetingEncryptionKey::key_id)
    }

    /// Ratchets the encryption key forward, so the next frame is encrypted with the key of the
    /// next Ratchet Step - and the receivers of the previous ones cannot read it anymore.
    /// The key carries its own key material, so no base key has to be kept next to it.
    pub fn ratchet_encryption_key(&mut self) -> Result<()> {
        self.enc_key = Some(
            self.enc_key
                .as_ref()
                .ok_or(SframeError::EncryptionFailure)?
                .ratchet()?,
        );
        Ok(())
    }
}

impl From<SenderOptions> for Sender {
    fn from(options: SenderOptions) -> Self {
        log::debug!(
            "[sender] Creating sframe Sender with Key Generation {}, CipherSuiteParams {:?}",
            options.generation,
            options.cipher_suite
        );
        Self {
            // a Key Generation starts at Ratchet Step 0
            key_id: RatchetingKeyId::new(options.generation, options.n_ratchet_bits),
            cipher_suite: options.cipher_suite,
            enc_key: None,
            counter: MonotonicCounter::new(options.max_counter),
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
        let mut sender = Sender::new(Generation::from(1));
        // do not set the encryption-key
        let encrypted = sender.encrypt("foobar is unsafe", 0);

        assert!(matches!(encrypted, Err(SframeError::EncryptionFailure)));
    }
}
