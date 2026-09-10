use sframe::{
    CipherSuite,
    error::{Result, SframeError},
    frame::{
        EncryptedFrameView,
        validation::{ReplayAttackProtectionError, ReplayAttackProtectionStore, Tolerance},
    },
    header::KeyId,
    ratchet::{
        Generation, RatchetBits, RatchetStepDiff, RatchetingDecryptionKey, RatchetingKeyId,
        RatchetingKeyStore,
    },
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
    /// default: [`ReplayAttackProtectionStore`] with a [`Tolerance`] of `128`
    pub frame_validation: ReplayAttackProtectionStore,
    /// ratcheting as of [RFC 9605 5.1](https://www.rfc-editor.org/rfc/rfc9605.html#section-5.1),
    /// using `n_ratchet_bits` to depict the Ratchet Step
    ///
    /// default: [`N_RATCHET_BITS`]
    pub n_ratchet_bits: RatchetBits,
    /// the No. Ratchet Steps a single frame may catch up with, matching the loss and re-ordering
    /// to be expected - each step costs a key derivation an attacker can trigger
    ///
    /// default: `2`, the sender of this example ratchets once per frame
    pub max_ratchet_steps: RatchetStepDiff,
}

impl Default for ReceiverOptions {
    fn default() -> Self {
        Self {
            cipher_suite: CipherSuite::AesGcm256Sha512,
            frame_validation: ReplayAttackProtectionStore::new(Tolerance::new(128)),
            n_ratchet_bits: RatchetBits::new(N_RATCHET_BITS),
            max_ratchet_steps: RatchetStepDiff::from(2),
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
    /// the No. bits used to depict the Ratchet Step is agreed on for the session, the store
    /// takes it from the key ids it is given
    n_ratchet_bits: RatchetBits,
}

impl Receiver {
    /// Tries to decrypt an incoming encrypted frame, returning a slice to the decrypted data on success.
    /// The first `skip` bytes are assumed to be not encrypted (e.g. another header) and are only used as AAD for authentification
    ///
    /// Returns [`None`] if the frame was dropped as a replay.
    /// May fail with
    /// - [`SframeError::MissingDecryptionKey`]
    /// - [`SframeError::DecryptionFailure`]
    /// - [`SframeError::FrameValidationFailed`]
    /// - [`SframeError::InvalidBuffer`]
    pub fn decrypt<F>(&mut self, encrypted_frame: F, skip: usize) -> Result<Option<&[u8]>>
    where
        F: AsRef<[u8]>,
    {
        let encrypted_frame = encrypted_frame.as_ref();

        let data = &encrypted_frame[skip..];
        let meta_data = &encrypted_frame[..skip];
        let encrypted_frame = EncryptedFrameView::try_with_meta_data(data, meta_data)?;

        let key_id =
            RatchetingKeyId::from_key_id(encrypted_frame.header().key_id(), self.n_ratchet_bits);

        // The store is a key store like any other, it is only passed mutably: it ratchets the
        // key forward to the Ratchet Step of the key id, and keeps it only if the frame
        // decrypted - a forged header must not evict a valid key. The frame is screened before
        // decryption and recorded once it authenticated.
        let media_frame = match encrypted_frame.validated_decrypt_into(
            &mut self.keys,
            &mut self.buffer,
            &mut self.frame_validation,
        ) {
            Ok(media_frame) => media_frame,
            Err(error) => return drop_if_replayed(error),
        };

        // The Ratchet Step the key was ratcheted away from leaves a replay window behind,
        // dropping it avoids memory growth. Safe to do here, as this example ratchets on every
        // frame and the store only ratchets forward: a frame the channel delayed past a Ratchet
        // Step has no key anymore anyway. An application which ratchets rarely - only when a
        // receiver joins e.g. - should keep the window while frames of that step may still
        // arrive.
        let stale_key_id = self
            .keys
            .get(key_id.generation())
            .and_then(|key| key.ratcheted_from());
        if let Some(stale_key_id) = stale_key_id {
            self.frame_validation.remove(KeyId::from(stale_key_id));
        }

        log::debug!(
            "[receiver] Decrypted frame # {} of key id {}",
            media_frame.counter(),
            KeyId::from(key_id)
        );

        Ok(Some(media_frame.payload()))
    }

    /// Tries to expand (HKDF) the necessary encryptions key for a Key Generation using the given
    /// key material, which is then stored internally, to be used for decryption later on.
    /// May fail with
    /// - [`SframeError::KeyDerivation`]
    pub fn set_encryption_key<M>(&mut self, generation: Generation, key_material: M) -> Result<()>
    where
        M: AsRef<[u8]>,
    {
        // a Key Generation starts at Ratchet Step 0
        let key_id = RatchetingKeyId::try_new(generation, self.n_ratchet_bits)?;
        let key = RatchetingDecryptionKey::derive_from(self.cipher_suite, key_id, key_material)?;
        self.keys.insert(key);

        Ok(())
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

    /// removes the encryption key of a Key Generation, which was stored internally,
    /// returns `true` if a key was present
    pub fn remove_encryption_key(&mut self, generation: Generation) -> bool {
        // A whole key generation of KIDs is dropped here
        let n_ratchet_bits = self.n_ratchet_bits;
        self.frame_validation.retain(|tracked| {
            RatchetingKeyId::from_key_id(tracked, n_ratchet_bits).generation() != generation
        });

        self.keys.remove(generation)
    }
}

/// Drops a frame which the validator rejected as a replay, on a lossy transport a duplicated
/// or an outdated frame is normal traffic and no reason to fail the session.
///
/// The validator reports through an error type of its own choice, which [`SframeError`] boxes -
/// name it again to get the rejection back.
fn drop_if_replayed(error: SframeError) -> Result<Option<&'static [u8]>> {
    match error.source_as::<ReplayAttackProtectionError>().copied() {
        Some(ReplayAttackProtectionError::DuplicatedFrame { key_id, counter }) => {
            log::debug!("[receiver] Dropping duplicated frame {counter} of key id {key_id}");
            Ok(None)
        }
        Some(ReplayAttackProtectionError::CounterTooOld { key_id, counter }) => {
            log::debug!("[receiver] Dropping outdated frame {counter} of key id {key_id}");
            Ok(None)
        }
        // The store screens per key id, so its validators never see a foreign one
        Some(ReplayAttackProtectionError::KeyIdMismatch { .. }) => Err(error),
        // Not a rejection: no key, no valid buffer, or the frame did not authenticate
        None => Err(error),
    }
}

impl From<ReceiverOptions> for Receiver {
    fn from(options: ReceiverOptions) -> Self {
        Self {
            frame_validation: options.frame_validation,
            cipher_suite: options.cipher_suite,
            keys: RatchetingKeyStore::new(options.n_ratchet_bits, options.max_ratchet_steps),
            buffer: Default::default(),
            n_ratchet_bits: options.n_ratchet_bits,
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
        assert!(!receiver.remove_encryption_key(Generation::from(1234)));

        receiver
            .set_encryption_key(Generation::from(4223), "hendrikswaytoshortpassword")
            .unwrap();
        receiver
            .set_encryption_key(Generation::from(4711), "tobismuchbetterpassword;)")
            .unwrap();

        assert!(receiver.remove_encryption_key(Generation::from(4223)));
        assert!(!receiver.remove_encryption_key(Generation::from(4223)));

        assert!(receiver.remove_encryption_key(Generation::from(4711)));
        assert!(!receiver.remove_encryption_key(Generation::from(4711)));
    }

    #[test]
    fn fail_on_missing_key() {
        let mut receiver = Receiver::default();
        // do not set the encryption-key
        let decrypted = receiver.decrypt("foobar is unsafe", 0);

        assert!(matches!(
            decrypted,
            Err(SframeError::MissingDecryptionKey { key_id, .. }) if key_id == KeyId::from(6u8)
        ));
    }
}
