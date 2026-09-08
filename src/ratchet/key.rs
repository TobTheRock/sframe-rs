use crate::{
    CipherSuite,
    crypto::{AeadDecrypt, AeadEncrypt, KeyDerivation, Ratcheting},
    error::{Result, SframeError},
    header::KeyId,
    key::{
        KeyStore,
        generic::{GenericDecryptionKey, GenericEncryptionKey},
    },
    ratchet::{
        RatchetingKeyId, key_id::RatchetStepDiff, key_material::GenericRatchetingKeyMaterial,
    },
};

/// An [`GenericEncryptionKey`] which can be ratcheted forward as of
/// [RFC 9605 Section 5.1](https://www.rfc-editor.org/rfc/rfc9605.html#section-5.1),
pub struct GenericRatchetingEncryptionKey<A, D>
where
    A: AeadEncrypt,
    D: KeyDerivation + Ratcheting,
{
    key_id: RatchetingKeyId,
    material: GenericRatchetingKeyMaterial<D>,
    enc_key: GenericEncryptionKey<A, D>,
    ratcheted_from: Option<RatchetingKeyId>,
}

impl<A, D> GenericRatchetingEncryptionKey<A, D>
where
    A: AeadEncrypt<Secret = D::Secret>,
    D: KeyDerivation + Ratcheting,
{
    /// Tries to derive a ratcheting encryption key from the given key material, associating it
    /// with the given key id. The cipher suite is used for the derivation and when ratcheting
    /// forward.
    pub fn derive_from<K, M>(cipher_suite: CipherSuite, key_id: K, key_material: M) -> Result<Self>
    where
        K: Into<RatchetingKeyId>,
        M: AsRef<[u8]>,
    {
        let key_id = key_id.into();
        let enc_key =
            GenericEncryptionKey::<A, D>::derive_from(cipher_suite, key_id, &key_material)?;
        let material = GenericRatchetingKeyMaterial::derive_from(cipher_suite, key_material)?;

        Ok(Self {
            key_id,
            material,
            enc_key,
            ratcheted_from: None,
        })
    }

    /// the key material of the current Ratchet Step, which the next one is ratcheted from
    pub fn key_material(&self) -> &GenericRatchetingKeyMaterial<D> {
        &self.material
    }

    /// ratchets the key material forward, deriving the encryption key of the next Ratchet Step.
    /// The key is left untouched if that fails.
    pub fn ratchet(&self) -> Result<Self> {
        let key_id = self.key_id.inc_ratchet_step();
        let enc_key =
            GenericEncryptionKey::derive_from(self.enc_key.cipher_suite(), key_id, &self.material)?;
        let material = self.material.ratchet()?;

        Ok(Self {
            key_id,
            material,
            enc_key,
            ratcheted_from: Some(self.key_id),
        })
    }

    /// returns the [`RatchetingKeyId`] of the current Ratchet Step
    pub fn key_id(&self) -> RatchetingKeyId {
        self.key_id
    }

    /// The [`RatchetingKeyId`] of the Ratchet Step this key was ratcheted away from,
    /// [`None`] if it was derived rather than ratcheted.
    pub fn ratcheted_from(&self) -> Option<RatchetingKeyId> {
        self.ratcheted_from
    }
}

impl<A, D> AsRef<GenericEncryptionKey<A, D>> for GenericRatchetingEncryptionKey<A, D>
where
    A: AeadEncrypt<Secret = D::Secret>,
    D: KeyDerivation + Ratcheting,
{
    fn as_ref(&self) -> &GenericEncryptionKey<A, D> {
        &self.enc_key
    }
}

/// A [`GenericDecryptionKey`] which can be ratcheted forward as of
/// [RFC 9605 Section 5.1](https://www.rfc-editor.org/rfc/rfc9605.html#section-5.1), to catch up
/// with the Ratchet Step a sender encrypted a frame with.
pub struct GenericRatchetingDecryptionKey<A, D>
where
    A: AeadDecrypt<Secret = D::Secret>,
    D: KeyDerivation + Ratcheting,
{
    /// provides key material used for ratcheting
    material: GenericRatchetingKeyMaterial<D>,
    /// secrets used for decryption
    dec_key: GenericDecryptionKey<A, D>,
    key_id: RatchetingKeyId,
    ratcheted_from: Option<RatchetingKeyId>,
}

impl<A, D> GenericRatchetingDecryptionKey<A, D>
where
    A: AeadDecrypt<Secret = D::Secret>,
    D: KeyDerivation + Ratcheting,
{
    /// Tries to derive a ratcheting decryption key from the given key material, associating it
    /// with the given key id. The cipher suite is used for the derivation and when ratcheting
    /// forward.
    pub fn derive_from<K, M>(cipher_suite: CipherSuite, key_id: K, key_material: M) -> Result<Self>
    where
        K: Into<RatchetingKeyId>,
        M: AsRef<[u8]>,
    {
        let key_id = key_id.into();
        let dec_key = GenericDecryptionKey::derive_from(cipher_suite, key_id, &key_material)?;
        let material = GenericRatchetingKeyMaterial::derive_from(cipher_suite, key_material)?;
        Ok(Self {
            dec_key,
            key_id,
            material,
            ratcheted_from: None,
        })
    }

    /// the key material of the current Ratchet Step, which the next one is ratcheted from
    pub fn key_material(&self) -> &GenericRatchetingKeyMaterial<D> {
        &self.material
    }

    /// returns the [`RatchetingKeyId`] of the current Ratchet Step
    pub fn key_id(&self) -> RatchetingKeyId {
        self.key_id
    }

    /// ratchets the key material forward by a single Ratchet Step, deriving the decryption key
    /// of the step which is reached. The key is left untouched if that fails.
    pub fn ratchet(&self) -> Result<Self>
    where
        A: Clone,
        D::Secret: Clone,
    {
        self.ratchet_by(RatchetStepDiff::ONE)
    }

    /// Ratchets the key material forward until the Ratchet Step of `key_id` is reached, deriving
    /// the decryption key of that step. The key is left untouched if a step fails.
    ///
    /// Fails with [`SframeError::RatchetingFailure`] if `key_id` is not of the same Key
    /// Generation, does not use the same No. ratchet bits, or is more than `max_steps` ahead -
    /// which is also the case for a Ratchet Step which was already passed.
    pub fn ratchet_to(&self, key_id: RatchetingKeyId, max_steps: RatchetStepDiff) -> Result<Self>
    where
        A: Clone,
        D::Secret: Clone,
    {
        let steps = self.key_id.steps_to(key_id)?;
        if steps > max_steps {
            return Err(SframeError::RatchetingFailure);
        }

        self.ratchet_by(steps)
    }

    fn ratchet_by(&self, steps: RatchetStepDiff) -> Result<Self>
    where
        A: Clone,
        D::Secret: Clone,
    {
        // no step to take means the key is handed back as it is
        let mut key_id = self.key_id;
        let mut dec_key = self.dec_key.clone();
        let mut material = self.material.clone();

        for _ in 0..u64::from(steps) {
            key_id = key_id.inc_ratchet_step();
            dec_key =
                GenericDecryptionKey::derive_from(self.dec_key.cipher_suite(), key_id, &material)?;
            material = material.ratchet()?;
        }

        Ok(Self {
            dec_key,
            material,
            ratcheted_from: (key_id != self.key_id).then_some(self.key_id),
            key_id,
        })
    }

    /// The [`RatchetingKeyId`] of the Ratchet Step this key was ratcheted away from,
    /// [`None`] if it was derived rather than ratcheted. Its key is gone, so anything kept per
    /// key id - a replay window e.g. - can be dropped with it.
    pub fn ratcheted_from(&self) -> Option<RatchetingKeyId> {
        self.ratcheted_from
    }
}

impl<A, D> AsRef<GenericDecryptionKey<A, D>> for GenericRatchetingDecryptionKey<A, D>
where
    A: AeadDecrypt<Secret = D::Secret>,
    D: KeyDerivation + Ratcheting,
{
    fn as_ref(&self) -> &GenericDecryptionKey<A, D> {
        &self.dec_key
    }
}

/// A ratcheting key holds the key of its current Ratchet Step, so it can be handed to
/// decryption directly - as long as the frame carries the key id of that step.
impl<A, D> KeyStore<A, D> for GenericRatchetingDecryptionKey<A, D>
where
    A: AeadDecrypt<Secret = D::Secret>,
    D: KeyDerivation + Ratcheting,
{
    fn get_key<K>(&self, key_id: K) -> Option<&GenericDecryptionKey<A, D>>
    where
        K: Into<KeyId>,
    {
        self.dec_key.get_key(key_id)
    }
}

#[cfg(all(test, crypto_backend))]
mod test {
    use crate::{
        CipherSuite,
        crypto::{Aead, Kdf},
        ratchet::{RatchetBits, RatchetStep, RatchetStepDiff, RatchetingKeyId},
    };
    use pretty_assertions::assert_eq;

    // Exercise the generic key with the default crypto backend.
    type RatchetingEncryptionKey = super::GenericRatchetingEncryptionKey<Aead, Kdf>;
    type RatchetingDecryptionKey = super::GenericRatchetingDecryptionKey<Aead, Kdf>;

    const SECRET: &[u8] = b"SuperSecret";
    const CIPHER_SUITE: CipherSuite = CipherSuite::AesGcm128Sha256;

    fn max_steps() -> RatchetStepDiff {
        RatchetStepDiff::from(2)
    }

    fn key_id() -> RatchetingKeyId {
        RatchetingKeyId::new(42u8, RatchetBits::new(4))
    }

    fn encryption_key() -> RatchetingEncryptionKey {
        RatchetingEncryptionKey::derive_from(CIPHER_SUITE, key_id(), SECRET).unwrap()
    }

    fn decryption_key() -> RatchetingDecryptionKey {
        RatchetingDecryptionKey::derive_from(CIPHER_SUITE, key_id(), SECRET).unwrap()
    }

    /// the key id of the Key Generation, `n_steps` Ratchet Steps in
    fn advanced_key_id(n_steps: u64) -> RatchetingKeyId {
        (0..n_steps).fold(key_id(), |key_id, _| key_id.inc_ratchet_step())
    }

    #[test]
    fn derive_encryption_key() {
        let key = encryption_key();

        assert_eq!(key.key_id().ratchet_step(), RatchetStep::from(0));
        assert_eq!(None, key.ratcheted_from());
    }

    #[test]
    fn ratchets_encryption_key() {
        let original_key = encryption_key();

        let ratcheted_key = original_key.ratchet().unwrap();

        assert_eq!(ratcheted_key.key_id().ratchet_step(), RatchetStep::from(1));
        assert_eq!(Some(key_id()), ratcheted_key.ratcheted_from());
        assert_ne!(original_key.as_ref(), ratcheted_key.as_ref());
        assert_ne!(
            original_key.key_material().as_ref(),
            ratcheted_key.key_material().as_ref()
        );
    }

    #[test]
    fn derive_decryption_key() {
        let key = decryption_key();

        assert_eq!(RatchetStep::from(0), key.key_id().ratchet_step());
        assert_eq!(None, key.ratcheted_from());
    }

    #[test]
    fn doesnt_ratchet_decryption_key() {
        let original_key = decryption_key();

        let key = original_key.ratchet_to(key_id(), max_steps()).unwrap();

        assert_eq!(RatchetStep::from(0), key.key_id().ratchet_step());
        assert_eq!(original_key.as_ref(), key.as_ref());
        assert_eq!(
            original_key.key_material().as_ref(),
            key.key_material().as_ref()
        );
        assert_eq!(None, key.ratcheted_from());
    }

    #[test]
    fn ratchets_decryption_key_once() {
        let original_key = decryption_key();

        let key = original_key.ratchet().unwrap();

        assert_eq!(RatchetStep::from(1), key.key_id().ratchet_step());
        assert_ne!(original_key.as_ref(), key.as_ref());
        assert_ne!(
            original_key.key_material().as_ref(),
            key.key_material().as_ref()
        );
        assert_eq!(Some(key_id()), key.ratcheted_from());
    }

    #[test]
    fn ratchets_decryption_key_up_to_a_key_id() {
        let original_key = decryption_key();

        let key = original_key
            .ratchet_to(advanced_key_id(2), max_steps())
            .unwrap();
        let step_by_step = original_key.ratchet().unwrap().ratchet().unwrap();

        assert_eq!(RatchetStep::from(2), key.key_id().ratchet_step());
        // ratcheting two steps at once has to reach the same key as two single steps
        assert_eq!(step_by_step.as_ref(), key.as_ref());
        assert_eq!(
            step_by_step.key_material().as_ref(),
            key.key_material().as_ref()
        );
        assert_eq!(Some(key_id()), key.ratcheted_from());
    }

    #[test]
    fn rejects_a_key_id_further_ahead_than_the_maximum() {
        let key = decryption_key();

        let too_far = key.ratchet_to(advanced_key_id(3), max_steps());

        assert!(too_far.is_err());
    }
}
