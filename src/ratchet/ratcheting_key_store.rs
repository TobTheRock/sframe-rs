use std::collections::HashMap;

use crate::{
    CipherSuite,
    crypto::{
        aead::AeadDecrypt,
        key_derivation::{KeyDerivation, Ratcheting},
    },
    error::{Result, SframeError},
    header::KeyId,
    key::{KeyStore, crypto_key::DecryptionKey},
    util::limit_bit_len,
};

use super::{ratcheting_base_key::RatchetingBaseKey, ratcheting_key_id::RatchetingKeyId};

/// Utility class to store multiple encryption keys and base keys ([`RatchetingBaseKey`]) each associated with a [`KeyId`].
/// Allows to automatically ratchet forward an encryption key if necessary.
///
/// Generic over the crypto backend used for decryption (`A`) and key derivation (`D`).
///
/// As the Ratchet Step is taken from an unauthenticated header, catching up with it lets an
/// attacker trigger key derivations with a single forged frame. By default this is only bounded by
/// the Ratchet Step itself (`2^n_ratchet_bits - 1` steps); pick a bound matching the expected loss
/// and re-ordering with [`RatchetingKeyStore::with_max_ratchet_steps`].
pub struct RatchetingKeyStore<A, D>
where
    A: AeadDecrypt<Secret = D::Secret>,
    D: KeyDerivation + Ratcheting,
{
    keys: HashMap<RatchetingKeyId, RatchetingKeys<A, D>>,
    n_ratchet_bits: u8,
    max_ratchet_steps: u64,
}

impl<A, D> RatchetingKeyStore<A, D>
where
    A: AeadDecrypt<Secret = D::Secret>,
    D: KeyDerivation + Ratcheting,
{
    /// creates a new [`RatchetingKeyStore`] which uses `n_ratchet_bits` to determine the Ratchet
    /// Step, limited to 63 bits as in [`RatchetingKeyId`]
    pub fn new(n_ratchet_bits: u8) -> Self {
        let n_ratchet_bits = limit_bit_len("n_ratchet_bits", n_ratchet_bits, u64::BITS as u8 - 1);

        Self {
            n_ratchet_bits,
            keys: Default::default(),
            max_ratchet_steps: (1u64 << n_ratchet_bits) - 1,
        }
    }

    /// limits how many ratchet steps [`RatchetingKeyStore::try_ratchet`] catches up with at once
    // TODO(v2): make this an mandatory parameter?
    pub fn with_max_ratchet_steps(mut self, max_ratchet_steps: u64) -> Self {
        self.max_ratchet_steps = max_ratchet_steps;
        self
    }

    /// returns the No. bits used to determine the Ratchet Step
    pub fn n_ratchet_bits(&self) -> u8 {
        self.n_ratchet_bits
    }

    /// inserts a new key associated with a key id
    /// expands the key and ratchets the original key material to not store for security reasons
    pub fn insert<K, M>(
        &mut self,
        cipher_suite: CipherSuite,
        key_id: K,
        key_material: M,
    ) -> Result<()>
    where
        K: Into<KeyId>,
        M: AsRef<[u8]>,
    {
        let key_id = RatchetingKeyId::from_key_id(key_id.into(), self.n_ratchet_bits);

        let sframe_key = DecryptionKey::derive_from(cipher_suite, key_id, &key_material)?;
        let base_key = RatchetingBaseKey::ratchet_forward(key_id, key_material, cipher_suite)?;

        self.keys.insert(
            key_id,
            RatchetingKeys {
                base_key,
                dec_key: sframe_key,
            },
        );

        Ok(())
    }

    /// removes a key associated with the key id
    pub fn remove<K>(&mut self, key_id: K) -> bool
    where
        K: Into<KeyId>,
    {
        let key_id = RatchetingKeyId::from_key_id(key_id.into(), self.n_ratchet_bits);
        self.keys.remove(&key_id).is_some()
    }

    /// returns the encryption key and [`RatchetingBaseKey`] associated with the key id
    pub fn get<K>(&self, key_id: K) -> Option<&RatchetingKeys<A, D>>
    where
        K: Into<KeyId>,
    {
        let key_id = RatchetingKeyId::from_key_id(key_id.into(), self.n_ratchet_bits);
        self.keys.get(&key_id)
    }

    /// Tries to ratchet a stored [`RatchetingBaseKey`].
    /// The given Key Id is interpreted as a [`RatchetingKeyId`], which generation is used to select the matching Sframe key.
    /// If the [`RatchetingKeyId`] indicates a Ratchet Step, which is different from the currently known one
    /// the [`RatchetingBaseKey`] is ratcheted forward accordingly.
    /// On success returns the number of ratcheting steps performed.
    /// Fails if more than [`RatchetingKeyStore::with_max_ratchet_steps`] steps would be needed.
    // TODO(v2): This method mustn't commit, a forged header could evict a valid key else wise. A
    // two step API is needed
    // TODO(v2): improve the API, so it is easier to determine which was the KID ratched from
    pub fn try_ratchet<K>(&mut self, key_id: K) -> Result<u64>
    where
        K: Into<KeyId>,
    {
        let mut key_id = RatchetingKeyId::from_key_id(key_id, self.n_ratchet_bits);
        let keys = self
            .keys
            .get_mut(&key_id)
            .ok_or(SframeError::MissingDecryptionKey(key_id.into()))?;

        // The base_key is already ratcheted, so we are one step ahead.
        // Thus we need to increment here to calculate the diff properly
        key_id.inc_ratchet_step();

        let current_ratchet_step = keys.base_key.key_id().ratchet_step();
        let max_ratchet_value = 1 << self.n_ratchet_bits;
        let step_diff = (key_id
            .ratchet_step()
            .overflowing_sub(current_ratchet_step)
            .0)
            % max_ratchet_value;

        if step_diff > self.max_ratchet_steps {
            return Err(SframeError::RatchetingFailure);
        }

        let mut next_base_key = None;
        for _ in 0..step_diff {
            next_base_key = Some(keys.base_key.next_base_key()?);
        }

        if let Some((next_key_id, next_material)) = next_base_key {
            keys.dec_key = DecryptionKey::derive_from(
                keys.dec_key.cipher_suite(),
                next_key_id,
                next_material,
            )?;
        }

        Ok(step_diff)
    }
}

/// Storage struct used by [`RatchetingKeyStore`], each associated with a [`RatchetingKeyId`]
pub struct RatchetingKeys<A, D>
where
    A: AeadDecrypt<Secret = D::Secret>,
    D: KeyDerivation + Ratcheting,
{
    /// provides key material used for ratcheting
    pub base_key: RatchetingBaseKey<D>,
    /// secrets used for decryption
    pub dec_key: DecryptionKey<A, D>,
}

impl<A, D> KeyStore<A, D> for RatchetingKeyStore<A, D>
where
    A: AeadDecrypt<Secret = D::Secret>,
    D: KeyDerivation + Ratcheting,
{
    fn get_key<K>(&self, key_id: K) -> Option<&DecryptionKey<A, D>>
    where
        K: Into<KeyId>,
    {
        let key_id = RatchetingKeyId::from_key_id(key_id, self.n_ratchet_bits);
        self.keys.get(&key_id).map(|key| &key.dec_key)
    }
}

#[cfg(all(test, crypto_backend))]
mod test {
    use crate::{
        CipherSuite,
        crypto::{Aead, Kdf},
        header::KeyId,
        key::KeyStore,
        ratchet::ratcheting_key_id::RatchetingKeyId,
    };
    use pretty_assertions::assert_eq;

    // Exercise the generic key store with the default crypto backend.
    type RatchetingKeyStore = super::RatchetingKeyStore<Aead, Kdf>;

    const N_RATCHET_BITS: u8 = 8;
    const KEY_MATERIAL: &[u8] = b"SECRET";
    const GENERATION: u64 = 42;
    const CIPHER_SUITE: CipherSuite = CipherSuite::AesGcm256Sha512;

    fn key_store_with_key() -> (RatchetingKeyStore, RatchetingKeyId) {
        let mut key_store = RatchetingKeyStore::new(N_RATCHET_BITS);
        let key_id = insert_key(&mut key_store, N_RATCHET_BITS);

        (key_store, key_id)
    }

    fn insert_key(key_store: &mut RatchetingKeyStore, n_ratchet_bits: u8) -> RatchetingKeyId {
        let key_id = RatchetingKeyId::new(GENERATION, n_ratchet_bits);
        key_store
            .insert(CIPHER_SUITE, key_id, KEY_MATERIAL)
            .unwrap();

        key_id
    }

    #[test]
    fn expands_and_ratchets_forward_on_insert() {
        let (key_store, key_id) = key_store_with_key();

        let keys = key_store.get(key_id);

        assert!(keys.is_some());
        let keys = keys.unwrap();

        assert_eq!(keys.base_key.key_id().generation(), GENERATION);
        // should have ratcheted forward already for the base key
        assert_eq!(keys.base_key.key_id().ratchet_step(), 1);

        // the  sframe key should have no ratcheting step
        let key_id_without_ratcheting_step = RatchetingKeyId::new(GENERATION, N_RATCHET_BITS);
        assert_eq!(
            KeyId::from(key_id_without_ratcheting_step),
            keys.dec_key.key_id()
        );
    }

    #[test]
    fn returns_none_for_unknown_key_on_get() {
        let key_store = RatchetingKeyStore::new(N_RATCHET_BITS);
        let key_id = RatchetingKeyId::new(GENERATION, N_RATCHET_BITS);

        let keys = key_store.get(key_id);

        assert!(keys.is_none());
    }

    #[test]
    fn removes_key() {
        let (mut key_store, key_id) = key_store_with_key();

        let was_removed = key_store.remove(key_id);
        let keys = key_store.get(key_id);

        assert!(was_removed);
        assert!(keys.is_none());
    }

    #[test]
    fn returns_err_for_unknown_key_on_ratcheting_get() {
        let mut key_store = RatchetingKeyStore::new(N_RATCHET_BITS);
        let key_id = RatchetingKeyId::new(GENERATION, N_RATCHET_BITS);

        let keys = key_store.try_ratchet(key_id);

        assert!(keys.is_err());
    }

    #[test]
    fn inserts_and_gets_key() {
        let (key_store, key_id) = key_store_with_key();

        let dec_key = key_store.get_key(key_id).unwrap();

        assert_eq!(KeyId::from(key_id), dec_key.key_id());
    }

    #[test]
    fn inserts_key_and_ratches_forward_if_needed() {
        let (mut key_store, mut key_id) = key_store_with_key();

        let ratchet_steps = key_store.try_ratchet(key_id).unwrap();
        assert_eq!(ratchet_steps, 0);

        let first_key = key_store.get_key(key_id).unwrap().clone();
        assert_eq!(first_key.key_id(), KeyId::from(key_id));

        // ratchet
        key_id.inc_ratchet_step();

        let ratchet_steps = key_store.try_ratchet(key_id).unwrap();
        assert_eq!(ratchet_steps, 1);

        let second_key = key_store.get_key(key_id).unwrap();
        assert_ne!(first_key.secret(), second_key.secret());
        assert_eq!(second_key.key_id(), KeyId::from(key_id));
    }

    #[test]
    fn stores_ratcheted_key() {
        let (mut key_store, mut key_id) = key_store_with_key();

        key_id.inc_ratchet_step();

        key_store.try_ratchet(key_id).unwrap();
        let first_secret = key_store.get_key(key_id).unwrap().clone();

        key_store.try_ratchet(key_id).unwrap();
        let second_secret = key_store.get_key(key_id).unwrap().clone();

        assert_eq!(first_secret, second_secret);
    }

    #[test]
    fn ratchets_forward_multiple_steps_at_once() {
        const STEPS: u64 = 3;
        let (mut key_store, mut key_id) = key_store_with_key();
        let (mut step_by_step_store, _) = key_store_with_key();

        for _ in 0..STEPS {
            key_id.inc_ratchet_step();
            step_by_step_store.try_ratchet(key_id).unwrap();
        }

        let ratchet_steps = key_store.try_ratchet(key_id).unwrap();

        assert_eq!(ratchet_steps, STEPS);
        let key = key_store.get_key(key_id).unwrap();
        assert_eq!(key.key_id(), KeyId::from(key_id));
        assert_eq!(key, step_by_step_store.get_key(key_id).unwrap());
    }

    #[test]
    fn rejects_ratcheting_beyond_the_maximum() {
        let mut key_store = RatchetingKeyStore::new(N_RATCHET_BITS).with_max_ratchet_steps(2);
        let mut key_id = insert_key(&mut key_store, N_RATCHET_BITS);
        let key_before = key_store.get_key(key_id).unwrap().clone();

        for _ in 0..3 {
            key_id.inc_ratchet_step();
        }

        assert!(key_store.try_ratchet(key_id).is_err());
        // the stored key must be untouched
        assert_eq!(&key_before, key_store.get_key(key_id).unwrap());
    }

    #[test]
    fn limits_n_ratchet_bits_to_63() {
        let n_ratchet_bits = 255;
        let mut key_store = RatchetingKeyStore::new(n_ratchet_bits);
        let mut key_id = RatchetingKeyId::new(1u8, n_ratchet_bits);

        key_store
            .insert(CipherSuite::AesGcm256Sha512, key_id, KEY_MATERIAL)
            .unwrap();
        key_id.inc_ratchet_step();

        assert!(key_store.try_ratchet(key_id).is_ok());
    }

    #[test]
    fn ratchets_on_ratcheting_step_overflow() {
        let n_ratchet_bits = 1;
        let mut key_store = RatchetingKeyStore::new(n_ratchet_bits);
        let mut key_id = insert_key(&mut key_store, n_ratchet_bits);

        key_id.inc_ratchet_step();
        key_store.try_ratchet(key_id).unwrap();
        let first_secret = key_store.get_key(key_id).unwrap().clone();
        // ratchet again to overflow
        key_id.inc_ratchet_step();
        key_store.try_ratchet(key_id).unwrap();
        let second_secret = key_store.get_key(key_id).unwrap().clone();

        assert_ne!(first_secret, second_secret);
    }
}
