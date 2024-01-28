use std::collections::HashMap;

use crate::{
    crypto::{key_derivation::KeyDerivation, sframe_key::SframeKey},
    error::{Result, SframeError},
    header::KeyId,
    CipherSuiteVariant,
};

use super::{ratcheting_base_key::RatchetingBaseKey, ratcheting_key_id::RatchetingKeyId};

/// Utility class to store multiple encryption keys and base keys ([`RatchetingBaseKey`]) each associated with a [`KeyId`].
/// Allows to automatically ratchet forward an encryption key if necessary.
pub struct RatchetingKeyStore {
    keys: HashMap<RatchetingKeyId, RatchetingKeys>,
    n_ratchet_bits: u8,
}

impl RatchetingKeyStore {
    /// creates a new [`RatchetingKeyStore`] which uses `n_ratchet_bits` to determine the Ratchet Step  
    pub fn new(n_ratchet_bits: u8) -> Self {
        Self {
            n_ratchet_bits,
            keys: Default::default(),
        }
    }

    /// inserts a new key associated with a key id
    /// expands the key and ratchets the original key material to not store for security reasons
    pub fn insert<K, M>(
        &mut self,
        variant: CipherSuiteVariant,
        key_id: K,
        key_material: M,
    ) -> Result<()>
    where
        K: Into<KeyId>,
        M: AsRef<[u8]>,
    {
        let key_id = RatchetingKeyId::from_key_id(key_id.into(), self.n_ratchet_bits);
        let cipher_suite = variant.into();

        let sframe_key = SframeKey::expand_from(&cipher_suite, &key_material, key_id)?;
        let base_key = RatchetingBaseKey::ratchet_forward(key_id, key_material, variant)?;

        self.keys.insert(
            key_id,
            RatchetingKeys {
                base_key,
                sframe_key,
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
    pub fn get<K>(&self, key_id: K) -> Option<&RatchetingKeys>
    where
        K: Into<KeyId>,
    {
        let key_id = RatchetingKeyId::from_key_id(key_id.into(), self.n_ratchet_bits);
        self.keys.get(&key_id)
    }

    /// returns the encryption key associated with the key id
    /// if the key id indicates a Ratchet Step, which is different from the internally known one
    /// a [`RatchetingBaseKey`] is used to ratchet the encryption key forward accordingly
    pub fn ratcheting_get<K>(&mut self, key_id: K) -> Result<&SframeKey>
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

        let next_base_key = (0..step_diff).map(|_| keys.base_key.next_base_key()).last();
        if let Some(next_base_key) = next_base_key {
            let (next_key_id, next_material) = next_base_key?;
            keys.sframe_key =
                SframeKey::expand_from(&keys.sframe_key.cipher_suite, next_material, next_key_id)?;
        }

        Ok(&keys.sframe_key)
    }
}

/// Storage struct used by [`RatchetingKeyStore`], each associated with a [`RatchetingKeyId`]
pub struct RatchetingKeys {
    /// provides key material used for ratcheting
    pub base_key: RatchetingBaseKey,
    /// secrets used for encryption/decryption
    pub sframe_key: SframeKey,
}

#[cfg(test)]
mod test {
    use super::RatchetingKeyStore;
    use crate::{header::KeyId, ratchet::ratcheting_key_id::RatchetingKeyId, CipherSuiteVariant};

    const N_RATCHET_BITS: u8 = 8;
    const KEY_MATERIAL: &[u8] = b"SECRET";
    const GENERATION: u64 = 42;

    #[test]
    fn expands_and_ratchets_forward_on_insert() {
        let mut key_store = RatchetingKeyStore::new(N_RATCHET_BITS);
        let key_id = RatchetingKeyId::new(GENERATION, N_RATCHET_BITS);

        key_store
            .insert(CipherSuiteVariant::AesGcm256Sha512, key_id, KEY_MATERIAL)
            .unwrap();
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
            keys.sframe_key.key_id
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
        let mut key_store = RatchetingKeyStore::new(N_RATCHET_BITS);
        let key_id = RatchetingKeyId::new(GENERATION, N_RATCHET_BITS);

        key_store
            .insert(CipherSuiteVariant::AesGcm128Sha256, key_id, KEY_MATERIAL)
            .unwrap();
        let was_removed = key_store.remove(key_id);
        let keys = key_store.get(key_id);

        assert!(was_removed);
        assert!(keys.is_none());
    }

    #[test]
    fn returns_err_for_unknown_key_on_ratcheting_get() {
        let mut key_store = RatchetingKeyStore::new(N_RATCHET_BITS);
        let key_id = RatchetingKeyId::new(GENERATION, N_RATCHET_BITS);

        let keys = key_store.ratcheting_get(key_id);

        assert!(keys.is_err());
    }

    #[test]
    fn inserts_and_ratcheting_gets_key() {
        let mut key_store = RatchetingKeyStore::new(N_RATCHET_BITS);
        let key_id = RatchetingKeyId::new(GENERATION, N_RATCHET_BITS);

        key_store
            .insert(CipherSuiteVariant::AesGcm256Sha512, key_id, KEY_MATERIAL)
            .unwrap();
        let sframe_key = key_store.ratcheting_get(key_id);

        assert!(sframe_key.is_ok());
        assert_eq!(KeyId::from(key_id), sframe_key.unwrap().key_id);
    }

    #[test]
    fn inserts_key_and_ratches_forward_if_needed() {
        let mut key_store = RatchetingKeyStore::new(N_RATCHET_BITS);

        let mut key_id = RatchetingKeyId::new(42u8, N_RATCHET_BITS);

        key_store
            .insert(CipherSuiteVariant::AesGcm256Sha512, key_id, KEY_MATERIAL)
            .unwrap();

        let first_secret = key_store.ratcheting_get(key_id).unwrap().clone();
        let first_key_id = RatchetingKeyId::from_key_id(first_secret.key_id, N_RATCHET_BITS);

        assert_eq!(first_key_id, key_id);
        assert_eq!(first_key_id.ratchet_step(), 0);

        // ratchet
        key_id.inc_ratchet_step();

        let second_secret = key_store.ratcheting_get(key_id).unwrap();
        assert_ne!(first_secret.key, second_secret.key);
        assert_ne!(first_secret.salt, second_secret.salt);

        let second_key_id = RatchetingKeyId::from_key_id(second_secret.key_id, N_RATCHET_BITS);
        assert_eq!(second_key_id.ratchet_step(), 1);
        assert_eq!(first_key_id, second_key_id);
    }

    #[test]
    fn stores_ratcheted_key() {
        let mut key_store = RatchetingKeyStore::new(N_RATCHET_BITS);

        let mut key_id = RatchetingKeyId::new(42u8, N_RATCHET_BITS);

        key_store
            .insert(CipherSuiteVariant::AesGcm128Sha256, key_id, KEY_MATERIAL)
            .unwrap();

        // ratchet
        key_id.inc_ratchet_step();

        let first_secret = key_store.ratcheting_get(key_id).unwrap().clone();
        let second_secret = key_store.ratcheting_get(key_id).unwrap().clone();

        assert_eq!(first_secret, second_secret);
    }

    #[test]
    fn ratchets_on_ratcheting_step_overflow() {
        let n_ratchet_bits = 1;
        let mut key_store = RatchetingKeyStore::new(n_ratchet_bits);

        let mut key_id = RatchetingKeyId::new(42u8, n_ratchet_bits);

        key_store
            .insert(CipherSuiteVariant::AesGcm256Sha512, key_id, KEY_MATERIAL)
            .unwrap();

        // ratchet
        key_id.inc_ratchet_step();
        let first_secret = key_store.ratcheting_get(key_id).unwrap().clone();
        // ratchet again to overflow
        key_id.inc_ratchet_step();
        let second_secret = key_store.ratcheting_get(key_id).unwrap().clone();

        assert_ne!(first_secret, second_secret);
    }
}
