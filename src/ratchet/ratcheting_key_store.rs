use std::collections::HashMap;

use crate::{
    CipherSuite,
    error::{Result, SframeError},
    header::KeyId,
    key::{DecryptionKey, KeyStore},
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
    pub fn get<K>(&self, key_id: K) -> Option<&RatchetingKeys>
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

        let next_base_key = (0..step_diff)
            .map(|_| keys.base_key.next_base_key())
            .next_back();
        if let Some(next_base_key) = next_base_key {
            let (next_key_id, next_material) = next_base_key?;
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
pub struct RatchetingKeys {
    /// provides key material used for ratcheting
    pub base_key: RatchetingBaseKey,
    /// secrets used for decryption
    pub dec_key: DecryptionKey,
}

impl KeyStore for RatchetingKeyStore {
    fn get_key<K>(&self, key_id: K) -> Option<&DecryptionKey>
    where
        K: Into<KeyId>,
    {
        let key_id = RatchetingKeyId::from_key_id(key_id, self.n_ratchet_bits);
        self.keys.get(&key_id).map(|key| &key.dec_key)
    }
}

#[cfg(test)]
mod test {
    use super::RatchetingKeyStore;
    use crate::{
        CipherSuite, header::KeyId, key::KeyStore, ratchet::ratcheting_key_id::RatchetingKeyId,
    };
    use pretty_assertions::assert_eq;

    const N_RATCHET_BITS: u8 = 8;
    const KEY_MATERIAL: &[u8] = b"SECRET";
    const GENERATION: u64 = 42;

    #[test]
    fn expands_and_ratchets_forward_on_insert() {
        let mut key_store = RatchetingKeyStore::new(N_RATCHET_BITS);
        let key_id = RatchetingKeyId::new(GENERATION, N_RATCHET_BITS);

        key_store
            .insert(CipherSuite::AesGcm256Sha512, key_id, KEY_MATERIAL)
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
        let mut key_store = RatchetingKeyStore::new(N_RATCHET_BITS);
        let key_id = RatchetingKeyId::new(GENERATION, N_RATCHET_BITS);

        key_store
            .insert(CipherSuite::AesGcm128Sha256, key_id, KEY_MATERIAL)
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

        let keys = key_store.try_ratchet(key_id);

        assert!(keys.is_err());
    }

    #[test]
    fn inserts_and_gets_key() {
        let mut key_store = RatchetingKeyStore::new(N_RATCHET_BITS);
        let key_id = RatchetingKeyId::new(GENERATION, N_RATCHET_BITS);

        key_store
            .insert(CipherSuite::AesGcm256Sha512, key_id, KEY_MATERIAL)
            .unwrap();
        let dec_key = key_store.get_key(key_id).unwrap();

        assert_eq!(KeyId::from(key_id), dec_key.key_id());
    }

    #[test]
    fn inserts_key_and_ratches_forward_if_needed() {
        let mut key_store = RatchetingKeyStore::new(N_RATCHET_BITS);
        let mut key_id = RatchetingKeyId::new(42u8, N_RATCHET_BITS);

        key_store
            .insert(CipherSuite::AesGcm256Sha512, key_id, KEY_MATERIAL)
            .unwrap();

        let ratchet_steps = key_store.try_ratchet(key_id).unwrap();
        assert_eq!(ratchet_steps, 0);

        let first_key = key_store.get_key(key_id).unwrap().clone();
        let first_key_id = RatchetingKeyId::from_key_id(first_key.key_id(), N_RATCHET_BITS);
        assert_eq!(first_key_id, key_id);
        assert_eq!(first_key_id.ratchet_step(), 0);

        // ratchet
        key_id.inc_ratchet_step();

        let ratchet_steps = key_store.try_ratchet(key_id).unwrap();
        assert_eq!(ratchet_steps, 1);

        let second_key = key_store.get_key(key_id).unwrap();
        assert_ne!(first_key.secret(), second_key.secret());

        let second_key_id = RatchetingKeyId::from_key_id(second_key.key_id(), N_RATCHET_BITS);
        assert_eq!(second_key_id.ratchet_step(), 1);
        assert_eq!(first_key_id, second_key_id);
    }

    #[test]
    fn stores_ratcheted_key() {
        let mut key_store = RatchetingKeyStore::new(N_RATCHET_BITS);

        let mut key_id = RatchetingKeyId::new(42u8, N_RATCHET_BITS);

        key_store
            .insert(CipherSuite::AesGcm128Sha256, key_id, KEY_MATERIAL)
            .unwrap();

        key_id.inc_ratchet_step();

        key_store.try_ratchet(key_id).unwrap();
        let first_secret = key_store.get_key(key_id).unwrap().clone();

        key_store.try_ratchet(key_id).unwrap();
        let second_secret = key_store.get_key(key_id).unwrap().clone();

        assert_eq!(first_secret, second_secret);
    }

    #[test]
    fn ratchets_on_ratcheting_step_overflow() {
        let n_ratchet_bits = 1;
        let mut key_store = RatchetingKeyStore::new(n_ratchet_bits);

        let mut key_id = RatchetingKeyId::new(42u8, n_ratchet_bits);

        key_store
            .insert(CipherSuite::AesGcm256Sha512, key_id, KEY_MATERIAL)
            .unwrap();

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
