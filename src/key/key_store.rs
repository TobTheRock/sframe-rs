use std::collections::HashMap;

use crate::header::KeyId;

use super::DecryptionKey;

/// Abstraction for a key store that allows retrieving decryption keys by their respective key id.
pub trait KeyStore {
    /// Tries to retrieve a key with by its matching key ID.
    /// If no such key is found an error ([`SframeError`]) is returned.
    fn get_key<K>(&self, key_id: K) -> Option<&DecryptionKey>
    where
        K: Into<KeyId>;
}

impl KeyStore for DecryptionKey {
    fn get_key<K>(&self, key_id: K) -> Option<&DecryptionKey>
    where
        K: Into<KeyId>,
    {
        let key_id = key_id.into();
        if self.key_id() == key_id {
            Some(self)
        } else {
            None
        }
    }
}

impl KeyStore for HashMap<KeyId, DecryptionKey> {
    fn get_key<K>(&self, key_id: K) -> Option<&DecryptionKey>
    where
        K: Into<KeyId>,
    {
        let key_id = key_id.into();
        self.get(&key_id)
    }
}
