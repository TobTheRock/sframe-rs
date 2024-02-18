use std::collections::HashMap;

use crate::{
    error::{Result, SframeError},
    header::KeyId,
};

use super::SframeKey;

pub trait KeyStore {
    fn get_key<K>(&self, key_id: K) -> Result<&SframeKey>
    where
        K: Into<KeyId>;
}

impl KeyStore for SframeKey {
    fn get_key<K>(&self, key_id: K) -> Result<&SframeKey>
    where
        K: Into<KeyId>,
    {
        let key_id = key_id.into();
        if self.key_id() == key_id {
            Ok(self)
        } else {
            Err(SframeError::MissingDecryptionKey(key_id))
        }
    }
}

impl KeyStore for HashMap<KeyId, SframeKey> {
    fn get_key<K>(&self, key_id: K) -> Result<&SframeKey>
    where
        K: Into<KeyId>,
    {
        let key_id = key_id.into();
        self.get(&key_id)
            .ok_or(SframeError::MissingDecryptionKey(key_id))
    }
}
