use crate::header::KeyId;

use super::SframeKey;

pub trait KeyStore {
    fn get_key<K>(&self, key_id: K) -> Option<&SframeKey>
    where
        K: Into<KeyId>;
}

impl KeyStore for SframeKey {
    fn get_key<K>(&self, key_id: K) -> Option<&SframeKey>
    where
        K: Into<KeyId>,
    {
        if self.key_id() == key_id.into() {
            Some(self)
        } else {
            None
        }
    }
}
