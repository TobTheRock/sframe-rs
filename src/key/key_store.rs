use std::collections::HashMap;

use crate::{
    crypto::{aead::AeadDecrypt, key_derivation::KeyDerivation},
    header::KeyId,
};

use super::generic::GenericDecryptionKey;

/// Abstraction for a key store that allows retrieving decryption keys by their respective key id.
pub trait KeyStore<A, D>
where
    A: AeadDecrypt<Secret = D::Secret>,
    D: KeyDerivation,
{
    /// Tries to retrieve a key with by its matching key ID.
    /// If no such key is found None is returned
    fn get_key<K>(&self, key_id: K) -> Option<&GenericDecryptionKey<A, D>>
    where
        K: Into<KeyId>;
}

impl<A, D> KeyStore<A, D> for GenericDecryptionKey<A, D>
where
    A: AeadDecrypt<Secret = D::Secret>,
    D: KeyDerivation,
{
    fn get_key<K>(&self, key_id: K) -> Option<&GenericDecryptionKey<A, D>>
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

impl<A, D> KeyStore<A, D> for HashMap<KeyId, GenericDecryptionKey<A, D>>
where
    A: AeadDecrypt<Secret = D::Secret>,
    D: KeyDerivation,
{
    fn get_key<K>(&self, key_id: K) -> Option<&GenericDecryptionKey<A, D>>
    where
        K: Into<KeyId>,
    {
        let key_id = key_id.into();
        self.get(&key_id)
    }
}
