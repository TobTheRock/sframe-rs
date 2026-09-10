use std::collections::HashMap;

use crate::{
    crypto::{aead::AeadDecrypt, key_derivation::KeyDerivation},
    header::KeyId,
};

use super::generic::GenericDecryptionKey;

/// Looks a decryption key up by its Key ID, without any state of its own.
///
/// This is what a receiver implements whose keys are simply there: nothing has to happen on
/// lookup, and nothing can go wrong with it beyond not finding a key.
///
/// Implement it, and a shared reference to your store is a [`KeyStore`] - the trait the frame
/// API decrypts against, see
/// [`decrypt_into`](crate::frame::EncryptedFrameView::decrypt_into).
pub trait KeyLookup<A, D>
where
    A: AeadDecrypt<Secret = D::Secret>,
    D: KeyDerivation,
{
    /// Tries to retrieve a key with by its matching key id.
    /// If no such key is found None is returned
    fn get_key<K>(&self, key_id: K) -> Option<&GenericDecryptionKey<A, D>>
    where
        K: Into<KeyId>;
}

/// Provides the decryption keys of a receiver, the abstraction the frame API decrypts against.
///
/// ```text
/// lookup(key_id)? -> key -> decrypt()? -> record(key)
/// ```
///
/// Split in two steps because a Key ID is unauthenticated until its frame decrypts: a store which
/// changes state on lookup could be driven by forged frames. A key which is dropped instead of
/// recorded leaves the store as it was, so a forged Key ID cannot evict the key of a valid one.
/// A store which only looks keys up ignores the second step.
///
/// It is implemented for references rather than for the stores themselves, so both cases pass the
/// store the way it is used and nothing else has to change at the call site:
///
/// ```text
/// frame.decrypt(&keys)?        // a lookup, shared
/// frame.decrypt(&mut keys)?    // a ratcheting store, mutable
/// ```
pub trait KeyStore<A, D>
where
    A: AeadDecrypt<Secret = D::Secret>,
    D: KeyDerivation,
{
    /// The key a lookup handed out, borrowed from the store or derived on the spot. Opaque to the
    /// caller apart from the decryption key it yields.
    type Key: AsRef<GenericDecryptionKey<A, D>>;

    /// Why no key was handed out.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Looks the key of a Key ID up BEFORE decryption, leaving the store's state untouched.
    /// The Key ID is attacker controlled here.
    ///
    /// Report why with an error of your own: the frame API boxes it as the source of
    /// [`SframeError::MissingDecryptionKey`](crate::error::SframeError::MissingDecryptionKey),
    /// where [`source_as`](crate::error::SframeError::source_as) names it again.
    #[must_use = "a key must be recorded once the frame decrypts, or dropped"]
    fn lookup(&self, key_id: KeyId) -> Result<Self::Key, Self::Error>;

    /// Takes the key back AFTER decryption authenticated the frame it was looked up for, so a
    /// store which derived it can keep it for the frames to come.
    ///
    /// Infallible on purpose: every rejection belongs in [`lookup`](Self::lookup). A frame which
    /// got this far is authentic, failing here would discard a frame the receiver already
    /// decrypted.
    fn record(&mut self, key: Self::Key);
}

/// A [`KeyLookup`] has no key for a Key ID, all it can report.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("the key store holds no key for it")]
pub struct KeyNotFound;

/// Every plain lookup is a key store through a shared reference, recording nothing.
impl<'store, A, D, S> KeyStore<A, D> for &'store S
where
    A: AeadDecrypt<Secret = D::Secret> + 'store,
    D: KeyDerivation + 'store,
    S: KeyLookup<A, D>,
{
    type Key = &'store GenericDecryptionKey<A, D>;
    type Error = KeyNotFound;

    fn lookup(&self, key_id: KeyId) -> Result<Self::Key, Self::Error> {
        (*self).get_key(key_id).ok_or(KeyNotFound)
    }

    fn record(&mut self, _key: Self::Key) {}
}

impl<A, D> KeyLookup<A, D> for GenericDecryptionKey<A, D>
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

impl<A, D> KeyLookup<A, D> for HashMap<KeyId, GenericDecryptionKey<A, D>>
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
