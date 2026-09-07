use std::collections::HashMap;

use crate::{
    crypto::{
        aead::AeadDecrypt,
        key_derivation::{KeyDerivation, Ratcheting},
    },
    error::{Result, SframeError},
    ratchet::{
        key::RatchetingDecryptionKey,
        key_id::{Generation, RatchetStepDiff, RatchetingKeyId},
    },
};

/// Utility class to store one [`RatchetingDecryptionKey`] per Key Generation ([`Generation`]).
/// A [`RatchetingKeyId`] selects the key by its Key Generation alone, its Ratchet Step says how
/// far the stored key has to be ratcheted forward.
///
/// Generic over the crypto backend used for decryption (`A`) and key derivation/ratcheting (`D`).
///
/// As the Ratchet Step is taken from an unauthenticated header, catching up with it lets an
/// attacker trigger key derivations with a single forged frame, which is why the No. steps to
/// catch up with is bounded, see [`RatchetingKeyStore::new`].
pub struct RatchetingKeyStore<A, D>
where
    A: AeadDecrypt<Secret = D::Secret>,
    D: KeyDerivation + Ratcheting,
{
    keys: HashMap<Generation, RatchetingDecryptionKey<A, D>>,
    max_ratchet_steps: RatchetStepDiff,
}

impl<A, D> RatchetingKeyStore<A, D>
where
    A: AeadDecrypt<Secret = D::Secret>,
    D: KeyDerivation + Ratcheting,
{
    /// Creates an empty [`RatchetingKeyStore`] which catches up with at most `max_ratchet_steps`
    /// per frame in [`RatchetingKeyStore::with_ratcheted_key`] - pick it to match the loss and
    /// re-ordering to be expected, as each step costs a key derivation an attacker can trigger.
    ///
    /// Always capped at
    /// [`RatchetBits::max_distinguishable_steps`](super::RatchetBits::max_distinguishable_steps),
    /// so a step which was already passed is never mistaken for a jump forward.
    pub fn new(max_ratchet_steps: RatchetStepDiff) -> Self {
        Self {
            keys: HashMap::default(),
            max_ratchet_steps,
        }
    }

    /// stores a key for its Key Generation, replacing the key stored for it.
    /// Returns `true` if a key was replaced.
    pub fn insert(&mut self, key: RatchetingDecryptionKey<A, D>) -> bool {
        self.keys.insert(key.key_id().generation(), key).is_some()
    }

    /// removes the key stored for a Key Generation, returns `true` if one was present
    pub fn remove(&mut self, generation: Generation) -> bool {
        self.keys.remove(&generation).is_some()
    }

    /// returns the key stored for a Key Generation, at the Ratchet Step it was ratcheted to
    pub fn get(&self, generation: Generation) -> Option<&RatchetingDecryptionKey<A, D>> {
        self.keys.get(&generation)
    }

    /// Runs `operation` with the decryption key of the Ratchet Step which `key_id` denotes,
    /// ratcheting the key stored for its Key Generation forward to reach that step.
    ///
    /// The ratcheted key replaces the stored one only if `operation` succeeded. As the Ratchet
    /// Step is taken from an unauthenticated header, a forged frame can thus not evict a valid
    /// key: it fails to decrypt, and the store is left untouched.
    ///
    /// Fails with [`SframeError::MissingDecryptionKey`] if no key is stored for the Key
    /// Generation, or with [`SframeError::RatchetingFailure`] if the Ratchet Step was already
    /// passed or is too far ahead to be caught up with.
    pub fn with_ratcheted_key<T, F>(&mut self, key_id: RatchetingKeyId, operation: F) -> Result<T>
    where
        F: FnOnce(&RatchetingDecryptionKey<A, D>) -> Result<T>,
        A: Clone,
        D::Secret: Clone,
    {
        let stored = self
            .keys
            .get(&key_id.generation())
            .ok_or(SframeError::MissingDecryptionKey(key_id.into()))?;

        // the steady state between two Ratchet Steps: there is nothing to ratchet or to commit
        if stored.key_id() == key_id {
            return operation(stored);
        }

        let max_ratchet_steps = self
            .max_ratchet_steps
            .min(key_id.n_ratchet_bits().max_distinguishable_steps());
        let ratcheted = stored.ratchet_to(key_id, max_ratchet_steps)?;

        // committing only after the operation succeeded is what keeps an unauthenticated
        // Ratchet Step from evicting a valid key
        let result = operation(&ratcheted)?;
        self.keys.insert(key_id.generation(), ratcheted);

        Ok(result)
    }
}

#[cfg(all(test, crypto_backend))]
mod test {
    use crate::{
        CipherSuite,
        crypto::{Aead, Kdf},
        error::{Result, SframeError},
        header::KeyId,
        key::crypto_key::DecryptionKey,
        ratchet::{Generation, RatchetBits, RatchetStepDiff, RatchetingKeyId},
    };
    use pretty_assertions::assert_eq;

    // Exercise the generic key store with the default crypto backend.
    type RatchetingKeyStore = super::RatchetingKeyStore<Aead, Kdf>;
    type RatchetingDecryptionKey = super::RatchetingDecryptionKey<Aead, Kdf>;

    const KEY_MATERIAL: &[u8] = b"SuperSecret";
    const CIPHER_SUITE: CipherSuite = CipherSuite::AesGcm256Sha512;

    fn n_ratchet_bits() -> RatchetBits {
        RatchetBits::new(4)
    }

    fn distinguishable_steps() -> u64 {
        n_ratchet_bits().max_distinguishable_steps().into()
    }

    fn generation() -> Generation {
        Generation::from(42)
    }

    /// the key id of the Key Generation, `n_steps` Ratchet Steps in
    fn key_id(n_steps: u64) -> RatchetingKeyId {
        let key_id = RatchetingKeyId::new(generation(), n_ratchet_bits());
        (0..n_steps).fold(key_id, |key_id, _| key_id.inc_ratchet_step())
    }

    /// a store holding the key of the Key Generation at Ratchet Step 0, which may catch up with
    /// the whole distinguishable range of Ratchet Steps
    fn key_store() -> RatchetingKeyStore {
        key_store_with_max_steps(n_ratchet_bits().max_distinguishable_steps())
    }

    fn key_store_with_max_steps(max_ratchet_steps: RatchetStepDiff) -> RatchetingKeyStore {
        let mut key_store = RatchetingKeyStore::new(max_ratchet_steps);
        let key =
            RatchetingDecryptionKey::derive_from(CIPHER_SUITE, key_id(0), KEY_MATERIAL).unwrap();
        key_store.insert(key);

        key_store
    }

    fn stored_key(key_store: &RatchetingKeyStore) -> DecryptionKey<Aead, Kdf> {
        key_store.get(generation()).unwrap().as_ref().clone()
    }

    #[test]
    fn inserts_and_gets_a_key_per_generation() {
        let key_store = key_store();

        let key = key_store.get(generation()).unwrap();

        assert_eq!(key_id(0), key.key_id());
    }

    #[test]
    fn replaces_the_key_of_a_generation_on_insert() {
        let mut replaced = key_store();
        let key = RatchetingDecryptionKey::derive_from(CIPHER_SUITE, key_id(0), b"other").unwrap();

        let was_replaced = replaced.insert(key);

        assert!(was_replaced);
        assert_ne!(stored_key(&key_store()), stored_key(&replaced));
    }

    #[test]
    fn returns_none_for_an_unknown_generation() {
        let key_store = key_store();

        assert!(key_store.get(Generation::from(1)).is_none());
    }

    #[test]
    fn removes_a_key() {
        let mut key_store = key_store();

        assert!(key_store.remove(generation()));
        assert!(!key_store.remove(generation()));
        assert!(key_store.get(generation()).is_none());
    }

    #[test]
    fn runs_the_operation_with_the_stored_key() {
        let mut key_store = key_store();
        let stored = stored_key(&key_store);

        let used = key_store
            .with_ratcheted_key(key_id(0), |key| Ok(key.as_ref().clone()))
            .unwrap();

        assert_eq!(stored, used);
    }

    #[test]
    fn ratchets_the_stored_key_forward_to_the_key_id() {
        let mut key_store = key_store();
        let stored = stored_key(&key_store);

        let used = key_store
            .with_ratcheted_key(key_id(2), |key| Ok(key.as_ref().clone()))
            .unwrap();

        assert_eq!(KeyId::from(key_id(2)), used.key_id());
        assert_ne!(stored, used);
        // the ratcheted key is kept for the next frame
        assert_eq!(used, stored_key(&key_store));
    }

    #[test]
    fn does_not_commit_a_key_if_the_operation_failed() {
        let mut key_store = key_store();
        let stored = stored_key(&key_store);

        let result = key_store.with_ratcheted_key(key_id(2), |_| -> Result<()> {
            Err(SframeError::DecryptionFailure)
        });

        assert!(result.is_err());
        // a forged header must not evict a valid key
        assert_eq!(stored, stored_key(&key_store));
    }

    #[test]
    fn fails_for_an_unknown_generation() {
        let mut key_store = RatchetingKeyStore::new(RatchetStepDiff::NONE);

        let result = key_store.with_ratcheted_key(key_id(0), |_| Ok(()));

        assert!(matches!(
            result,
            Err(SframeError::MissingDecryptionKey(missing)) if missing == KeyId::from(key_id(0))
        ));
    }

    #[test]
    fn rejects_a_ratchet_step_which_was_already_passed() {
        let mut key_store = key_store();
        key_store.with_ratcheted_key(key_id(2), |_| Ok(())).unwrap();
        let ratcheted = stored_key(&key_store);

        // a re-ordered frame carrying a step we are already past
        let result = key_store.with_ratcheted_key(key_id(1), |_| Ok(()));

        assert!(result.is_err());
        assert_eq!(ratcheted, stored_key(&key_store));
    }

    #[test]
    fn catches_up_at_most_max_ratchet_steps() {
        let mut key_store = key_store_with_max_steps(RatchetStepDiff::ONE);
        let stored = stored_key(&key_store);

        let result = key_store.with_ratcheted_key(key_id(2), |_| Ok(()));

        assert!(result.is_err());
        assert_eq!(stored, stored_key(&key_store));
    }

    #[test]
    fn never_catches_up_more_steps_than_can_be_told_apart() {
        let too_many = distinguishable_steps() + 1;
        let mut key_store = key_store_with_max_steps(RatchetStepDiff::from(too_many));
        let stored = stored_key(&key_store);

        let result = key_store.with_ratcheted_key(key_id(too_many), |_| Ok(()));

        assert!(result.is_err());
        assert_eq!(stored, stored_key(&key_store));
    }

    #[test]
    fn rejects_more_ratchet_steps_than_can_be_told_apart() {
        let mut key_store = key_store();
        let stored = stored_key(&key_store);
        // one step further is half of the 2^R steps: as many steps forward as it is back, so it
        // cannot be told apart from a step which was already passed
        let ambiguous = distinguishable_steps() + 1;

        let result = key_store.with_ratcheted_key(key_id(ambiguous), |_| Ok(()));

        assert!(result.is_err());
        assert_eq!(stored, stored_key(&key_store));
    }
}
