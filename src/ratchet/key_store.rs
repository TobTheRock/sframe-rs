use std::collections::HashMap;

use crate::{
    crypto::{
        aead::AeadDecrypt,
        key_derivation::{KeyDerivation, Ratcheting},
    },
    error::SframeError,
    header::KeyId,
    key::KeyStore,
    ratchet::{
        key::GenericRatchetingDecryptionKey,
        key_id::{Generation, RatchetBits, RatchetStepDiff, RatchetingKeyId},
    },
};

/// Utility class to store one [`GenericRatchetingDecryptionKey`] per Key Generation ([`Generation`]).
/// A [`RatchetingKeyId`] selects the key by its Key Generation alone, its Ratchet Step says how
/// far the stored key has to be ratcheted forward.
///
/// Generic over the crypto backend used for decryption (`A`) and key derivation/ratcheting (`D`).
///
/// As the Ratchet Step is taken from an unauthenticated header, catching up with it lets an
/// attacker trigger key derivations with a single forged frame, which is why the No. steps to
/// catch up with is bounded, see [`GenericRatchetingKeyStore::new`].
pub struct GenericRatchetingKeyStore<A, D>
where
    A: AeadDecrypt<Secret = D::Secret>,
    D: KeyDerivation + Ratcheting,
{
    keys: HashMap<Generation, GenericRatchetingDecryptionKey<A, D>>,
    n_ratchet_bits: RatchetBits,
    max_ratchet_steps: RatchetStepDiff,
}

impl<A, D> GenericRatchetingKeyStore<A, D>
where
    A: AeadDecrypt<Secret = D::Secret>,
    D: KeyDerivation + Ratcheting,
{
    /// Creates an empty [`GenericRatchetingKeyStore`] for a session which depicts the Ratchet Step
    /// in `n_ratchet_bits` of the Key ID, and which catches up with at most `max_ratchet_steps`
    /// per frame - pick it to match the loss and re-ordering to be expected, as each step costs a
    /// key derivation an attacker can trigger.
    ///
    /// Always capped at
    /// [`RatchetBits::max_distinguishable_steps`](crate::ratchet::RatchetBits::max_distinguishable_steps),
    /// so a step which was already passed is never mistaken for a jump forward.
    pub fn new(n_ratchet_bits: RatchetBits, max_ratchet_steps: RatchetStepDiff) -> Self {
        Self {
            keys: HashMap::default(),
            n_ratchet_bits,
            max_ratchet_steps,
        }
    }

    /// stores a key for its Key Generation, replacing the key stored for it.
    /// Returns `true` if a key was replaced.
    pub fn insert(&mut self, key: GenericRatchetingDecryptionKey<A, D>) -> bool {
        self.keys.insert(key.key_id().generation(), key).is_some()
    }

    /// removes the key stored for a Key Generation, returns `true` if one was present
    pub fn remove(&mut self, generation: Generation) -> bool {
        self.keys.remove(&generation).is_some()
    }

    /// returns the key stored for a Key Generation, at the Ratchet Step it was ratcheted to
    pub fn get(&self, generation: Generation) -> Option<&GenericRatchetingDecryptionKey<A, D>> {
        self.keys.get(&generation)
    }

    /// The key of the Ratchet Step which `key_id` denotes, ratcheted forward from the key stored
    /// for its Key Generation. The store is left untouched, the key is only kept once it is
    /// recorded.
    fn ratcheted_key(
        &self,
        key_id: RatchetingKeyId,
    ) -> Result<GenericRatchetingDecryptionKey<A, D>, RatchetingKeyStoreError>
    where
        A: Clone,
        D::Secret: Clone,
    {
        let stored = self.keys.get(&key_id.generation()).ok_or(
            RatchetingKeyStoreError::UnknownGeneration(key_id.generation()),
        )?;

        // A single step is followed even where none is provably forward, which is the case for
        // `R = 1`: the ratcheted key is only kept if the frame decrypts, so a frame of the step
        // before costs one derivation and leaves the store untouched.
        let can_be_told_apart = self
            .n_ratchet_bits
            .max_distinguishable_steps()
            .max(RatchetStepDiff::ONE);
        let max_ratchet_steps = self.max_ratchet_steps.min(can_be_told_apart);

        stored
            .ratchet_to(key_id, max_ratchet_steps)
            .map_err(RatchetingKeyStoreError::RatchetingFailed)
    }
}

/// Why a [`GenericRatchetingKeyStore`] handed out no key. The Key Generation is the
/// unauthenticated one of the frame's header, it only identifies the frame which was rejected.
#[derive(Debug, thiserror::Error)]
pub enum RatchetingKeyStoreError {
    /// No key is stored for the Key Generation of the frame.
    #[error("No key is stored for Key Generation {0}")]
    UnknownGeneration(Generation),

    /// The Ratchet Step of the frame was already passed, is too far ahead to be caught up with,
    /// or its key could not be derived.
    #[error("{0}")]
    RatchetingFailed(#[source] SframeError),
}

/// A ratcheting store is a key store through a mutable reference: it ratchets the stored key
/// forward to the Ratchet Step of the frame's Key ID on lookup, and keeps that key only once the
/// frame authenticated it, so a forged Key ID cannot evict a valid key.
impl<A, D> KeyStore<A, D> for &mut GenericRatchetingKeyStore<A, D>
where
    A: AeadDecrypt<Secret = D::Secret> + Clone,
    D: KeyDerivation + Ratcheting,
    D::Secret: Clone,
{
    type Key = GenericRatchetingDecryptionKey<A, D>;
    type Error = RatchetingKeyStoreError;

    /// Fails with [`RatchetingKeyStoreError::UnknownGeneration`] if no key is stored for the Key
    /// Generation of `key_id`, or with [`RatchetingKeyStoreError::RatchetingFailed`] if its
    /// Ratchet Step was already passed or is too far ahead to be caught up with.
    ///
    /// The key is ratcheted forward on every lookup, which costs a clone of the stored key where
    /// there is no step to take.
    fn lookup(&self, key_id: KeyId) -> Result<Self::Key, Self::Error> {
        self.ratcheted_key(RatchetingKeyId::from_key_id(key_id, self.n_ratchet_bits))
    }

    fn record(&mut self, key: Self::Key) {
        self.insert(key);
    }
}

#[cfg(all(test, crypto_backend))]
mod test {
    use crate::{
        CipherSuite,
        crypto::{Aead, Kdf},
        header::KeyId,
        key::{GenericDecryptionKey, KeyStore},
        ratchet::{Generation, RatchetBits, RatchetStepDiff, RatchetingKeyId},
    };
    use pretty_assertions::assert_eq;

    use super::RatchetingKeyStoreError;

    // Exercise the generic key store with the default crypto backend.
    type RatchetingKeyStore = super::GenericRatchetingKeyStore<Aead, Kdf>;
    type RatchetingDecryptionKey = super::GenericRatchetingDecryptionKey<Aead, Kdf>;

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
        let mut key_store = RatchetingKeyStore::new(n_ratchet_bits(), max_ratchet_steps);
        let key =
            RatchetingDecryptionKey::derive_from(CIPHER_SUITE, key_id(0), KEY_MATERIAL).unwrap();
        key_store.insert(key);

        key_store
    }

    fn stored_key(key_store: &RatchetingKeyStore) -> GenericDecryptionKey<Aead, Kdf> {
        key_store.get(generation()).unwrap().as_ref().clone()
    }

    /// what the frame API does before it decrypts
    fn lookup(
        key_store: &mut RatchetingKeyStore,
        key_id: RatchetingKeyId,
    ) -> Result<RatchetingDecryptionKey, RatchetingKeyStoreError> {
        key_store.lookup(KeyId::from(key_id))
    }

    /// what it does once the frame authenticated
    fn lookup_and_record(
        mut key_store: &mut RatchetingKeyStore,
        key_id: RatchetingKeyId,
    ) -> Result<GenericDecryptionKey<Aead, Kdf>, RatchetingKeyStoreError> {
        let key = key_store.lookup(KeyId::from(key_id))?;
        let used = key.as_ref().clone();
        key_store.record(key);

        Ok(used)
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
    fn looks_the_stored_key_up() {
        let mut key_store = key_store();
        let stored = stored_key(&key_store);

        let looked_up = lookup(&mut key_store, key_id(0)).unwrap();

        assert_eq!(stored, *looked_up.as_ref());
    }

    #[test]
    fn follows_a_single_step_with_one_ratchet_bit() {
        // R = 1 leaves no step which is provably forward, but a flipped bit still has to be
        // followed, otherwise ratcheting would not work at all
        let n_ratchet_bits = RatchetBits::new(1);
        let key_id = RatchetingKeyId::new(generation(), n_ratchet_bits);
        let mut key_store = RatchetingKeyStore::new(n_ratchet_bits, RatchetStepDiff::ONE);
        key_store.insert(
            RatchetingDecryptionKey::derive_from(CIPHER_SUITE, key_id, KEY_MATERIAL).unwrap(),
        );
        let stored = stored_key(&key_store);

        let used = lookup_and_record(&mut key_store, key_id.inc_ratchet_step()).unwrap();

        assert_ne!(stored, used);
    }

    #[test]
    fn ratchets_the_stored_key_forward_to_the_key_id() {
        let mut key_store = key_store();
        let stored = stored_key(&key_store);

        let used = lookup_and_record(&mut key_store, key_id(2)).unwrap();

        assert_eq!(KeyId::from(key_id(2)), used.key_id());
        assert_ne!(stored, used);
        // the recorded key is kept for the next frame
        assert_eq!(used, stored_key(&key_store));
    }

    #[test]
    fn does_not_keep_a_key_which_was_not_recorded() {
        let mut key_store = key_store();
        let stored = stored_key(&key_store);

        // a frame which does not decrypt drops its key instead of recording it
        let ratcheted = lookup(&mut key_store, key_id(2)).unwrap();
        drop(ratcheted);

        // a forged header must not evict a valid key
        assert_eq!(stored, stored_key(&key_store));
    }

    #[test]
    fn fails_for_an_unknown_generation() {
        let mut key_store = RatchetingKeyStore::new(n_ratchet_bits(), RatchetStepDiff::NONE);

        let result = lookup(&mut key_store, key_id(0));

        assert!(matches!(
            result,
            Err(RatchetingKeyStoreError::UnknownGeneration(missing)) if missing == generation()
        ));
    }

    #[test]
    fn rejects_a_ratchet_step_which_was_already_passed() {
        let mut key_store = key_store();
        lookup_and_record(&mut key_store, key_id(2)).unwrap();
        let ratcheted = stored_key(&key_store);

        // a re-ordered frame carrying a step we are already past
        let result = lookup(&mut key_store, key_id(1));

        assert!(result.is_err());
        assert_eq!(ratcheted, stored_key(&key_store));
    }

    #[test]
    fn catches_up_at_most_max_ratchet_steps() {
        let mut key_store = key_store_with_max_steps(RatchetStepDiff::ONE);
        let stored = stored_key(&key_store);

        let result = lookup(&mut key_store, key_id(2));

        assert!(result.is_err());
        assert_eq!(stored, stored_key(&key_store));
    }

    #[test]
    fn never_catches_up_more_steps_than_can_be_told_apart() {
        let too_many = distinguishable_steps() + 1;
        let mut key_store = key_store_with_max_steps(RatchetStepDiff::from(too_many));
        let stored = stored_key(&key_store);

        let result = lookup(&mut key_store, key_id(too_many));

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

        let result = lookup(&mut key_store, key_id(ambiguous));

        assert!(result.is_err());
        assert_eq!(stored, stored_key(&key_store));
    }
}
