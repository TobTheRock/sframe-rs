use crate::{
    frame::{FrameValidation, ReplayAttackProtection},
    header,
};
use std::collections::HashMap;

use super::{ReplayAttackProtectionError, ReplayToken, UnvalidatedFrame};

/// Tracks replay protection per key id, keeping a [`ReplayAttackProtection`] for
/// each of them, see [RFC 9605 9.3](https://www.rfc-editor.org/rfc/rfc9605.html#name-anti-replay).
///
/// Key ids are tracked until they are [`remove`](Self::remove)d, thus a key id
/// should be dropped together with its key. Otherwise the store keeps growing,
/// note that a sender may use a set of key ids, e.g. when ratcheting.
pub struct ReplayAttackProtectionStore {
    validators: HashMap<header::KeyId, ReplayAttackProtection>,
    tolerance: u64,
}

impl ReplayAttackProtectionStore {
    /// Creates a store, tracking each key id with the given tolerance for the
    /// frame count.
    ///
    /// # Panics
    /// Panics if `tolerance` is `0` or exceeds the platform's `usize` range.
    // TODO(v2): tolerance should be usize or generic
    pub fn with_tolerance(tolerance: u64) -> Self {
        assert!(tolerance > 0, "Tolerance must be greater than 0");
        let _: usize = tolerance
            .try_into()
            .expect("Tolerance exceeds OS capabilities");

        ReplayAttackProtectionStore {
            validators: HashMap::new(),
            tolerance,
        }
    }

    /// Stops tracking the given key id, returning whether it was tracked at all.
    pub fn remove<K>(&mut self, key_id: K) -> bool
    where
        K: Into<header::KeyId>,
    {
        self.validators.remove(&key_id.into()).is_some()
    }

    /// Stops tracking every key id which does not match the predicate, e.g. to
    /// drop all ratchet steps belonging to one key generation.
    pub fn retain<F>(&mut self, mut keep: F)
    where
        F: FnMut(header::KeyId) -> bool,
    {
        self.validators.retain(|key_id, _| keep(*key_id));
    }
}

impl FrameValidation for ReplayAttackProtectionStore {
    type Token = ReplayToken;

    type Error = ReplayAttackProtectionError;

    /// Screens a frame against the window of its key id. An unknown key id
    /// passes: it is only tracked once a frame of it was decrypted, otherwise
    /// anyone could grow the store with forged headers.
    fn screen(&self, unvalidated: UnvalidatedFrame<'_>) -> Result<Self::Token, Self::Error> {
        let header = unvalidated.header();
        match self.validators.get(&header.key_id()) {
            Some(validator) => validator.screen(unvalidated),
            None => Ok(ReplayToken::new(header.key_id(), header.counter())),
        }
    }

    fn record(&mut self, token: Self::Token) {
        let tolerance = self.tolerance;
        self.validators
            .entry(token.key_id())
            .or_insert_with(|| ReplayAttackProtection::with_tolerance(tolerance))
            .record(token);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::frame::validation::test::{screen, screen_and_record};
    use ReplayAttackProtectionError::DuplicatedFrame;

    const TOLERANCE: u64 = 128;
    const KID_A: header::KeyId = 1;
    const KID_B: header::KeyId = 2;
    const COUNTER: header::Counter = 2480;

    fn store() -> ReplayAttackProtectionStore {
        ReplayAttackProtectionStore::with_tolerance(TOLERANCE)
    }

    #[test]
    fn tracks_key_ids_independently() {
        let mut store = store();

        // The same counter from two key ids is not a replay.
        assert!(screen_and_record(&mut store, KID_A, COUNTER).is_ok());
        assert!(screen_and_record(&mut store, KID_B, COUNTER).is_ok());
    }

    #[test]
    fn reuses_the_window_of_a_key_id() {
        let mut store = store();

        // A duplicate is only detected if the key id keeps its window,
        // instead of getting a new one per frame.
        assert!(screen_and_record(&mut store, KID_A, COUNTER).is_ok());
        assert!(matches!(
            screen(&store, KID_A, COUNTER),
            Err(DuplicatedFrame { .. })
        ));
    }

    #[test]
    fn screens_a_known_key_id() {
        let mut store = store();
        screen_and_record(&mut store, KID_A, COUNTER).unwrap();

        assert!(matches!(
            screen(&store, KID_A, COUNTER),
            Err(DuplicatedFrame { .. })
        ));
    }

    #[test]
    fn screening_accepts_an_unknown_key_id() {
        let store = store();

        assert!(screen(&store, KID_A, COUNTER).is_ok());
    }

    #[test]
    fn screening_does_not_track_a_key_id() {
        let store = store();

        screen(&store, KID_A, COUNTER).unwrap();

        // Key ids are unauthenticated, tracking them on screening would let
        // anyone grow the store.
        assert!(store.validators.is_empty());
    }

    #[test]
    fn removes_a_tracked_key_id() {
        let mut store = store();
        screen_and_record(&mut store, KID_A, COUNTER).unwrap();

        assert!(store.remove(KID_A));

        // Its window is gone, so the counter is not known anymore.
        assert!(screen(&store, KID_A, COUNTER).is_ok());
    }

    #[test]
    fn retains_only_the_matching_key_ids() {
        let mut store = store();
        screen_and_record(&mut store, KID_A, COUNTER).unwrap();
        screen_and_record(&mut store, KID_B, COUNTER).unwrap();

        store.retain(|key_id| key_id == KID_B);

        // The window of KID_A is gone, KID_B keeps its counter.
        assert!(screen(&store, KID_A, COUNTER).is_ok());
        assert!(matches!(
            screen(&store, KID_B, COUNTER),
            Err(DuplicatedFrame { .. })
        ));
    }

    #[test]
    fn reports_removal_of_an_untracked_key_id() {
        let mut store = store();

        assert!(!store.remove(KID_A));
    }

    #[test]
    fn keeps_other_key_ids_on_removal() {
        let mut store = store();
        screen_and_record(&mut store, KID_A, COUNTER).unwrap();
        screen_and_record(&mut store, KID_B, COUNTER).unwrap();

        store.remove(KID_A);

        assert!(matches!(
            screen(&store, KID_B, COUNTER),
            Err(DuplicatedFrame { .. })
        ));
    }
}
