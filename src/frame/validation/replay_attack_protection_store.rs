use crate::{
    error::Result,
    frame::{FrameValidation, ReplayAttackProtection},
    header::{self, SframeHeader},
};
use std::{cell::RefCell, collections::HashMap};

/// Tracks replay protection per key id, keeping a [`ReplayAttackProtection`] for
/// each of them, see [RFC 9605 9.3](https://www.rfc-editor.org/rfc/rfc9605.html#name-anti-replay).
///
/// Key ids are tracked until they are [`remove`](Self::remove)d, thus a key id
/// should be dropped together with its key. Otherwise the store keeps growing,
/// note that a sender may use a set of key ids, e.g. when ratcheting.
pub struct ReplayAttackProtectionStore {
    validators: RefCell<HashMap<header::KeyId, ReplayAttackProtection>>,
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
            validators: RefCell::new(HashMap::new()),
            tolerance,
        }
    }

    /// Stops tracking the given key id, returning whether it was tracked at all.
    pub fn remove<K>(&mut self, key_id: K) -> bool
    where
        K: Into<header::KeyId>,
    {
        self.validators.get_mut().remove(&key_id.into()).is_some()
    }

    /// Stops tracking every key id which does not match the predicate, e.g. to
    /// drop all ratchet steps belonging to one key generation.
    pub fn retain<F>(&mut self, mut keep: F)
    where
        F: FnMut(header::KeyId) -> bool,
    {
        self.validators.get_mut().retain(|key_id, _| keep(*key_id));
    }

    /// Screens a header against the window of its key id, without recording it.
    /// Safe on unauthenticated headers to reject invalid frames before decryption,
    /// an unknown key id passes as it is only tracked once a frame was decrypted.
    pub fn inspect(&self, header: &SframeHeader) -> Result<()> {
        match self.validators.borrow().get(&header.key_id()) {
            Some(validator) => validator.inspect(header),
            None => Ok(()),
        }
    }
}

impl FrameValidation for ReplayAttackProtectionStore {
    fn validate(&self, header: &SframeHeader) -> Result<()> {
        let key_id = header.key_id();
        self.validators
            .borrow_mut()
            .entry(key_id)
            .or_insert_with(|| {
                // Panics if tolerance==0, already checked in ctor
                ReplayAttackProtection::with_tolerance(self.tolerance).for_key_id(key_id)
            })
            .validate(header)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{frame::FrameValidation, header::SframeHeader};

    const TOLERANCE: u64 = 128;
    const KID_A: u64 = 1;
    const KID_B: u64 = 2;
    const COUNTER: u64 = 2480;

    fn store() -> ReplayAttackProtectionStore {
        ReplayAttackProtectionStore::with_tolerance(TOLERANCE)
    }

    fn header(key_id: u64, counter: u64) -> SframeHeader {
        SframeHeader::new(key_id, counter)
    }

    #[test]
    fn tracks_key_ids_independently() {
        let store = store();

        // The same counter from two key ids is not a replay.
        assert!(store.validate(&header(KID_A, COUNTER)).is_ok());
        assert!(store.validate(&header(KID_B, COUNTER)).is_ok());
    }

    #[test]
    fn reuses_the_window_of_a_key_id() {
        let store = store();

        // A duplicate is only detected if the key id keeps its window,
        // instead of getting a new one per frame.
        assert!(store.validate(&header(KID_A, COUNTER)).is_ok());
        assert!(store.validate(&header(KID_A, COUNTER)).is_err());
    }

    #[test]
    fn inspect_screens_a_known_key_id() {
        let store = store();
        store.validate(&header(KID_A, COUNTER)).unwrap();

        assert!(store.inspect(&header(KID_A, COUNTER)).is_err());
    }

    #[test]
    fn inspect_accepts_an_unknown_key_id() {
        let store = store();

        assert!(store.inspect(&header(KID_A, COUNTER)).is_ok());
    }

    #[test]
    fn inspect_does_not_track_a_key_id() {
        let store = store();

        store.inspect(&header(KID_A, COUNTER)).unwrap();

        // Key ids are unauthenticated, tracking them on inspection would let
        // anyone grow the store.
        assert!(store.validate(&header(KID_A, COUNTER)).is_ok());
    }

    #[test]
    fn removes_a_tracked_key_id() {
        let mut store = store();
        store.validate(&header(KID_A, COUNTER)).unwrap();

        assert!(store.remove(KID_A));

        // Its window is gone, so the counter is not known anymore.
        assert!(store.validate(&header(KID_A, COUNTER)).is_ok());
    }

    #[test]
    fn retains_only_the_matching_key_ids() {
        let mut store = store();
        store.validate(&header(KID_A, COUNTER)).unwrap();
        store.validate(&header(KID_B, COUNTER)).unwrap();

        store.retain(|key_id| key_id == KID_B);

        // The window of KID_A is gone, KID_B keeps its counter.
        assert!(store.validate(&header(KID_A, COUNTER)).is_ok());
        assert!(store.validate(&header(KID_B, COUNTER)).is_err());
    }

    #[test]
    fn reports_removal_of_an_untracked_key_id() {
        let mut store = store();

        assert!(!store.remove(KID_A));
    }

    #[test]
    fn keeps_other_key_ids_on_removal() {
        let mut store = store();
        store.validate(&header(KID_A, COUNTER)).unwrap();
        store.validate(&header(KID_B, COUNTER)).unwrap();

        store.remove(KID_A);

        assert!(store.inspect(&header(KID_B, COUNTER)).is_err());
    }
}
