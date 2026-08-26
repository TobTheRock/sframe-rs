use crate::{
    frame::{FrameValidation, validation::sliding_window::SlidingWindow},
    header,
};

use super::{ReplayToken, UnvalidatedFrame, util::assert_tolerance};

/// This implementation allows to detect replay attacks by omitting frames with
/// to old frame counters, see [RFC 9605 9.3](https://www.rfc-editor.org/rfc/rfc9605.html#name-anti-replay).
/// The window of allowed frame counts is given with a certain tolerance.
///
/// Protects a single sender, rejecting frames of any other key id. Use
/// [`ReplayAttackProtectionStore`](super::ReplayAttackProtectionStore) to track
/// several senders.
pub struct ReplayAttackProtection {
    window: Window,
    key_id: header::KeyId,
}

impl ReplayAttackProtection {
    /// Creates a [`ReplayAttackProtection`] for the sender `key_id`, with a given
    /// tolerance for the frame count.
    ///
    /// # Panics
    /// Panics if `tolerance` is `0` or exceeds `header::Counter::MAX / 2`.
    pub fn new(key_id: header::KeyId, tolerance: usize) -> Self {
        assert_tolerance(tolerance);
        ReplayAttackProtection {
            window: Window::Empty(Empty {
                window: SlidingWindow::new(tolerance),
                size: tolerance as u64,
            }),
            key_id,
        }
    }

    /// Rejects headers of another sender, leaving the window untouched.
    fn verify_key_id(&self, key_id: header::KeyId) -> Result<(), ReplayAttackProtectionError> {
        if key_id != self.key_id {
            return Err(ReplayAttackProtectionError::KeyIdMismatch {
                key_id,
                expected: self.key_id,
            });
        }
        Ok(())
    }
}

/// Why [`ReplayAttackProtection`] rejected a frame. The key id and counter are
/// the unauthenticated ones of its header, they only identify the rejected frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplayAttackProtectionError {
    /// The frame belongs to another sender than the associated one.
    #[error(
        "Frame of key id {key_id} was rejected, as it does not match the associated {expected}"
    )]
    KeyIdMismatch {
        /// Key id of the rejected frame.
        key_id: header::KeyId,
        /// Key id the protection is associated with.
        expected: header::KeyId,
    },
    /// The frame counter was already recorded.
    #[error("Frame {counter} of key id {key_id} was rejected, as it was duplicated")]
    DuplicatedFrame {
        /// Key id of the rejected frame.
        key_id: header::KeyId,
        /// Counter of the rejected frame.
        counter: header::Counter,
    },
    /// The frame counter fell out of the tolerance window.
    #[error("Frame {counter} of key id {key_id} was rejected, as its counter is too old")]
    CounterTooOld {
        /// Key id of the rejected frame.
        key_id: header::KeyId,
        /// Counter of the rejected frame.
        counter: header::Counter,
    },
}

impl FrameValidation for ReplayAttackProtection {
    type Token = ReplayToken;

    type Error = ReplayAttackProtectionError;

    fn screen(&self, unvalidated: UnvalidatedFrame<'_>) -> Result<Self::Token, Self::Error> {
        let header = unvalidated.header();
        self.verify_key_id(header.key_id())?;

        let token = ReplayToken {
            key_id: header.key_id(),
            counter: header.counter(),
        };
        if let Window::Active(active) = &self.window {
            active.screen(&token)?;
        }

        Ok(token)
    }

    fn record(&mut self, token: Self::Token) {
        self.window.record(token.counter);
    }
}

enum Window {
    Empty(Empty),
    Active(Active),
}

impl Window {
    /// Records `counter`, anchoring the window on the first frame.
    fn record(&mut self, counter: header::Counter) {
        match self {
            Window::Active(active) => active.record(counter),
            Window::Empty(empty) => {
                // First frame: swap the pre-allocated `Empty` out (the placeholder
                // holds an empty, non-allocating window) and consume it to anchor.
                let placeholder = Empty {
                    window: SlidingWindow::new(0),
                    size: 0,
                };
                let mut active = std::mem::replace(empty, placeholder).anchor(counter);
                active.record(counter);
                *self = Window::Active(active);
            }
        }
    }
}

/// Window before the first frame: the buffer is already allocated, only the
/// anchor counter is still unknown.
struct Empty {
    window: SlidingWindow,
    size: u64,
}

impl Empty {
    /// Consumes the pre-allocated window, anchoring it so `counter` sits in the
    /// newest slot.
    fn anchor(self, counter: header::Counter) -> Active {
        Active {
            window: self.window,
            size: self.size,
            oldest: counter.wrapping_sub(self.size - 1),
        }
    }
}

struct Active {
    window: SlidingWindow,
    size: u64,
    /// Counter mapped to the lowest window index (0).
    oldest: header::Counter,
}

impl Active {
    /// Records `counter` and advances the window.
    ///
    /// Counters outside the window are dropped instead of reported: only
    /// [`screen`](Self::screen)ed counters get here, and rejecting an already
    /// decrypted frame is not an option.
    fn record(&mut self, counter: header::Counter) {
        if self.is_newer(counter) {
            self.advance_to(counter);
        }

        if let Some(idx) = self.window_index(counter) {
            self.window.set(idx);
        }
    }

    /// Screens the token's counter without recording it or moving the window.
    /// Errors if the counter is too old or already seen.
    fn screen(&self, token: &ReplayToken) -> Result<(), ReplayAttackProtectionError> {
        let ReplayToken { key_id, counter } = *token;
        if self.is_newer(counter) {
            return Ok(());
        }

        match self.window_index(counter) {
            None => Err(ReplayAttackProtectionError::CounterTooOld { key_id, counter }),
            Some(idx) if self.window.is_set(idx) => {
                Err(ReplayAttackProtectionError::DuplicatedFrame { key_id, counter })
            }
            Some(_) => Ok(()),
        }
    }

    /// The newest accepted counter.
    fn newest(&self) -> header::Counter {
        self.oldest.wrapping_add(self.size - 1)
    }

    fn is_newer(&self, counter: header::Counter) -> bool {
        let forward = counter.wrapping_sub(self.newest());
        forward != 0 && forward <= header::Counter::MAX / 2
    }

    fn advance_to(&mut self, counter: header::Counter) {
        let shift = counter.wrapping_sub(self.newest()).min(self.size);
        self.window.shift_right(shift as usize);
        self.oldest = counter.wrapping_sub(self.size - 1);
    }

    /// Ring buffer index of `counter` (oldest -> 0), or `None` when it falls
    /// outside the window `[oldest, oldest + size)`.
    fn window_index(&self, counter: header::Counter) -> Option<usize> {
        let index = counter.wrapping_sub(self.oldest);
        if index < self.size {
            Some(index as usize)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::frame::validation::util::test::{screen, screen_and_record};
    use ReplayAttackProtectionError::*;

    const KID: header::KeyId = 23456789;
    const TOLERANCE: usize = 128;
    const SPAN: u64 = TOLERANCE as u64; // the tolerance, as a counter distance

    // A reference window `[WINDOW_OLDEST, NEWEST]`, spanning TOLERANCE counters.
    const NEWEST: u64 = 2480;
    const WINDOW_OLDEST: u64 = NEWEST - (SPAN - 1);
    const TOO_OLD: u64 = NEWEST - SPAN; // one counter past the oldest edge
    const OLDER: u64 = NEWEST - 80; // an arbitrary counter well inside the window

    // Newer frames that advance the window, named by their effect on OLDER.
    const NEWER_KEEPS_OLDER: u64 = NEWEST + 20;
    const NEWER_DROPS_OLDER: u64 = NEWEST + 60;
    const FULL_WINDOW_JUMP: u64 = NEWEST + SPAN; // shift >= size, wipes all marks

    const OTHER_KID: header::KeyId = KID + 1;

    fn validator() -> Fixture {
        Fixture(ReplayAttackProtection::new(KID, TOLERANCE))
    }

    struct Fixture(ReplayAttackProtection);

    impl Fixture {
        /// Screens and records the counter, as a frame which decrypted.
        fn expect_accepted(&mut self, counter: header::Counter) -> &mut Self {
            assert!(
                screen_and_record(&mut self.0, KID, counter).is_ok(),
                "counter {counter} should be accepted"
            );
            self
        }

        /// Screens the counter without recording it, as a frame which is only
        /// inspected or which failed to decrypt.
        fn expect_screened(&mut self, counter: header::Counter) -> &mut Self {
            assert!(
                screen(&self.0, KID, counter).is_ok(),
                "counter {counter} should pass screening"
            );
            self
        }

        fn expect_duplicated(&mut self, counter: header::Counter) -> &mut Self {
            let err = self.expect_rejected(counter);
            assert!(
                matches!(err, DuplicatedFrame { .. }),
                "counter {counter}: expected a duplicate, got {err}"
            );
            self
        }

        fn expect_too_old(&mut self, counter: header::Counter) -> &mut Self {
            let err = self.expect_rejected(counter);
            assert!(
                matches!(err, CounterTooOld { .. }),
                "counter {counter}: expected a too old counter, got {err}"
            );
            self
        }

        fn expect_rejected(&mut self, counter: header::Counter) -> ReplayAttackProtectionError {
            screen(&self.0, KID, counter)
                .expect_err(&format!("counter {counter} should be rejected"))
        }
    }

    #[test]
    fn screening_does_not_record_the_counter() {
        // Screening must not mutate state: the same counter can be screened
        // repeatedly and is still accepted afterwards.
        validator()
            .expect_accepted(OLDER)
            .expect_screened(NEWEST)
            .expect_screened(NEWEST)
            .expect_accepted(NEWEST);
    }

    #[test]
    fn screening_accepts_future_counter_without_advancing() {
        // A future counter passes screening but must not advance the window,
        // so an in-window counter it would have dropped is still accepted.
        validator()
            .expect_accepted(NEWEST)
            .expect_screened(NEWER_DROPS_OLDER)
            .expect_accepted(OLDER);
    }

    #[test]
    fn screening_on_empty_window_accepts_anything() {
        validator().expect_screened(NEWEST);
    }

    #[test]
    fn accepts_the_associated_key_id() {
        let mut validator = ReplayAttackProtection::new(KID, TOLERANCE);

        assert!(screen_and_record(&mut validator, KID, NEWEST).is_ok());
    }

    #[test]
    fn rejects_another_key_id() {
        let validator = ReplayAttackProtection::new(KID, TOLERANCE);

        assert_eq!(
            screen(&validator, OTHER_KID, NEWEST),
            Err(KeyIdMismatch {
                key_id: OTHER_KID,
                expected: KID
            })
        );
    }

    #[test]
    fn another_key_id_does_not_record_the_counter() {
        let mut validator = ReplayAttackProtection::new(KID, TOLERANCE);

        let _ = screen(&validator, OTHER_KID, NEWEST);

        // A foreign sender must not be able to consume counters of the associated one.
        assert!(screen_and_record(&mut validator, KID, NEWEST).is_ok());
    }

    #[test]
    fn accept_newer_headers() {
        validator().expect_accepted(OLDER).expect_accepted(NEWEST);
    }

    #[test]
    fn accept_older_headers_in_tolerance() {
        validator().expect_accepted(NEWEST).expect_accepted(OLDER);
    }

    #[test]
    fn reject_too_old_headers() {
        validator().expect_accepted(NEWEST).expect_too_old(TOO_OLD);
    }

    #[test]
    fn accepts_oldest_in_window_but_rejects_one_beyond() {
        validator()
            .expect_accepted(NEWEST)
            .expect_accepted(WINDOW_OLDEST)
            .expect_too_old(TOO_OLD);
    }

    #[test]
    fn rejects_header_with_duplicate_frame_counts() {
        validator()
            .expect_accepted(NEWEST)
            .expect_duplicated(NEWEST);
    }

    #[test]
    fn rejects_header_with_duplicate_frame_counts_within_tolerance() {
        validator()
            .expect_accepted(NEWEST)
            .expect_accepted(OLDER)
            .expect_duplicated(OLDER);
    }

    #[test]
    fn rejects_header_with_duplicate_frame_counts_with_upper_wraparound() {
        validator()
            .expect_accepted(header::Counter::MAX)
            .expect_accepted(0)
            .expect_duplicated(0);
    }

    #[test]
    fn rejects_header_with_duplicate_frame_counts_with_lower_wraparound() {
        validator()
            .expect_accepted(0)
            .expect_accepted(header::Counter::MAX)
            .expect_duplicated(header::Counter::MAX);
    }

    #[test]
    fn detects_duplicate_after_window_advanced() {
        validator()
            .expect_accepted(NEWEST)
            .expect_accepted(OLDER)
            .expect_accepted(NEWER_KEEPS_OLDER)
            .expect_duplicated(OLDER);
    }

    #[test]
    fn dropped_counter_is_too_old_not_duplicate() {
        validator()
            .expect_accepted(NEWEST)
            .expect_accepted(OLDER)
            .expect_accepted(NEWER_DROPS_OLDER)
            .expect_too_old(OLDER);
    }

    #[test]
    fn jump_beyond_window_clears_all_marks() {
        let mut validator = validator();
        validator.expect_accepted(NEWEST);
        for counter in WINDOW_OLDEST..NEWEST {
            validator.expect_accepted(counter);
        }

        validator.expect_accepted(FULL_WINDOW_JUMP);

        // Every counter in the fresh window is new; a leftover mark would surface
        // here as a false duplicate.
        for counter in (NEWEST + 1)..FULL_WINDOW_JUMP {
            validator.expect_accepted(counter);
        }
    }

    #[test]
    fn handle_overflowing_counters() {
        let start = header::Counter::MAX - 3;
        let mut validator = validator();
        validator.expect_accepted(start);

        for step in 1..10 {
            // wrapping_add dodges the debug overflow panic as we cross u64::MAX
            validator.expect_accepted(start.wrapping_add(step));
        }
    }
}
