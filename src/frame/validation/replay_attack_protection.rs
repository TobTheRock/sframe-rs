use crate::{
    error::{Result, SframeError},
    frame::{FrameValidation, validation::sliding_window::SlidingWindow},
    header::{self, SframeHeader},
};
use std::cell::RefCell;

/// This implementation allows to detect replay attacks by omitting frames with
/// to old frame counters, see [RFC 9605 9.3](https://www.rfc-editor.org/rfc/rfc9605.html#name-anti-replay).
/// The window of allowed frame counts is given with a certain tolerance.
pub struct ReplayAttackProtection {
    window: RefCell<Window>,
}

impl ReplayAttackProtection {
    /// creates a [`ReplayAttackProtection`] with a given tolerance for the frame count
    ///
    /// # Panics
    /// Panics if `tolerance` is `0` or exceeds the platform's `usize` range.
    // TODO(v2): Tolerance should be usize
    pub fn with_tolerance(tolerance: u64) -> Self {
        assert!(tolerance > 0, "Tolerance must be greater than 0");
        let size: usize = tolerance
            .try_into()
            .expect("Tolerance exceeds OS capabilities");
        ReplayAttackProtection {
            window: RefCell::new(Window::Empty(Empty {
                window: SlidingWindow::new(size),
                size: size as u64,
            })),
        }
    }
}

impl FrameValidation for ReplayAttackProtection {
    fn validate(&self, header: &SframeHeader) -> Result<()> {
        let counter = header.counter();
        let mut window = self.window.borrow_mut();

        match &mut *window {
            Window::Active(active) => active.check(counter),
            Window::Empty(empty) => {
                // First frame: swap the pre-allocated `Empty` out (the placeholder
                // holds an empty, non-allocating window) and consume it to anchor.
                let placeholder = Empty {
                    window: SlidingWindow::new(0),
                    size: 0,
                };
                let mut active = std::mem::replace(empty, placeholder).anchor(counter);
                let result = active.check(counter);
                *window = Window::Active(active);
                result
            }
        }
    }
}

enum Window {
    Empty(Empty),
    Active(Active),
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
    fn check(&mut self, counter: header::Counter) -> Result<()> {
        if self.is_newer(counter) {
            self.advance_to(counter);
        }

        let err = |reason| {
            Err(SframeError::FrameValidationFailed(format!(
                "Replay check failed, frame counter {counter} {reason}"
            )))
        };
        match self.window_index(counter) {
            None => err(REJECT_TOO_OLD),
            Some(idx) if self.window.is_set(idx) => err(REJECT_DUPLICATED),
            Some(idx) => {
                self.window.set(idx);
                Ok(())
            }
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

const REJECT_TOO_OLD: &str = "is too old";
const REJECT_DUPLICATED: &str = "is duplicated";

#[cfg(test)]
mod test {
    use crate::header;

    use super::*;
    use pretty_assertions::assert_eq;

    const KID: u64 = 23456789;
    const TOLERANCE: u64 = 128;

    // A reference window `[WINDOW_OLDEST, NEWEST]`, spanning TOLERANCE counters.
    const NEWEST: u64 = 2480;
    const WINDOW_OLDEST: u64 = NEWEST - (TOLERANCE - 1);
    const TOO_OLD: u64 = NEWEST - TOLERANCE; // one counter past the oldest edge
    const OLDER: u64 = NEWEST - 80; // an arbitrary counter well inside the window

    // Newer frames that advance the window, named by their effect on OLDER.
    const NEWER_KEEPS_OLDER: u64 = NEWEST + 20;
    const NEWER_DROPS_OLDER: u64 = NEWEST + 60;
    const FULL_WINDOW_JUMP: u64 = NEWEST + TOLERANCE; // shift >= size, wipes all marks

    fn validator() -> Fixture {
        Fixture(ReplayAttackProtection::with_tolerance(TOLERANCE))
    }

    fn header(counter: header::Counter) -> SframeHeader {
        SframeHeader::new(KID, counter)
    }

    struct Fixture(ReplayAttackProtection);

    impl Fixture {
        fn expect_accepted(&self, counter: header::Counter) -> &Self {
            assert_eq!(
                self.0.validate(&header(counter)),
                Ok(()),
                "counter {counter} should be accepted"
            );
            self
        }

        fn expect_rejected(&self, counter: header::Counter, reason: &str) -> &Self {
            match self.0.validate(&header(counter)) {
                Err(SframeError::FrameValidationFailed(msg)) => assert!(
                    msg.contains(reason),
                    "counter {counter}: expected reason {reason:?}, got: {msg}"
                ),
                other => panic!("counter {counter}: expected rejection {reason:?}, got: {other:?}"),
            }
            self
        }
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
        validator()
            .expect_accepted(NEWEST)
            .expect_rejected(TOO_OLD, REJECT_TOO_OLD);
    }

    #[test]
    fn accepts_oldest_in_window_but_rejects_one_beyond() {
        validator()
            .expect_accepted(NEWEST)
            .expect_accepted(WINDOW_OLDEST)
            .expect_rejected(TOO_OLD, REJECT_TOO_OLD);
    }

    #[test]
    fn rejects_header_with_duplicate_frame_counts() {
        validator()
            .expect_accepted(NEWEST)
            .expect_rejected(NEWEST, REJECT_DUPLICATED);
    }

    #[test]
    fn rejects_header_with_duplicate_frame_counts_within_tolerance() {
        validator()
            .expect_accepted(NEWEST)
            .expect_accepted(OLDER)
            .expect_rejected(OLDER, REJECT_DUPLICATED);
    }

    #[test]
    fn rejects_header_with_duplicate_frame_counts_with_upper_wraparound() {
        validator()
            .expect_accepted(header::Counter::MAX)
            .expect_accepted(0)
            .expect_rejected(0, REJECT_DUPLICATED);
    }

    #[test]
    fn rejects_header_with_duplicate_frame_counts_with_lower_wraparound() {
        validator()
            .expect_accepted(0)
            .expect_accepted(header::Counter::MAX)
            .expect_rejected(header::Counter::MAX, REJECT_DUPLICATED);
    }

    #[test]
    fn detects_duplicate_after_window_advanced() {
        validator()
            .expect_accepted(NEWEST)
            .expect_accepted(OLDER)
            .expect_accepted(NEWER_KEEPS_OLDER)
            .expect_rejected(OLDER, REJECT_DUPLICATED);
    }

    #[test]
    fn dropped_counter_is_too_old_not_duplicate() {
        validator()
            .expect_accepted(NEWEST)
            .expect_accepted(OLDER)
            .expect_accepted(NEWER_DROPS_OLDER)
            .expect_rejected(OLDER, REJECT_TOO_OLD);
    }

    #[test]
    fn jump_beyond_window_clears_all_marks() {
        let validator = validator();
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
        let validator = validator();
        validator.expect_accepted(start);

        for step in 1..10 {
            // wrapping_add dodges the debug overflow panic as we cross u64::MAX
            validator.expect_accepted(start.wrapping_add(step));
        }
    }
}
