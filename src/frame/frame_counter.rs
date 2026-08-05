use crate::header::Counter;

/// Trait to provide the next counter value (CTR) used in the header and for encryption.
/// # Warning
/// It is crutial that a unique combination of (base key, KID, CTR) is used for each encryption
/// operation to prevent reusing the  same key and nonce of the underlying AEAD algorithm.
/// ,see [RFC 9605 9.1](https://www.rfc-editor.org/rfc/rfc9605.html#name-header-value-uniqueness)
pub trait FrameCounter {
    /// Returns the next counter value, unique for each encryption operation (with the same
    /// base key & KID). Returns `None` once the counter space is exhausted, e.g. by an
    /// overflow, in which case the caller must not encrypt any further frame with the current
    /// (base key, KID) - see [`crate::error::SframeError::CounterExhausted`].
    fn next(&mut self) -> Option<Counter>;
}

#[derive(Copy, Clone, Debug)]
/// A simple counter that increases by one for each call to `next()` up to a fixed limit.
/// Per default the limit is `u64::MAX` and the counter is exhausted (returning `None`) once
/// that limit has been handed out, instead of silently wrapping back to `0` - reusing a counter
/// under the same (base key, KID) would break confidentiality of the AEAD scheme.
///
/// Wrapping around can be opted into explicitly via [`MonotonicCounter::allow_overrun`], e.g.
/// when the caller can independently guarantee that the (base key, KID) is rotated before the
/// counter space is exhausted.
pub struct MonotonicCounter {
    current_counter: u64,
    max_counter: u64,
    allow_overrun: bool,
    exhausted: bool,
}

impl MonotonicCounter {
    /// Creates a new counter which will be exhausted after `max_counter` was reached.
    pub fn new(max_counter: u64) -> Self {
        Self {
            current_counter: 0,
            max_counter,
            allow_overrun: false,
            exhausted: false,
        }
    }

    /// Creates a new counter with a start value which will be exhausted after `max_counter` was
    /// reached.
    pub fn with_start_value(start_value: u64, max_counter: u64) -> Self {
        Self {
            current_counter: start_value,
            max_counter,
            allow_overrun: false,
            exhausted: false,
        }
    }

    /// Configures whether the counter is allowed to wrap around to `0` after `max_counter` was
    /// reached, instead of being exhausted.
    /// # Warning
    /// Only enable this if the (base key, KID) is guaranteed to be rotated before the counter
    /// wraps, otherwise the same (base key, KID, CTR) combination will be reused, breaking
    /// confidentiality of the AEAD scheme, see [RFC 9605 9.1](https://www.rfc-editor.org/rfc/rfc9605.html#name-header-value-uniqueness).
    pub fn allow_overrun(mut self, allow_overrun: bool) -> Self {
        self.allow_overrun = allow_overrun;
        self
    }

    /// Returns the current counter value.
    pub fn current(&self) -> Counter {
        self.current_counter
    }

    /// Returns whether the counter is exhausted, i.e. further calls to `next()` will return
    /// `None`.
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Resets the counter to `0` and clears the exhausted state.
    /// # Warning
    /// This must only be done after switching to a new (base key, KID), otherwise a previously
    /// used counter value could be handed out again under the same (base key, KID).
    pub fn reset(&mut self) {
        self.reset_to(0);
    }

    /// Resets the counter to `start_value` and clears the exhausted state.
    /// # Warning
    /// This must only be done after switching to a new (base key, KID), otherwise a previously
    /// used counter value could be handed out again under the same (base key, KID).
    pub fn reset_to(&mut self, start_value: u64) {
        self.current_counter = start_value;
        self.exhausted = false;
    }
}

impl FrameCounter for MonotonicCounter {
    fn next(&mut self) -> Option<Counter> {
        if self.exhausted {
            return None;
        }

        let counter = self.current_counter;

        if counter == self.max_counter {
            if self.allow_overrun {
                self.current_counter = 0;
            } else {
                self.exhausted = true;
            }
        } else {
            self.current_counter += 1;
        }

        Some(counter)
    }
}

impl Default for MonotonicCounter {
    fn default() -> Self {
        Self {
            current_counter: 0,
            max_counter: u64::MAX,
            allow_overrun: false,
            exhausted: false,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::frame::FrameCounter;

    use super::MonotonicCounter;
    use pretty_assertions::assert_eq;

    #[test]
    fn create_increasing_counters() {
        let mut counter = MonotonicCounter::default();

        for i in 0..10 {
            assert_eq!(counter.next(), Some(i));
        }
    }

    #[test]
    fn exhausted_after_u64_max_was_reached() {
        let mut counter = MonotonicCounter::new(u64::MAX);

        counter.current_counter = u64::MAX - 1;

        assert_eq!(counter.next(), Some(u64::MAX - 1));
        assert_eq!(counter.next(), Some(u64::MAX));
        assert_eq!(counter.next(), None);
        assert!(counter.is_exhausted());
    }

    #[test]
    fn exhausted_after_max_counter_was_reached() {
        let max_counter = 1;
        let mut counter = MonotonicCounter::new(max_counter);

        assert_eq!(counter.next(), Some(0));
        assert_eq!(counter.next(), Some(1));
        assert_eq!(counter.next(), None);
        assert_eq!(counter.next(), None);
    }

    #[test]
    fn does_not_reuse_counter_after_exhaustion_without_overrun() {
        let max_counter = 0;
        let mut counter = MonotonicCounter::new(max_counter);

        assert_eq!(counter.next(), Some(0));
        for _ in 0..3 {
            assert_eq!(counter.next(), None);
        }
    }

    #[test]
    fn wraps_after_max_counter_was_reached_when_overrun_is_allowed() {
        let max_counter = 1;
        let mut counter = MonotonicCounter::new(max_counter).allow_overrun(true);

        assert_eq!(counter.next(), Some(0));
        assert_eq!(counter.next(), Some(1));
        assert_eq!(counter.next(), Some(0));
        assert_eq!(counter.next(), Some(1));
    }

    #[test]
    fn reset_clears_exhausted_state() {
        let mut counter = MonotonicCounter::new(0);

        assert_eq!(counter.next(), Some(0));
        assert_eq!(counter.next(), None);

        counter.reset();
        assert_eq!(counter.next(), Some(0));
        assert_eq!(counter.next(), None);
    }

    #[test]
    fn reset_to_starts_from_given_value() {
        let mut counter = MonotonicCounter::new(10);

        assert_eq!(counter.next(), Some(0));

        counter.reset_to(5);
        assert_eq!(counter.next(), Some(5));
        assert_eq!(counter.next(), Some(6));
    }
}
