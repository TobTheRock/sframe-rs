use crate::header::Counter;

/// Trait to provide the next counter value (CTR) used in the header and for encryption.
/// # Warning
/// It is crutial that a unique combination of (base key, KID, CTR) is used for each encryption
/// operation to prevent reusing the  same key and nonce of the underlying AEAD algorithm.
/// ,see [RFC 9605 9.1](https://www.rfc-editor.org/rfc/rfc9605.html#name-header-value-uniqueness)
/// ** This is not enforced by this library.**
pub trait FrameCounter {
    /// Returns the next counter value. Must be unique for each encryption operation (with the same
    /// base key & KID).
    fn next(&mut self) -> Counter;
}

#[derive(Copy, Clone, Debug)]
/// A simple counter that increases by one for each call to `next()` up to a fixed limit. It never
/// wraps around, reusing a counter value would break the uniqueness required by
/// [`FrameCounter`] - instead it is exhausted after the limit was reached, see
/// [`MonotonicCounter::is_exhausted`]. Per Default the limit is `u64::MAX`.
pub struct MonotonicCounter {
    current_counter: u64,
    max_counter: u64,
    exhausted: bool,
}

impl MonotonicCounter {
    /// Creates a new counter which is exhausted after `max_counter` was returned.
    pub fn new(max_counter: u64) -> Self {
        Self::with_start_value(0, max_counter)
    }

    /// Creates a new counter with a start value which is exhausted after `max_counter` was
    /// returned.
    pub fn with_start_value(start_value: u64, max_counter: u64) -> Self {
        Self {
            current_counter: start_value,
            max_counter,
            exhausted: false,
        }
    }

    /// Returns the current counter value.
    pub fn current(&self) -> Counter {
        self.current_counter
    }

    /// Returns `true` if all counter values were used up, i.e. the next call to
    /// [`FrameCounter::next`] will panic.
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }
}

impl FrameCounter for MonotonicCounter {
    /// # Panics
    /// If the counter is exhausted, see [`MonotonicCounter::is_exhausted`].
    fn next(&mut self) -> Counter {
        assert!(
            !self.exhausted,
            "MonotonicCounter is exhausted, its maximum value {} was already used",
            self.max_counter
        );

        let counter = self.current_counter;
        if counter >= self.max_counter {
            self.exhausted = true;
        } else {
            self.current_counter += 1;
        }

        counter
    }
}

impl Default for MonotonicCounter {
    fn default() -> Self {
        Self::new(u64::MAX)
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
            assert_eq!(counter.next(), i);
        }
    }
    #[test]
    fn is_exhausted_after_max_counter_was_returned() {
        let mut counter = MonotonicCounter::new(1);

        assert_eq!(counter.next(), 0);
        assert!(!counter.is_exhausted());

        assert_eq!(counter.next(), 1);
        assert!(counter.is_exhausted());
    }

    #[test]
    #[should_panic(expected = "exhausted")]
    fn panics_when_exhausted() {
        let mut counter = MonotonicCounter::new(1);

        counter.next();
        counter.next();
        counter.next();
    }

    #[test]
    #[should_panic(expected = "exhausted")]
    fn panics_when_u64_max_was_reached() {
        let mut counter = MonotonicCounter::with_start_value(u64::MAX - 1, u64::MAX);

        assert_eq!(counter.next(), u64::MAX - 1);
        assert_eq!(counter.next(), u64::MAX);
        assert!(counter.is_exhausted());

        counter.next();
    }
}
