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
/// A simple counter that increases by one for each call to `next()` up to a fixed limit, where it
/// wraps around. Per Default the limit is `u64::MAX`.
pub struct MonotonicCounter {
    current_counter: u64,
    max_counter: u64,
}

impl MonotonicCounter {
    /// Creates a new counter which will wrap around after `max_counter` was reached.
    pub fn new(max_counter: u64) -> Self {
        Self {
            current_counter: 0,
            max_counter,
        }
    }

    /// Creates a new counter with a start value which will wrap around after `max_counter` was
    /// reached.
    pub fn with_start_value(start_value: u64, max_counter: u64) -> Self {
        Self {
            current_counter: start_value,
            max_counter,
        }
    }

    /// Returns the current counter value.
    pub fn current(&self) -> Counter {
        self.current_counter
    }
}

impl FrameCounter for MonotonicCounter {
    fn next(&mut self) -> Counter {
        let counter = self.current_counter;
        self.current_counter = self.current_counter.wrapping_add(1);

        if self.current_counter > self.max_counter {
            self.current_counter = 0;
        }

        counter
    }
}

impl Default for MonotonicCounter {
    fn default() -> Self {
        Self {
            current_counter: 0,
            max_counter: u64::MAX,
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
            assert_eq!(counter.next(), i);
        }
    }
    #[test]
    fn wraps_after_u64_max_was_reached() {
        let mut counter = MonotonicCounter::new(u64::MAX);

        counter.current_counter = u64::MAX - 1;

        assert_eq!(counter.next(), u64::MAX - 1);
        assert_eq!(counter.next(), u64::MAX);
        assert_eq!(counter.next(), 0);
    }

    #[test]
    fn wraps_after_max_counter_was_reached() {
        let max_counter = 1;
        let mut counter = MonotonicCounter::new(max_counter);

        assert_eq!(counter.next(), 0);
        assert_eq!(counter.next(), 1);
        assert_eq!(counter.next(), 0);
    }
}
