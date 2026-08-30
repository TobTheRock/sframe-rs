use crate::header::Counter;
use std::convert::Infallible;

/// Trait to provide the next counter value (CTR) used in the header and for encryption.
/// # Warning
/// It is crutial that a unique combination of (base key, KID, CTR) is used for each encryption
/// operation to prevent reusing the  same key and nonce of the underlying AEAD algorithm.
/// ,see [RFC 9605 9.1](https://www.rfc-editor.org/rfc/rfc9605.html#name-header-value-uniqueness)
/// ** This is not enforced by this library.**
///
/// Thus a counter must never restart to hand out a value again. Once it cannot provide a new one,
/// e.g. because it is exhausted, you have to rekey - use a new base key or KID - to keep
/// encrypting.
pub trait FrameCounter {
    /// Why a frame counter could not be created
    type Error: std::error::Error + Send + Sync + 'static;
    /// Returns the next counter value. Must be unique for each encryption operation (with the same
    /// base key & KID).
    fn try_next(&mut self) -> Result<Counter, Self::Error>;
}

#[derive(Copy, Clone, Debug)]
/// A simple counter that increases by one for each call to [`FrameCounter::try_next`] up to a
/// fixed limit. It never wraps around, reusing a counter value would break the uniqueness required
/// by [`FrameCounter`] - instead it is exhausted after the limit was reached, see
/// [`MonotonicCounter::is_exhausted`]. Per Default the limit is [`Counter::MAX`].
pub struct MonotonicCounter {
    current_counter: Counter,
    max_counter: Counter,
    exhausted: bool,
}

impl MonotonicCounter {
    /// Creates a new counter which is exhausted after `max_counter` was returned.
    pub fn new(max_counter: Counter) -> Self {
        Self::with_start_value(0, max_counter)
    }

    /// Creates a new counter with a start value which is exhausted after `max_counter` was
    /// returned.
    pub fn with_start_value(start_value: Counter, max_counter: Counter) -> Self {
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
    /// [`FrameCounter::try_next`] will fail.
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("MonotonicCounter is exhausted, its maximum value {max} was already used")]
/// All counter values of a [`MonotonicCounter`] were used up, see
/// [`MonotonicCounter::is_exhausted`]
pub struct CounterExhausted {
    max: Counter,
}

impl CounterExhausted {
    /// The maximum counter value, which was already used
    pub fn max(&self) -> Counter {
        self.max
    }
}

impl FrameCounter for MonotonicCounter {
    type Error = CounterExhausted;

    fn try_next(&mut self) -> Result<Counter, Self::Error> {
        if self.exhausted {
            return Err(CounterExhausted {
                max: self.max_counter,
            });
        }

        let counter = self.current_counter;
        if counter >= self.max_counter {
            self.exhausted = true;
        } else {
            self.current_counter += 1;
        }

        Ok(counter)
    }
}

impl Default for MonotonicCounter {
    fn default() -> Self {
        Self::new(Counter::MAX)
    }
}

/// A [`MonotonicCounter`] which panics when it is exhausted, instead of returning an error, i.e.
/// its [`FrameCounter::Error`] is [`Infallible`]. Use it where a counter error cannot be handled
/// anyways - with a large limit, e.g. the default [`Counter::MAX`], exhausting it is unlikely.
///
/// # Panics
/// [`FrameCounter::try_next`] panics after the limit was reached, see
/// [`PanickingMonotonicCounter::is_exhausted`].
#[derive(Copy, Clone, Debug, Default)]
pub struct PanickingMonotonicCounter(MonotonicCounter);
impl PanickingMonotonicCounter {
    /// Creates a new counter which is exhausted after `max_counter` was returned.
    pub fn new(max_counter: Counter) -> Self {
        Self::with_start_value(0, max_counter)
    }

    /// Creates a new counter with a start value which is exhausted after `max_counter` was
    /// returned.
    pub fn with_start_value(start_value: Counter, max_counter: Counter) -> Self {
        Self(MonotonicCounter::with_start_value(start_value, max_counter))
    }

    /// Returns the current counter value.
    pub fn current(&self) -> Counter {
        self.0.current()
    }

    /// Returns `true` if all counter values were used up, i.e. the next call to
    /// [`FrameCounter::try_next`] will panic.
    pub fn is_exhausted(&self) -> bool {
        self.0.is_exhausted()
    }
}

impl FrameCounter for PanickingMonotonicCounter {
    type Error = Infallible;

    /// # Panics
    /// If the counter is exhausted, see [`PanickingMonotonicCounter::is_exhausted`].
    fn try_next(&mut self) -> Result<Counter, Self::Error> {
        let cnt = self.0.try_next().expect("Counter was exhausted");
        Ok(cnt)
    }
}

#[cfg(test)]
mod test {
    use crate::{frame::FrameCounter, header::Counter};

    use super::MonotonicCounter;
    use pretty_assertions::assert_eq;

    #[test]
    fn create_increasing_counters() {
        let mut counter = MonotonicCounter::default();

        for i in 0..10 {
            assert_eq!(counter.try_next().unwrap(), i);
        }
    }
    #[test]
    fn is_exhausted_after_max_counter_was_returned() {
        let mut counter = MonotonicCounter::new(1);

        assert_eq!(counter.try_next().unwrap(), 0);
        assert!(!counter.is_exhausted());

        assert_eq!(counter.try_next().unwrap(), 1);
        assert!(counter.is_exhausted());
    }

    #[test]
    fn returns_err_when_exhausted() {
        let mut counter = MonotonicCounter::new(1);

        counter.try_next().unwrap();
        counter.try_next().unwrap();
        assert!(counter.is_exhausted());
        assert!(counter.try_next().is_err());
    }

    #[test]
    fn returns_err_when_u64_max_was_reached() {
        let mut counter = MonotonicCounter::with_start_value(Counter::MAX - 1, Counter::MAX);

        assert_eq!(counter.try_next().unwrap(), Counter::MAX - 1);
        assert_eq!(counter.try_next().unwrap(), Counter::MAX);
        assert!(counter.is_exhausted());
        assert!(counter.try_next().is_err());
    }
}
