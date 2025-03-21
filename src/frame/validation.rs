use crate::{
    error::{Result, SframeError},
    header::{Counter, SframeHeader},
};
use std::{cell::Cell, ops::Deref};

/// Allows to validate frames by their sframe header before the decryption
pub trait FrameValidation {
    /// checks if the new header is valid, returns an [`SframeError`] if not
    fn validate(&self, header: &SframeHeader) -> Result<()>;
}

/// Box to any implementation of the `FrameValidation` trait
pub type FrameValidationBox = Box<dyn FrameValidation>;

impl FrameValidation for FrameValidationBox {
    fn validate(&self, header: &SframeHeader) -> Result<()> {
        self.deref().validate(header)
    }
}

/// This implementation allows to detect replay attacks by omitting frames with
/// to old frame counters, see [RFC 9605 9.3](https://www.rfc-editor.org/rfc/rfc9605.html#name-anti-replay).
/// The window of allowed frame counts is given with a certain tolerance.
pub struct ReplayAttackProtection {
    tolerance: u64,
    last_counter: Cell<Counter>,
}

impl ReplayAttackProtection {
    /// creates a [`ReplayAttackProtection`] with a given tolerance for the frame count
    pub fn with_tolerance(tolerance: u64) -> Self {
        ReplayAttackProtection {
            tolerance,
            last_counter: Cell::new(0u64),
        }
    }
}

impl FrameValidation for ReplayAttackProtection {
    fn validate(&self, header: &SframeHeader) -> Result<()> {
        let last_counter = self.last_counter.get();
        let current_counter = header.counter();

        if current_counter > last_counter {
            // frame is fine and fresh
            self.last_counter.set(current_counter);
            Ok(())
        } else {
            // frame old
            let age = last_counter - current_counter;

            if age <= self.tolerance {
                self.last_counter.set(current_counter);
                Ok(())
            } else {
                // maybe there was an overflow
                let dist_to_overflow = u64::MAX - last_counter;
                let overflow_age = current_counter + dist_to_overflow;

                // no it's just too old
                if overflow_age <= self.tolerance {
                    self.last_counter.set(current_counter);
                    Ok(())
                } else {
                    Err(SframeError::FrameValidationFailed(
                        "Replay check failed, frame counter too old".to_string(),
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn accept_newer_headers() {
        let validator = ReplayAttackProtection::with_tolerance(128);
        let first_header = SframeHeader::new(23456789u64, 2400);
        let second_header = SframeHeader::new(23456789u64, 2480);

        assert_eq!(validator.validate(&first_header), Ok(()));
        assert_eq!(validator.validate(&second_header), Ok(()));
    }

    #[test]
    fn accept_older_headers_in_tolerance() {
        let validator = ReplayAttackProtection::with_tolerance(128);
        let first_header = SframeHeader::new(23456789u64, 2480);
        let late_header = SframeHeader::new(23456789u64, 2400);

        assert_eq!(validator.validate(&first_header), Ok(()));
        assert_eq!(validator.validate(&late_header), Ok(()));
    }

    #[test]
    fn reject_too_old_headers() {
        let validator = ReplayAttackProtection::with_tolerance(128);
        let first_header = SframeHeader::new(23456789u64, 2480);
        let too_late_header = SframeHeader::new(23456789u64, 1024);

        assert_eq!(validator.validate(&first_header), Ok(()));
        assert!(matches!(
            validator.validate(&too_late_header),
            Err(SframeError::FrameValidationFailed(_))
        ));
    }

    #[test]
    fn handle_overflowing_counters() {
        let validator = ReplayAttackProtection::with_tolerance(128);
        let start_count = u64::MAX - 3;
        let first_header = SframeHeader::new(23456789u64, start_count);

        assert_eq!(validator.validate(&first_header), Ok(()));

        for step in 0..10 {
            let late_count = start_count.wrapping_add(step); // using this instead of `+` to avoid overflow panic in debug
            let too_late_header = SframeHeader::new(23456789u64, late_count);
            assert_eq!(validator.validate(&too_late_header), Ok(()));
        }
    }
}
