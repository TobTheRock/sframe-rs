use crate::{
    error::{Result, SframeError},
    header,
};

/// The No. frames a replay validator accepts out of order, i.e. how far behind the newest
/// frame a counter may lag before it is rejected as too old.
///
/// Pick it to match the re-ordering and loss the transport produces: too small drops frames a
/// lossy network delivers late, too large keeps a wider window an attacker may replay into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tolerance(usize);

impl Tolerance {
    /// the smallest usable tolerance, a window holding the newest frame alone
    pub const MIN: usize = 1;

    /// A counter is treated as newer than the window if it lies in the forward half of the
    /// counter range. A window spanning more than that half would overlap it, making a counter
    /// both contained in the window and newer than it.
    pub const MAX: u64 = header::Counter::MAX / 2;

    /// Creates a [`Tolerance`] of the given No. frames.
    ///
    /// # Panics
    /// If it is outside [`Tolerance::MIN`]..=[`Tolerance::MAX`], use [`Tolerance::try_new`] to
    /// handle this as an error instead.
    pub fn new(tolerance: usize) -> Self {
        Self::try_new(tolerance).unwrap()
    }

    /// Tries to create a [`Tolerance`] of the given No. frames.
    ///
    /// Fails with [`SframeError::OutOfRange`] if it is outside
    /// [`Tolerance::MIN`]..=[`Tolerance::MAX`].
    pub fn try_new(tolerance: usize) -> Result<Self> {
        let value = tolerance as u64;

        if value < Self::MIN as u64 || value > Self::MAX {
            return Err(SframeError::OutOfRange {
                name: "tolerance",
                value,
                min: Self::MIN as u64,
                max: Self::MAX,
            });
        }

        Ok(Self(tolerance))
    }
}

impl From<Tolerance> for usize {
    fn from(tolerance: Tolerance) -> Self {
        tolerance.0
    }
}

#[cfg(test)]
mod test {
    use super::Tolerance;
    use crate::error::SframeError;

    #[test]
    fn accepts_a_tolerance_in_range() {
        assert_eq!(usize::from(Tolerance::new(128)), 128);
        assert_eq!(usize::from(Tolerance::new(Tolerance::MIN)), Tolerance::MIN);
        assert_eq!(
            usize::from(Tolerance::new(Tolerance::MAX as usize)),
            Tolerance::MAX as usize
        );
    }

    #[test]
    fn rejects_a_tolerance_of_zero() {
        let result = Tolerance::try_new(0);

        assert!(matches!(
            result,
            Err(SframeError::OutOfRange {
                value: 0,
                min: 1,
                ..
            })
        ));
    }

    #[test]
    fn rejects_a_tolerance_beyond_half_the_counter_range() {
        let too_large = Tolerance::MAX + 1;

        let result = Tolerance::try_new(too_large as usize);

        assert!(matches!(
            result,
            Err(SframeError::OutOfRange { value, max, .. })
                if value == too_large && max == Tolerance::MAX
        ));
    }

    #[test]
    #[should_panic(expected = "OutOfRange")]
    fn panics_on_zero() {
        Tolerance::new(0);
    }
}
