#[cfg(test)]
use std::fmt::Write;

use crate::error::{Result, SframeError};

#[cfg(test)]
pub fn bin2string(bin: &[u8]) -> String {
    bin.iter().fold(String::new(), |mut output, x| {
        let _ = write!(output, "{x:08b} ");
        output
    })
}

pub fn get_n_lsb_bits(value: u64, n: u8) -> u64 {
    let bitmask = (1 << n) - 1;
    value & bitmask
}

/// Passes the value through if it fits into `n_bits`, else reports it as
/// [`SframeError::OutOfRange`]
pub fn fit_into<I>(name: &'static str, value: u64, n_bits: I) -> Result<u64>
where
    I: Into<u32>,
{
    let max = match n_bits.into() {
        0 => 0,
        n if n >= u64::BITS => u64::MAX,
        n => u64::MAX >> (u64::BITS - n),
    };

    if value > max {
        return Err(SframeError::OutOfRange { name, value, max });
    }

    Ok(value)
}

#[cfg(test)]
pub mod test {
    use super::{bin2string, fit_into};
    use crate::error::SframeError;
    use pretty_assertions::assert_eq;

    #[allow(clippy::missing_panics_doc)]
    pub fn assert_bytes_eq(l: &[u8], r: &[u8]) {
        assert_eq!(bin2string(l), bin2string(r));
    }

    #[test]
    fn passes_a_value_which_fits() {
        assert_eq!(fit_into("value", 0xFF, 8u8).unwrap(), 0xFF);
        // the whole range is available, a u64 fits into 64 bits or more
        assert_eq!(fit_into("value", u64::MAX, 64u8).unwrap(), u64::MAX);
        assert_eq!(fit_into("value", u64::MAX, 65u32).unwrap(), u64::MAX);
        // without any bit only 0 fits
        assert_eq!(fit_into("value", 0, 0u8).unwrap(), 0);
    }

    #[test]
    fn rejects_a_value_which_does_not_fit() {
        assert!(fit_into("value", 0x100, 8u8).is_err());
        assert!(fit_into("value", 1, 0u8).is_err());
    }

    #[test]
    fn reports_the_largest_value_which_fits() {
        let error = fit_into("value", 0x100, 8u8).unwrap_err();

        assert!(matches!(
            error,
            SframeError::OutOfRange {
                name: "value",
                value: 0x100,
                max: 0xFF
            }
        ));
    }
}
