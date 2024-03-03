#[cfg(test)]
use std::fmt::Write;

#[cfg(test)]
pub(crate) fn bin2string(bin: &[u8]) -> String {
    bin.iter().fold(String::new(), |mut output, x| {
        let _ = write!(output, "{x:08b} ");
        output
    })
}

pub(crate) fn limit_bit_len(name: &str, value: u8, limit: u8) -> u8 {
    if value > limit {
        log::warn!("Bit length for {name} of {value} is too long, limiting it to {limit} bits");
        return limit;
    }

    value
}

pub(crate) fn get_n_lsb_bits(value: u64, n: u8) -> u64 {
    let bitmask = (1 << n) - 1;
    value & bitmask
}

#[cfg(test)]
pub mod test {
    use super::bin2string;
    use pretty_assertions::assert_eq;

    #[allow(clippy::missing_panics_doc)]
    pub fn assert_bytes_eq(l: &[u8], r: &[u8]) {
        assert_eq!(bin2string(l), bin2string(r));
    }
}
