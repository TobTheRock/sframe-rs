pub const U64_LEN: usize = std::mem::size_of::<u64>();

pub fn min_len_in_bytes(value: u64) -> u8 {
    if value == 0 {
        return 1; // at least 1 byte is needed to represent 0000_0000
    }

    let leading_zeros = value
        .to_be_bytes()
        .iter()
        .take_while(|&&value| value == 0)
        .count();

    (U64_LEN - leading_zeros) as u8 // never panics as u64 has only 8 bytes
}

#[cfg(test)]
mod test {
    use super::min_len_in_bytes;

    #[test]
    fn nof_non_zero_bytes() {
        assert_eq!(1u8, min_len_in_bytes(0));
        assert_eq!(1u8, min_len_in_bytes(7));
        assert_eq!(2u8, min_len_in_bytes(256));
        assert_eq!(8u8, min_len_in_bytes(u64::MAX));
    }
}
