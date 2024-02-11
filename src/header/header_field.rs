use super::util::{min_len_in_bytes, U64_LEN};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HeaderField {
    FixedLen(u8),
    VariableLen(VariableLengthField),
}

impl From<u64> for HeaderField {
    fn from(value: u64) -> Self {
        const FIXED_SIZED_MAX: u64 = 8;
        if value < FIXED_SIZED_MAX {
            Self::FixedLen(value as u8)
        } else {
            Self::VariableLen(value.into())
        }
    }
}

impl From<HeaderField> for u64 {
    fn from(value: HeaderField) -> Self {
        match value {
            HeaderField::FixedLen(value) => value as u64,
            HeaderField::VariableLen(value) => value.into(),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VariableLengthField {
    length: u8,
    value: u64,
}

impl VariableLengthField {
    pub fn len(&self) -> u8 {
        self.length
    }

    pub fn write_to_iter<'a>(&self, iter: impl ExactSizeIterator<Item = &'a mut u8>) {
        iter.zip(self)
            .for_each(|(buf_byte, field_byte)| *buf_byte = field_byte);
    }

    pub fn from_sized_iter<'a>(iter: impl ExactSizeIterator<Item = &'a u8>) -> Self {
        // enforce that the iter fits an u64
        let iter = iter.take(U64_LEN);
        let length = iter.len();

        let zero_padding = std::iter::repeat(&0u8).take(U64_LEN - length);
        let be_bytes = zero_padding
            .chain(iter)
            .copied()
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(); // we assert the size, so this cannot fail

        let value = u64::from_be_bytes(be_bytes);
        let length = length as u8; // we assert that length <= 8 and it thus fits u8
        Self { length, value }
    }
}

impl From<VariableLengthField> for HeaderField {
    fn from(value: VariableLengthField) -> Self {
        HeaderField::VariableLen(value)
    }
}

impl From<VariableLengthField> for u64 {
    fn from(value: VariableLengthField) -> Self {
        value.value
    }
}

impl From<u64> for VariableLengthField {
    fn from(value: u64) -> Self {
        Self {
            length: min_len_in_bytes(value),
            value,
        }
    }
}

impl IntoIterator for &VariableLengthField {
    type Item = u8;
    type IntoIter = std::iter::Skip<std::array::IntoIter<u8, 8>>;

    fn into_iter(self) -> Self::IntoIter {
        self.value
            .to_be_bytes()
            .into_iter()
            .skip(U64_LEN - self.length as usize)
    }
}
