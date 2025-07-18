mod config_byte;
mod header_field;
mod util;

use super::error::{Result, SframeError};
use config_byte::ConfigByte;
use header_field::{HeaderField, VariableLengthField};

use std::fmt::Write;

/// type of the key id (KID) field used in the [`SframeHeader`]
pub type KeyId = u64;
/// type of the frame counter (CTR) field used in the [`SframeHeader`]
pub type Counter = u64;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
/// Modeled after [RFC 9605 4.3](https://www.rfc-editor.org/rfc/rfc9605.html#name-sframe-header).
/// The `SFrame` header specifies a Key ID (KID) and a counter (CTR) from which encryption parameters are derived.
///
/// Both are encoded as compact usigned integers in big-endian order. If the value of one of these fields is in the range 0-7,
/// then the value is carried in the corresponding bits of the config byte (K or C) and the corresponding flag (X or Y) is set to zero.
///
/// The `SFrame` header has the following format:
/// ```txt
///     Config Byte
///          |
///   .-----' '-----.
///  |               |
///   0 1 2 3 4 5 6 7
///  +-+-+-+-+-+-+-+-+------------+------------+
///  |X|  K  |Y|  C  |   KID...   |   CTR...   |
///  +-+-+-+-+-+-+-+-+------------+------------+
///
/// X: Extended Key ID Flag
/// K: Key ID Value (KID) or Length (KLEN)
/// Y: Extended Counter Flag
/// C: Counter Value (CTR) or Length (CLEN)
pub struct SframeHeader {
    key_id: HeaderField,
    counter: HeaderField,
}

impl SframeHeader {
    const LEN_OFFSET: u8 = 1; // a length of 1 is encoded as 0, etc.
    const STATIC_HEADER_LENGTH: usize = 1;

    /// creates a new [`SframeHeader`] with respective key id and frame count fields
    pub fn new(key_id: KeyId, counter: Counter) -> Self {
        Self {
            key_id: key_id.into(),
            counter: counter.into(),
        }
    }

    /// tries to deserialize an [`SframeHeader`] from a byte buffer
    /// Fails with an [`SframeError::InvalidBuffer`] if the size of the buffer is too small
    pub fn deserialize<T: AsRef<[u8]>>(buffer: T) -> Result<SframeHeader> {
        let buffer = buffer.as_ref();
        let buffer_len = buffer.len();
        let buffer_it = &mut buffer.iter();

        let config_byte = buffer_it
            .next()
            .ok_or(SframeError::InvalidBuffer(buffer_len))?;
        let config_byte = ConfigByte::from(config_byte);
        if buffer_len < config_byte.header_len() {
            return Err(SframeError::InvalidBuffer(buffer_len));
        }

        let key_id = if config_byte.extended_key_flag() {
            let key_len = (config_byte.key_or_klen() + Self::LEN_OFFSET) as usize;
            VariableLengthField::from_sized_iter(buffer_it.take(key_len)).into()
        } else {
            HeaderField::FixedLen(config_byte.key_or_klen())
        };

        let counter = if config_byte.extended_ctr_flag() {
            let ctr_len = (config_byte.ctr_or_clen() + Self::LEN_OFFSET) as usize;
            VariableLengthField::from_sized_iter(buffer_it.take(ctr_len)).into()
        } else {
            HeaderField::FixedLen(config_byte.ctr_or_clen())
        };

        Ok(Self { key_id, counter })
    }

    /// tries to serialize an [`SframeHeader`] into a byte buffer
    /// Fails with an [`SframeError::InvalidBuffer`] if the size of the buffer is too small
    pub fn serialize<T: AsMut<[u8]>>(&self, mut buffer: T) -> Result<()> {
        let buffer = buffer.as_mut();
        let buffer_len = buffer.len();

        if buffer_len < self.len() {
            return Err(SframeError::InvalidBuffer(buffer_len));
        }

        let buffer_it = &mut buffer.iter_mut();

        let config_byte = buffer_it
            .next()
            .ok_or(SframeError::InvalidBuffer(buffer_len))?;
        let mut config_byte = ConfigByte::from(config_byte);

        match self.key_id {
            HeaderField::FixedLen(key) => {
                config_byte.set_extended_key_flag(false);
                config_byte.set_key_or_klen(key);
            }
            HeaderField::VariableLen(field) => {
                let len = field.len();
                field.write_to_iter(buffer_it.take(len as usize));

                config_byte.set_extended_key_flag(true);
                config_byte.set_key_or_klen(len - Self::LEN_OFFSET);
            }
        }

        match self.counter {
            HeaderField::FixedLen(ctr) => {
                config_byte.set_extended_ctr_flag(false);
                config_byte.set_ctr_or_clen(ctr);
            }
            HeaderField::VariableLen(field) => {
                let len = field.len();
                field.write_to_iter(buffer_it.take(len as usize));

                config_byte.set_extended_ctr_flag(true);
                config_byte.set_ctr_or_clen(len - Self::LEN_OFFSET);
            }
        }

        Ok(())
    }

    /// returns the key Id header field
    pub fn key_id(&self) -> KeyId {
        self.key_id.into()
    }

    /// returns the frame count header field
    pub fn counter(&self) -> Counter {
        self.counter.into()
    }

    #[allow(clippy::len_without_is_empty)]
    /// returns the length of the header in bytes
    pub fn len(&self) -> usize {
        let mut len = Self::STATIC_HEADER_LENGTH;

        if let HeaderField::VariableLen(field) = self.key_id {
            len += field.len() as usize;
        }

        if let HeaderField::VariableLen(field) = self.counter {
            len += field.len() as usize;
        }

        len
    }
}

impl From<&SframeHeader> for Vec<u8> {
    fn from(header: &SframeHeader) -> Self {
        let mut buffer = vec![0u8; header.len()];
        // we guarantee that the buffer is large enough, so it is safe to unwrap
        header.serialize(buffer.as_mut_slice()).unwrap();
        buffer
    }
}

impl std::fmt::Display for SframeHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let error = std::fmt::Error {};

        let mut first_last_line = "+-+-+-+-+-+-+-+-+".to_string();

        let kid_field_label = match self.key_id {
            HeaderField::FixedLen(_) => "KID",
            HeaderField::VariableLen(_) => "KLEN",
        };
        let ctr_field_label = match self.counter {
            HeaderField::FixedLen(_) => "CTR",
            HeaderField::VariableLen(_) => "CLEN",
        };
        let mut second_line = format!("|X|{kid_field_label:^5}|Y|{ctr_field_label:^5}|");

        let mut serialized = Vec::from(self).into_iter().map(|x| format!("{x:08b} "));
        let first_byte = serialized.next().ok_or(error)?;
        let mut third_line = format!(
            "|{}|{:^5}|{}|{:^5}|",
            first_byte.get(0..1).ok_or(error)?,
            first_byte.get(1..4).ok_or(error)?,
            first_byte.get(4..5).ok_or(error)?,
            first_byte.get(5..8).ok_or(error)?,
        );

        match self.key_id {
            HeaderField::FixedLen(_) => {}
            HeaderField::VariableLen(field) => {
                let length = field.len() as usize;
                let variable_key: String = serialized.by_ref().take(length).collect();

                write!(first_last_line, "{:-^1$}+", "", variable_key.len() + 1)?;
                write!(second_line, "{:^1$}|", "KID", variable_key.len() + 1)?;
                write!(third_line, " {variable_key:^}|")?;
            }
        };

        match self.counter {
            HeaderField::FixedLen(_) => {}
            HeaderField::VariableLen(field) => {
                let length = field.len() as usize;
                let variable_ctr: String = serialized.take(length).collect();

                write!(first_last_line, "{:-^1$}+", "", variable_ctr.len() + 1)?;
                write!(second_line, "{:^1$}|", "CTR", variable_ctr.len() + 1)?;
                write!(third_line, " {variable_ctr:^}|")?;
            }
        };

        writeln!(f)?;
        writeln!(f, "{first_last_line}")?;
        writeln!(f, "{second_line}")?;
        writeln!(f, "{third_line}")?;
        write!(f, "{first_last_line}")
    }
}

#[cfg(test)]
mod test {
    use super::SframeHeader;
    use crate::util::test::assert_bytes_eq;
    use pretty_assertions::assert_eq;

    #[test]
    fn serialize_test_vectors() {
        crate::test_vectors::get_header_test_vectors()
            .iter()
            .for_each(|test_vector| {
                let header = SframeHeader::new(test_vector.key_id, test_vector.counter);
                let serialized = Vec::from(&header);
                assert_bytes_eq(&serialized, &test_vector.encoded);
            });
    }

    #[test]
    fn fail_to_serialize_when_buffer_is_empty() {
        let buffer = [];
        let result = SframeHeader::deserialize(buffer);
        assert!(result.is_err());
    }

    #[test]
    fn fail_to_serialize_when_buffer_is_too_small() {
        let buffer = [0b0000_1111]; // variable counter which is not present
        let result = SframeHeader::deserialize(buffer);
        assert!(result.is_err());

        let buffer = [0b1111_0000]; // variable key which is not present
        let result = SframeHeader::deserialize(buffer);
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_test_vectors() {
        crate::test_vectors::get_header_test_vectors()
            .iter()
            .for_each(|test_vector| {
                let header = SframeHeader::deserialize(&test_vector.encoded).unwrap();
                assert_eq!(header.len(), test_vector.encoded.len());
                assert_eq!(header.key_id(), test_vector.key_id);
                assert_eq!(header.counter(), test_vector.counter);
            });
    }

    #[test]
    fn fail_to_deserialize_when_buffer_is_empty() {
        let buffer = [];
        let result = SframeHeader::deserialize(buffer);
        assert!(result.is_err());
    }

    #[test]
    fn fail_to_deserialize_when_buffer_is_too_small() {
        let buffer = [0b0000_1111]; // variable counter which is not present
        let result = SframeHeader::deserialize(buffer);
        assert!(result.is_err());

        let buffer = [0b1111_0000]; // variable key which is not present
        let result = SframeHeader::deserialize(buffer);
        assert!(result.is_err());
    }
}
