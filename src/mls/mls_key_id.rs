use crate::{
    header::KeyId,
    util::{get_n_lsb_bits, limit_bit_len},
};

//

/// Represents the bit range for an MLS Key ID as of [sframe draft 06 5.2](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-06#name-mls)
/// The bit range specifies the number of bits allocated for the epoch (E) and member index (S) components of the MLS Key ID,
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlsKeyIdBitRange {
    n_epoch_bits: u8,
    n_index_bits: u8,
}

impl MlsKeyIdBitRange {
    /// Creates a new bit range from the given number of bits for the epoch (E) and the member index (S)
    /// It is ensured that
    /// - E < 63
    /// - S < 64 - E
    /// so that the number of bits used for encoding the MLS Key ID does not exceed the maximum allowed limit and that for each field at least 1 bit is available
    pub fn new<E, I>(n_epoch_bits: E, n_index_bits: I) -> Self
    where
        E: Into<u8>,
        I: Into<u8>,
    {
        let n_epoch_bits = limit_bit_len("n_epoch_bits", n_epoch_bits.into(), u64::BITS as u8 - 2);
        let n_index_bits = limit_bit_len(
            "n_index_bits",
            n_index_bits.into(),
            (u64::BITS as u8) - n_epoch_bits - 1,
        );

        Self {
            n_epoch_bits,
            n_index_bits,
        }
    }

    fn len(&self) -> u8 {
        self.n_epoch_bits + self.n_index_bits
    }
}

/// Special Key ID format as of [sframe draft 06 5.2](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-06#section-5.2)
/// to be used with [MLS](https://datatracker.ietf.org/doc/html/rfc9420).
/// It has the following format:
/// ```txt
///  64-S-E bits   S bits   E bit
/// <-----------> <------> <------>
/// +-------------+--------+-------+
/// | Context ID  | Index  | Epoch |
/// +-------------+--------+-------+
/// ```
/// where:
/// - Epoch: E least significant bits of the MLS epoch
/// - Index: MLS member index of the sender, the group size must be <= (1 << S)
/// - Context ID: context value chosen by the sender, a value of 0 will produce the shortest Key ID
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlsKeyId {
    value: u64,
    bit_range: MlsKeyIdBitRange,
}

impl MlsKeyId {
    /// Creates a new MLS specific Key ID with the given context, epoch and member index,
    /// using the bit ranges configured for each of them.
    pub fn new<C, E, M>(
        context_id: C,
        epoch_number: E,
        member_index: M,
        bit_range: MlsKeyIdBitRange,
    ) -> Self
    where
        C: Into<u64>,
        E: Into<u64>,
        M: Into<u64>,
    {
        let context_id = context_id.into();

        let epoch_number = get_n_lsb_bits(epoch_number.into(), bit_range.n_epoch_bits);
        let member_index = get_n_lsb_bits(member_index.into(), bit_range.n_index_bits);

        let value = (context_id << bit_range.len())
            | (member_index << bit_range.n_epoch_bits)
            | epoch_number;

        Self { value, bit_range }
    }

    /// Extracts an MLS specific Key ID from a general Key ID (e.g. from an [`crate::header::SframeHeader`]), assuming the given bit range
    pub fn from_key_id<K>(key_id: K, bit_range: MlsKeyIdBitRange) -> Self
    where
        K: Into<KeyId>,
    {
        let value = key_id.into();
        Self { value, bit_range }
    }

    /// Returns the context ID component of the MLS Key ID.
    pub fn context_id(&self) -> u64 {
        self.value >> self.bit_range.len()
    }

    /// Returns the member index component of the MLS Key ID.
    pub fn member_index(&self) -> u64 {
        get_n_lsb_bits(
            self.value >> self.bit_range.n_epoch_bits,
            self.bit_range.n_index_bits,
        )
    }

    /// Returns the least significant bits of the MLS epoch which are encoded in this MLS Key ID.
    pub fn epoch_lsb(&self) -> u64 {
        get_n_lsb_bits(self.value, self.bit_range.n_epoch_bits)
    }
}

impl From<MlsKeyId> for KeyId {
    fn from(mls_key_id: MlsKeyId) -> Self {
        mls_key_id.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::KeyId;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_mls_key_id_creation() {
        let context_id: u64 = 10;
        let epoch_number: u64 = 0b11_101;
        let epoch_number_lsb = 0b101;
        let member_index: u64 = 6;

        let bit_range = MlsKeyIdBitRange::new(3u8, 4u8);
        let mls_key_id = MlsKeyId::new(context_id, epoch_number, member_index, bit_range);

        assert_eq!(mls_key_id.context_id(), context_id);
        assert_eq!(mls_key_id.epoch_lsb(), epoch_number_lsb);
        assert_eq!(mls_key_id.member_index(), member_index);
    }

    #[test]
    fn test_mls_key_id_from_key_id() {
        #[allow(clippy::unusual_byte_groupings)]
        let key_id: KeyId = 0b11_010_1010;

        let epoch_bits: u8 = 4;
        let index_bits: u8 = 3;
        let bit_range = MlsKeyIdBitRange::new(epoch_bits, index_bits);

        let mls_key_id = MlsKeyId::from_key_id(key_id, bit_range);

        assert_eq!(mls_key_id.context_id(), 3);
        assert_eq!(mls_key_id.epoch_lsb(), 10);
        assert_eq!(mls_key_id.member_index(), 2);

        assert_eq!(key_id, KeyId::from(mls_key_id));
    }

    #[test]
    fn test_exceeded_mls_bit_range() {
        let bit_range = MlsKeyIdBitRange::new(100, 12);
        assert_eq!(bit_range.n_epoch_bits, u64::BITS as u8 - 2);
        assert_eq!(bit_range.n_index_bits, 1);

        let n_epoch_bits = 10;
        let bit_range = MlsKeyIdBitRange::new(n_epoch_bits, 60);
        assert_eq!(bit_range.n_epoch_bits, n_epoch_bits);
        assert_eq!(bit_range.n_index_bits, u64::BITS as u8 - n_epoch_bits - 1);
    }

    #[test]
    fn test_mls_key_id_creation_values_exceeding_bit_range() {
        let bit_range = MlsKeyIdBitRange::new(58, 3u8); // 3 bit for context id

        let context_id: u64 = 0b111_101;
        let epoch_number: u64 = 1;
        let member_index: u64 = 0b111_101;

        let mls_key_id = MlsKeyId::new(context_id, epoch_number, member_index, bit_range);

        assert_eq!(mls_key_id.context_id(), 5);
        assert_eq!(mls_key_id.member_index(), 5);
    }
}
