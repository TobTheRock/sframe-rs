use crate::{
    error::{Result, SframeError},
    header::KeyId,
    util::{fit_into, get_n_lsb_bits},
};

/// Represents the bit range for an MLS Key ID as of [RFC 9605 5.2](https://www.rfc-editor.org/rfc/rfc9605.html#name-mls)
/// The bit range specifies the number of bits allocated for the epoch (E) and member index (S) components of the MLS Key ID,
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MlsKeyIdBitRange {
    n_epoch_bits: u8,
    n_index_bits: u8,
}

impl MlsKeyIdBitRange {
    /// the maximum No. bits usable for the epoch (E) and the member index (S) together,
    /// so that at least one bit is left for the context id
    pub const MAX: u8 = u64::BITS as u8 - 1;

    /// Creates a new bit range from the given number of bits for the epoch (E) and the member index (S).
    ///
    /// # Panics
    /// If `E + S` is larger than [`MlsKeyIdBitRange::MAX`], use [`MlsKeyIdBitRange::try_new`] to
    /// handle this as an error instead.
    pub fn new(n_epoch_bits: u8, n_index_bits: u8) -> Self {
        Self::try_new(n_epoch_bits, n_index_bits).unwrap()
    }

    /// Tries to create a new bit range from the given number of bits for the epoch (E) and the member index (S).
    /// Fails with [`SframeError::OutOfRange`] if `E + S` is larger than
    /// [`MlsKeyIdBitRange::MAX`], i.e. if no bit is left for the context id.
    pub fn try_new(n_epoch_bits: u8, n_index_bits: u8) -> Result<Self> {
        if n_epoch_bits > Self::MAX {
            return Err(SframeError::OutOfRange {
                name: "n_epoch_bits",
                value: n_epoch_bits.into(),
                max: Self::MAX.into(),
            });
        }

        let max_index_bits = Self::MAX - n_epoch_bits;
        if n_index_bits > max_index_bits {
            return Err(SframeError::OutOfRange {
                name: "n_index_bits",
                value: n_index_bits.into(),
                max: max_index_bits.into(),
            });
        }

        Ok(Self {
            n_epoch_bits,
            n_index_bits,
        })
    }

    fn len(&self) -> u8 {
        self.n_epoch_bits + self.n_index_bits
    }
}

/// Special Key ID format as of [RFC 9605 5.2](https://www.rfc-editor.org/rfc/rfc9605.html#section-5.2)
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
    /// Tries to create a new MLS specific Key ID with the given context, epoch and member index,
    /// using the bit ranges configured for each of them.
    /// Of the epoch only the E least significant bits are encoded, as of the RFC.
    ///
    /// Fails with [`SframeError::OutOfRange`] if the context id or the member index do not fit
    /// into the bits configured for them.
    pub fn try_new<C, E, M>(
        context_id: C,
        epoch_number: E,
        member_index: M,
        bit_range: MlsKeyIdBitRange,
    ) -> Result<Self>
    where
        C: Into<u64>,
        E: Into<u64>,
        M: Into<u64>,
    {
        let context_id = fit_into(
            "context_id",
            context_id.into(),
            u64::BITS - u32::from(bit_range.len()),
        )?;
        let member_index = fit_into("member_index", member_index.into(), bit_range.n_index_bits)?;
        // as of the RFC only the least significant bits of the epoch are encoded
        let epoch_number = get_n_lsb_bits(epoch_number.into(), bit_range.n_epoch_bits);

        let value = (context_id << bit_range.len())
            | (member_index << bit_range.n_epoch_bits)
            | epoch_number;

        Ok(Self { value, bit_range })
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
        let mls_key_id =
            MlsKeyId::try_new(context_id, epoch_number, member_index, bit_range).unwrap();

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
    fn rejects_a_bit_range_leaving_no_context_id() {
        assert!(MlsKeyIdBitRange::try_new(100, 12).is_err());
        assert!(MlsKeyIdBitRange::try_new(10, 60).is_err());
        // one bit is left for the context id
        assert!(MlsKeyIdBitRange::try_new(10, MlsKeyIdBitRange::MAX - 10).is_ok());
    }

    #[test]
    fn rejects_values_exceeding_the_bit_range() {
        let bit_range = MlsKeyIdBitRange::new(58, 3u8); // 3 bit for context id
        let epoch_number: u64 = 1;

        let too_large: u64 = 0b1_000;
        assert!(MlsKeyId::try_new(too_large, epoch_number, 0u64, bit_range).is_err());
        assert!(MlsKeyId::try_new(0u64, epoch_number, too_large, bit_range).is_err());

        let largest: u64 = 0b111;
        assert!(MlsKeyId::try_new(largest, epoch_number, largest, bit_range).is_ok());
    }

    #[test]
    fn encodes_only_the_least_significant_bits_of_the_epoch() {
        let bit_range = MlsKeyIdBitRange::new(3u8, 4u8);

        let mls_key_id = MlsKeyId::try_new(0u64, 0b11_101u64, 0u64, bit_range).unwrap();

        assert_eq!(mls_key_id.epoch_lsb(), 0b101);
    }
}
