use std::hash::Hash;

use crate::header::KeyId;

/// Special key id format as of [sframe draft 06 5.1](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-06#section-5.1)
/// It has the following format:
/// ```txt
///       64-R bits         R bits
///    <---------------> <------------>
///   +-----------------+--------------+
///   | Key Generation  | Ratchet Step |
///   +-----------------+--------------+
/// ```
/// where:
/// - Key Generation: increments each time the sender distributes a new key
/// - Ratchet Step: increments each time the sender distributes a new key
/// - R: No. bits used for the Ratchet Step, defines a re-ordering,no more than 2^R ratchet steps can be active at a given time.  
///
/// For each Key Generation a new [`RatchetingKeyId`] needs to be created, as the Key Generation is determined by the application.
/// If the  Ratchet Steps reaches its maximum it starts anew with 0.
#[derive(Clone, Copy, Debug, Eq)]
pub struct RatchetingKeyId {
    value: u64,
    n_ratchet_bits: u8,
}

impl RatchetingKeyId {
    /// creates a new [`RatchetingKeyId`] with
    /// - generation: the key generation
    /// - `n_ratchet_bits`: the No. bits used for ratcheting (R)
    /// where the initial Ratchet Step is 0
    pub fn new<G>(generation: G, n_ratchet_bits: u8) -> Self
    where
        G: Into<u64>,
    {
        const U64_BITS: u8 = u64::BITS as u8;

        let generation = generation.into();
        let mut n_ratchet_bits = n_ratchet_bits;

        if n_ratchet_bits >= U64_BITS {
            log::warn!("n_ratchet_bits of {n_ratchet_bits} cannot be eq or larger than {U64_BITS} bits, limiting it to {}", U64_BITS -1);
            n_ratchet_bits = U64_BITS - 1;
        }

        // this means we start with ratchet step 0
        let value = generation << n_ratchet_bits;

        let (max_generation, overflow) = 1u64.overflowing_shl(u64::BITS - n_ratchet_bits as u32);
        if generation > max_generation && !overflow {
            log::warn!(
                "generation {generation} cannot be bigger than {max_generation}  with {n_ratchet_bits} ratcheting bits, limiting it to {value}",
            );
        }

        Self {
            value,
            n_ratchet_bits,
        }
    }

    /// parses a [`RatchetingKeyId`] from
    /// - `key_id`: a [`KeyId`], e.g. given by an `SFrame` header.
    /// - `n_ratchet_bits`: the No. bits used for ratcheting (R)
    pub fn from_key_id<K>(key_id: K, n_ratchet_bits: u8) -> Self
    where
        K: Into<KeyId>,
    {
        Self {
            value: key_id.into(),
            n_ratchet_bits,
        }
    }

    /// returns the associated Key Generation
    pub fn generation(&self) -> u64 {
        self.value >> self.n_ratchet_bits
    }

    /// returns the associated Ratchet Step
    pub fn ratchet_step(&self) -> u64 {
        self.value % (1 << self.n_ratchet_bits)
    }

    /// increments the internal Ratchet Step by 1.
    /// If it reaches its maximum (2^R), it is set to 0
    pub fn inc_ratchet_step(&mut self) {
        let ratchet_bitmask = u64::MAX >> (u64::BITS - self.n_ratchet_bits as u32);
        // if all ratchet bits are set we have to wrap
        if self.value & ratchet_bitmask == ratchet_bitmask {
            // clear n_ratchet_bits
            self.value ^= ratchet_bitmask;
            return;
        }

        self.value = self.value.wrapping_add(1);
    }
}

impl PartialEq for RatchetingKeyId {
    fn eq(&self, other: &Self) -> bool {
        self.generation() == other.generation()
    }
}
impl PartialEq<KeyId> for RatchetingKeyId {
    fn eq(&self, other: &u64) -> bool {
        self.value == *other
    }
}

impl PartialEq<RatchetingKeyId> for KeyId {
    fn eq(&self, other: &RatchetingKeyId) -> bool {
        *self == other.value
    }
}

impl From<RatchetingKeyId> for KeyId {
    fn from(ratcheting: RatchetingKeyId) -> Self {
        ratcheting.value
    }
}

impl Hash for RatchetingKeyId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.generation().hash(state);
    }
}

#[cfg(test)]
mod test {
    use crate::{header::KeyId, ratchet::ratcheting_key_id::RatchetingKeyId};
    use pretty_assertions::assert_eq;
    use std::collections::HashMap;

    #[test]
    fn returns_correct_ratcheting_params() {
        let expected_generation: u64 = 0xFF;
        let n_ratchet_bits = 8;
        let key_id = RatchetingKeyId::new(expected_generation, n_ratchet_bits);

        assert_eq!(expected_generation, key_id.generation());
        assert_eq!(0, key_id.ratchet_step());

        let expected_on_wire: KeyId = 0x0000_FF00;
        assert_eq!(expected_on_wire, KeyId::from(key_id));
    }

    #[test]
    fn works_with_zero_ratcheting_bits() {
        let expected_generation = 42;
        let key_id = RatchetingKeyId::new(expected_generation, 0);

        assert_eq!(expected_generation, key_id.generation());
        assert_eq!(0, key_id.ratchet_step());
        assert_eq!(expected_generation, key_id);
    }

    #[test]
    fn inc_ratchet_step() {
        let n_ratcheting_bits = 2;
        let n_ratcheting_steps: u64 = 1 << n_ratcheting_bits;
        let expected_generation: u64 = 42;
        let mut key_id = RatchetingKeyId::new(expected_generation, n_ratcheting_bits);

        for i in 0..n_ratcheting_steps {
            assert_eq!(i, key_id.ratchet_step());
            assert_eq!(expected_generation, key_id.generation());
            key_id.inc_ratchet_step();
        }
        // last inc should have wrapped around the ratchet step
        assert_eq!(0, key_id.ratchet_step());
        assert_eq!(expected_generation, key_id.generation());
    }

    #[test]
    fn limits_n_ratchet_bits_to_63() {
        let n_ratcheting_bits = 255;
        let mut key_id = RatchetingKeyId::new(u64::MAX, n_ratcheting_bits);

        assert_eq!(0, key_id.ratchet_step());
        // just one bit left for the generation
        assert_eq!(1, key_id.generation());

        key_id.inc_ratchet_step();
        assert_eq!(1, key_id.ratchet_step());
    }

    #[test]
    fn compares_only_generations() {
        let n_ratcheting_bits = 1;
        let mut key_id = RatchetingKeyId::new(42u64, n_ratcheting_bits);
        let key_id2 = RatchetingKeyId::new(42u64, n_ratcheting_bits);

        key_id.inc_ratchet_step();

        assert_eq!(key_id, key_id2);
    }

    #[test]
    fn works_with_hash_maps() {
        let mut map = HashMap::new();

        let generation: u32 = 42;
        let mut key_id = RatchetingKeyId::new(generation, 8);
        let value = "test_value";

        map.insert(key_id, value);

        key_id.inc_ratchet_step();

        // should still be the same generation
        assert!(map.contains_key(&key_id));
    }
}
