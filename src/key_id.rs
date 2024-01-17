use std::hash::Hash;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyId {
    Standard(u64),
    Ratcheting(RatchetingKeyId),
}

impl KeyId {
    pub fn new<K>(key_id: K) -> Self
    where
        K: Into<u64>,
    {
        KeyId::Standard(key_id.into())
    }

    pub fn with_ratcheting<K>(generation: K, n_ratchet_bits: u8) -> Self
    where
        K: Into<u64>,
    {
        // TODO if n_ratchet_bits = 0
        RatchetingKeyId::new(generation, n_ratchet_bits).into()
    }

    pub fn as_u64(&self) -> u64 {
        match self {
            KeyId::Standard(value) => *value,
            KeyId::Ratcheting(ratcheting) => ratcheting.as_u64(),
        }
    }
}

impl Hash for KeyId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            KeyId::Standard(value) => value.hash(state),
            KeyId::Ratcheting(ratcheting) => ratcheting.hash(state),
        };
    }
}

impl<T> From<T> for KeyId
where
    T: Into<u64>,
{
    fn from(value: T) -> Self {
        KeyId::new(value)
    }
}

impl From<RatchetingKeyId> for KeyId {
    fn from(ratcheting: RatchetingKeyId) -> Self {
        KeyId::Ratcheting(ratcheting)
    }
}

impl Hash for RatchetingKeyId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.generation().hash(state);
    }
}

#[derive(Clone, Copy, Debug, Eq)]
pub struct RatchetingKeyId {
    value: u64,
    n_ratchet_bits: u8,
}

impl RatchetingKeyId {
    pub fn new<K>(generation: K, n_ratchet_bits: u8) -> Self
    where
        K: Into<u64>,
    {
        const U64_BITS: u8 = u64::BITS as u8;

        let generation = generation.into();
        let mut n_ratchet_bits = n_ratchet_bits;

        if n_ratchet_bits >= U64_BITS {
            log::warn!("n_ratchet_bits of {n_ratchet_bits} cannot be eq or larger than {U64_BITS} bits, limiting it to {}", U64_BITS -1);
            n_ratchet_bits = U64_BITS - 1;
        }

        let value = generation << n_ratchet_bits;

        let (max_generation, overflow) = 1u64.overflowing_shl(u64::BITS - n_ratchet_bits as u32);
        if generation > max_generation && !overflow {
            log::warn!(
                "generation {generation} cannot be bigger than {max_generation}  with {n_ratchet_bits} ratcheting bits, limiting it to {value}",
            );
        }

        // this means we start with ratchet step 0

        Self {
            value,
            n_ratchet_bits,
        }
    }

    pub fn as_u64(&self) -> u64 {
        self.value
    }

    pub fn generation(&self) -> u64 {
        self.value >> self.n_ratchet_bits
    }

    pub fn ratchet_step(&self) -> u64 {
        self.value % (1 << self.n_ratchet_bits)
    }

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

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use pretty_assertions::assert_eq;

    use crate::key_id::RatchetingKeyId;

    use super::KeyId;

    #[test]
    fn returns_correct_standard_key_id() {
        let expected_key_id = 42;
        let key_id = KeyId::from(expected_key_id);

        assert_eq!(expected_key_id, key_id.as_u64());
    }

    #[test]
    fn returns_correct_ratcheting_params() {
        let expected_generation: u64 = 0xFF;
        let n_ratchet_bits = 8;
        let key_id = KeyId::with_ratcheting(expected_generation, n_ratchet_bits);

        let key_id = if let KeyId::Ratcheting(ratcheting) = key_id {
            ratcheting
        } else {
            panic!("expected KeyId::Ratcheting");
        };

        assert_eq!(expected_generation, key_id.generation());
        assert_eq!(0, key_id.ratchet_step());

        let expected_on_wire: u64 = 0x0000_FF00;
        assert_eq!(expected_on_wire, key_id.as_u64());
    }

    #[test]
    fn works_with_zero_ratcheting_bits() {
        let expected_generation = 42;
        let key_id = RatchetingKeyId::new(expected_generation, 0);

        assert_eq!(expected_generation, key_id.generation());
        assert_eq!(0, key_id.ratchet_step());
        assert_eq!(expected_generation, key_id.as_u64());
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
