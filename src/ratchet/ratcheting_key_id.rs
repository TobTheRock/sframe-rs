use std::fmt::Display;

use crate::{
    error::{Result, SframeError},
    header::KeyId,
    util::{fit_into, get_n_lsb_bits},
};

/// The Key Generation of a [`RatchetingKeyId`], incremented by the application each time it
/// distributes a new key. All Ratchet Steps of a Key Generation share its key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Generation(u64);

impl From<u64> for Generation {
    fn from(generation: u64) -> Self {
        Self(generation)
    }
}

impl From<Generation> for u64 {
    fn from(generation: Generation) -> Self {
        generation.0
    }
}

impl Display for Generation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// One Ratchet Step of a [`RatchetingKeyId`], wrapping around to 0 after its maximum (`2^R - 1`)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RatchetStep(u64);

impl From<u64> for RatchetStep {
    fn from(step: u64) -> Self {
        Self(step)
    }
}

impl From<RatchetStep> for u64 {
    fn from(step: RatchetStep) -> Self {
        step.0
    }
}

impl Display for RatchetStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// The No. bits (R) of a [`KeyId`] used for the Ratchet Step, see [`RatchetingKeyId`].
///
/// At most [`RatchetBits::MAX`], so that at least one bit is left for the Key Generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RatchetBits(u8);

impl RatchetBits {
    /// the maximum No. bits usable for the Ratchet Step
    pub const MAX: u8 = u64::BITS as u8 - 1;

    /// Creates a [`RatchetBits`] from the given No. bits.
    ///
    /// # Panics
    /// If `n_bits` is larger than [`RatchetBits::MAX`], use [`RatchetBits::try_new`] to handle
    /// this as an error instead.
    pub fn new(n_bits: u8) -> Self {
        Self::try_new(n_bits).unwrap()
    }

    /// Tries to create a [`RatchetBits`] from the given No. bits.
    /// Fails with [`SframeError::OutOfRange`] if it is larger than [`RatchetBits::MAX`].
    pub fn try_new(n_bits: u8) -> Result<Self> {
        if n_bits > Self::MAX {
            return Err(SframeError::OutOfRange {
                name: "n_ratchet_bits",
                value: n_bits.into(),
                max: Self::MAX.into(),
            });
        }

        Ok(Self(n_bits))
    }

    /// the largest Ratchet Step which fits into R bits (`2^R - 1`)
    pub fn max_step(self) -> RatchetStep {
        self.wrap_step(u64::MAX)
    }

    /// wraps a Ratchet Step into the `2^R` steps which R bits can hold
    pub fn wrap_step(self, step: u64) -> RatchetStep {
        RatchetStep(get_n_lsb_bits(step, self.0))
    }

    /// The No. steps needed to get from one Ratchet Step to another, wrapping at `2^R`
    pub fn steps_between(self, from: RatchetStep, to: RatchetStep) -> u64 {
        self.wrap_step(to.0.wrapping_sub(from.0)).0
    }

    /// The No. steps which can be told apart from a step which was already passed (`2^(R-1)`).
    ///
    /// The Ratchet Step wraps at `2^R`, so a step diff is ambiguous: a diff of `d` means either
    /// `d` steps forward or `2^R - d` steps back. Only the lower half can be told apart from a
    /// step which was already passed, e.g. carried by a re-ordered frame.
    pub fn max_distinguishable_steps(self) -> u64 {
        (1u64 << self.0) >> 1
    }
}

impl From<RatchetBits> for u8 {
    fn from(bits: RatchetBits) -> Self {
        bits.0
    }
}

/// Special key id format as of [RFC 9605 5.1](https://www.rfc-editor.org/rfc/rfc9605.html#section-5.1)
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
/// The Ratchet Step wraps around to 0 after its maximum (2^R - 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RatchetingKeyId {
    value: u64,
    n_ratchet_bits: RatchetBits,
}

impl RatchetingKeyId {
    /// creates a new [`RatchetingKeyId`] with
    /// - generation: the key generation
    /// - `n_ratchet_bits`: the No. bits used for ratcheting (R)
    ///
    /// where the initial Ratchet Step is 0
    ///
    /// # Panics
    /// If the generation does not fit into the remaining `64 - R` bits, use
    /// [`RatchetingKeyId::try_new`] to handle this as an error instead.
    pub fn new<G>(generation: G, n_ratchet_bits: RatchetBits) -> Self
    where
        G: Into<u64>,
    {
        Self::try_new(generation, n_ratchet_bits).unwrap()
    }

    /// Tries to create a new [`RatchetingKeyId`], as [`RatchetingKeyId::new`].
    /// Fails with [`SframeError::OutOfRange`] if the generation does not fit into the
    /// remaining `64 - R` bits.
    pub fn try_new<G>(generation: G, n_ratchet_bits: RatchetBits) -> Result<Self>
    where
        G: Into<u64>,
    {
        let n_bits = u8::from(n_ratchet_bits);
        let generation = fit_into(
            "generation",
            generation.into(),
            u64::BITS - u32::from(n_bits),
        )?;

        Ok(Self {
            value: generation << n_bits,
            n_ratchet_bits,
        })
    }

    /// parses a [`RatchetingKeyId`] from
    /// - `key_id`: a [`KeyId`], e.g. given by an `SFrame` header.
    /// - `n_ratchet_bits`: the No. bits used for ratcheting (R)
    pub fn from_key_id<K>(key_id: K, n_ratchet_bits: RatchetBits) -> Self
    where
        K: Into<KeyId>,
    {
        Self {
            value: key_id.into(),
            n_ratchet_bits,
        }
    }

    /// returns the associated Key Generation
    pub fn generation(&self) -> Generation {
        Generation(self.value >> u8::from(self.n_ratchet_bits))
    }

    /// returns the associated Ratchet Step
    pub fn ratchet_step(&self) -> RatchetStep {
        self.n_ratchet_bits.wrap_step(self.value)
    }

    /// increments the internal Ratchet Step by 1,
    /// wrapping around to 0 after its maximum (2^R - 1)
    pub fn inc_ratchet_step(&mut self) {
        // without ratcheting bits the maximum is 0, so there is nothing to increment
        let max_step = self.n_ratchet_bits.max_step();

        if self.ratchet_step() == max_step {
            // clear the ratchet bits to wrap around
            self.value ^= u64::from(max_step);
            return;
        }

        self.value = self.value.wrapping_add(1);
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

#[cfg(test)]
mod test {
    use crate::{
        header::KeyId,
        ratchet::ratcheting_key_id::{Generation, RatchetBits, RatchetStep, RatchetingKeyId},
    };
    use pretty_assertions::assert_eq;

    fn generation(generation: u64) -> Generation {
        Generation::from(generation)
    }

    fn step(step: u64) -> RatchetStep {
        RatchetStep::from(step)
    }

    #[test]
    fn returns_correct_ratcheting_params() {
        let expected_generation: u64 = 0xFF;
        let key_id = RatchetingKeyId::new(expected_generation, RatchetBits::new(8));

        assert_eq!(generation(expected_generation), key_id.generation());
        assert_eq!(step(0), key_id.ratchet_step());

        let expected_on_wire: KeyId = 0x0000_FF00;
        assert_eq!(expected_on_wire, KeyId::from(key_id));
    }

    #[test]
    fn works_with_zero_ratcheting_bits() {
        let expected_generation = 42;
        let key_id = RatchetingKeyId::new(expected_generation, RatchetBits::new(0));

        assert_eq!(generation(expected_generation), key_id.generation());
        assert_eq!(step(0), key_id.ratchet_step());
        assert_eq!(expected_generation, key_id);
    }

    #[test]
    fn inc_ratchet_step() {
        let n_ratcheting_bits = RatchetBits::new(2);
        let n_ratcheting_steps: u64 = 1 << u8::from(n_ratcheting_bits);
        let expected_generation: u64 = 42;
        let mut key_id = RatchetingKeyId::new(expected_generation, n_ratcheting_bits);

        for i in 0..n_ratcheting_steps {
            assert_eq!(step(i), key_id.ratchet_step());
            assert_eq!(generation(expected_generation), key_id.generation());
            key_id.inc_ratchet_step();
        }
        // last inc should have wrapped around the ratchet step
        assert_eq!(step(0), key_id.ratchet_step());
        assert_eq!(generation(expected_generation), key_id.generation());
    }

    #[test]
    fn rejects_more_ratchet_bits_than_a_key_id_holds() {
        assert!(RatchetBits::try_new(RatchetBits::MAX).is_ok());
        assert!(RatchetBits::try_new(RatchetBits::MAX + 1).is_err());
        assert!(RatchetBits::try_new(255).is_err());
    }

    #[test]
    fn works_with_the_maximum_of_ratchet_bits() {
        let n_ratcheting_bits = RatchetBits::new(RatchetBits::MAX);
        let mut key_id = RatchetingKeyId::from_key_id(u64::MAX, n_ratcheting_bits);

        // just one bit left for the generation
        assert_eq!(generation(1), key_id.generation());
        assert_eq!(step(u64::MAX >> 1), key_id.ratchet_step());

        key_id.inc_ratchet_step();
        assert_eq!(step(0), key_id.ratchet_step());
    }

    #[test]
    fn keeps_the_largest_generation_which_fits() {
        let n_ratcheting_bits = RatchetBits::new(8);
        let largest = u64::MAX >> u8::from(n_ratcheting_bits);

        let key_id = RatchetingKeyId::new(largest, n_ratcheting_bits);

        assert_eq!(generation(largest), key_id.generation());
    }

    #[test]
    fn rejects_a_generation_which_does_not_fit() {
        let n_ratcheting_bits = RatchetBits::new(8);
        let one_too_big = (u64::MAX >> u8::from(n_ratcheting_bits)) + 1;

        let key_id = RatchetingKeyId::try_new(one_too_big, n_ratcheting_bits);

        assert!(key_id.is_err());
    }

    #[test]
    fn keeps_any_generation_without_ratcheting_bits() {
        let key_id = RatchetingKeyId::new(u64::MAX, RatchetBits::new(0));

        assert_eq!(generation(u64::MAX), key_id.generation());
    }

    #[test]
    fn does_not_ratchet_without_ratcheting_bits() {
        let expected_generation = 42;
        let mut key_id = RatchetingKeyId::new(expected_generation, RatchetBits::new(0));

        key_id.inc_ratchet_step();

        assert_eq!(step(0), key_id.ratchet_step());
        assert_eq!(generation(expected_generation), key_id.generation());
    }

    #[test]
    fn separates_the_generation_from_the_ratchet_step() {
        let n_ratcheting_bits = RatchetBits::new(1);
        let mut key_id = RatchetingKeyId::new(42u64, n_ratcheting_bits);
        let key_id2 = RatchetingKeyId::new(42u64, n_ratcheting_bits);

        key_id.inc_ratchet_step();

        // both are of the same Key Generation, but are different key ids
        assert_eq!(key_id.generation(), key_id2.generation());
        assert_ne!(key_id, key_id2);
    }

    #[test]
    fn counts_the_steps_between_two_ratchet_steps() {
        let n_ratcheting_bits = RatchetBits::new(2);

        assert_eq!(1, n_ratcheting_bits.steps_between(step(2), step(3)));
        // wraps at 2^R
        assert_eq!(3, n_ratcheting_bits.steps_between(step(3), step(2)));
        assert_eq!(0, n_ratcheting_bits.steps_between(step(1), step(1)));
    }
}
