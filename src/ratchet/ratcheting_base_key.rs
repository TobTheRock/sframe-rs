use std::mem::replace;

use crate::{
    crypto::{cipher_suite::CipherSuite, key_derivation::Ratcheting},
    error::Result,
    CipherSuiteVariant,
};

use super::ratcheting_key_id::RatchetingKeyId;

// TODO docs!
pub struct RatchetingBaseKey {
    cipher_suite: CipherSuite,
    current_material: Vec<u8>,
    key_id: RatchetingKeyId,
}

impl RatchetingBaseKey {
    pub fn ratchet_forward<K, M>(
        key_id: K,
        key_material: M,
        cipher_suite_variant: CipherSuiteVariant,
    ) -> Result<RatchetingBaseKey>
    where
        K: Into<RatchetingKeyId>,
        M: AsRef<[u8]>,
    {
        let mut base_key = Self {
            cipher_suite: cipher_suite_variant.into(),
            current_material: key_material.as_ref().into(),
            key_id: key_id.into(),
        };

        base_key.ratchet()?;

        Ok(base_key)
    }

    pub fn next_base_key(&mut self) -> Result<(RatchetingKeyId, Vec<u8>)> {
        let key_id = self.key_id;
        let key_material = self.ratchet()?;

        Ok((key_id, key_material))
    }

    pub fn key_id(&self) -> RatchetingKeyId {
        self.key_id
    }

    fn ratchet(&mut self) -> Result<Vec<u8>> {
        self.key_id.inc_ratchet_step();

        let new_material = self.current_material.ratchet(&self.cipher_suite)?;
        Ok(replace(&mut self.current_material, new_material))
    }
}

#[cfg(test)]
mod test {
    use crate::ratchet::ratcheting_key_id::RatchetingKeyId;

    use super::RatchetingBaseKey;

    #[test]
    fn should_ratchet_forward() {
        const N_RATCHET_BITS: u8 = 8;
        let expected_key_id = RatchetingKeyId::new(42u8, N_RATCHET_BITS);
        let secret = b"SuperSecret";
        let mut base_key = RatchetingBaseKey::ratchet_forward(
            expected_key_id,
            secret,
            crate::CipherSuiteVariant::AesGcm128Sha256,
        )
        .unwrap();

        // first call returns the key id and key material of the first ratcheting step
        let (first_key_id, first_material) = base_key.next_base_key().unwrap();

        assert_eq!(expected_key_id.generation(), first_key_id.generation());
        assert_eq!(first_key_id.ratchet_step(), 1);
        assert_ne!(secret, first_material.as_slice());

        let (second_key_id, second_material) = base_key.next_base_key().unwrap();
        // second call returns the first ratcheting step
        assert_eq!(second_key_id.ratchet_step(), 2);
        assert_ne!(secret, second_material.as_slice());
    }
}
