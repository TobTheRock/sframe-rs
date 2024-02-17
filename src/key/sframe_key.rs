use crate::{
    crypto::{cipher_suite::CipherSuite, key_derivation::KeyDerivation, secret::Secret},
    error::Result,
    header::KeyId,
    CipherSuiteVariant,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SframeKey {
    secret: Secret,
    cipher_suite: CipherSuite,
    key_id: KeyId,
}

impl SframeKey {
    pub fn expand_from<K, M>(
        variant: CipherSuiteVariant,
        key_id: K,
        key_material: M,
    ) -> Result<Self>
    where
        K: Into<KeyId>,
        M: AsRef<[u8]>,
    {
        let key_id = key_id.into();
        let cipher_suite = variant.into();

        let secret = Secret::expand_from(&cipher_suite, key_material, key_id)?;

        Ok(Self {
            secret,
            cipher_suite,
            key_id,
        })
    }

    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }

    pub fn key_id(&self) -> u64 {
        self.key_id
    }

    pub fn cipher_suite_variant(&self) -> CipherSuiteVariant {
        self.cipher_suite.variant
    }

    pub(crate) fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    #[cfg(test)]
    pub(crate) fn from_test_vector(
        variant: CipherSuiteVariant,
        test_vec: &crate::test_vectors::SframeTest,
    ) -> Self {
        let cipher_suite: CipherSuite = variant.into();
        if cipher_suite.is_ctr_mode() {
            // the test vectors do not provide the auth key, so we have to expand here
            SframeKey::expand_from(variant, test_vec.key_id, &test_vec.key_material).unwrap()
        } else {
            let secret = Secret::from_test_vector(test_vec);
            SframeKey {
                secret,
                cipher_suite,
                key_id: test_vec.key_id,
            }
        }
    }
}
