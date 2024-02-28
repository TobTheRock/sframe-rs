use crate::{
    crypto::{cipher_suite::CipherSuite, key_derivation::KeyDerivation, secret::Secret},
    error::Result,
    header::KeyId,
    CipherSuiteVariant,
};

/// Represents an sframe key as described in [sframe draft 06 4.4.1](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-06#section-4.4.1).
/// It is associated with a key ID and a cipher suite which is used for encryption/ decryption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SframeKey {
    secret: Secret,
    cipher_suite: CipherSuite,
    key_id: KeyId,
}

impl SframeKey {
    /// Tries to expands an Sframe key from the provided base key material using the given cipher suite variant (as of [sframe draft 06 4.4.2](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-06#section-4.4.2))
    /// It is then assigned the provided key ID and the cipher suite vrriant.
    /// If key expansion fails an error ([`SframeError::KeyDerivation`])
    pub fn derive_from<K, M>(
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

    /// Returns the associated key ID
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Returns the cipher suite of this key
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
            SframeKey::derive_from(variant, test_vec.key_id, &test_vec.key_material).unwrap()
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
