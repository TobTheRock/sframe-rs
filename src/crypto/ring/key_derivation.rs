use crate::{
    crypto::{
        cipher_suite::{CipherSuite, CipherSuiteVariant},
        key_derivation::{
            get_hkdf_key_expand_label, get_hkdf_ratchet_expand_label, get_hkdf_salt_expand_label,
            KeyDerivation, Ratcheting,
        },
        secret::Secret,
    },
    error::{Result, SframeError},
    header::KeyId,
};

impl KeyDerivation for Secret {
    fn expand_from<M, K>(cipher_suite: &CipherSuite, key_material: M, key_id: K) -> Result<Secret>
    where
        M: AsRef<[u8]>,
        K: Into<KeyId>,
    {
        let key_id = key_id.into();
        let algorithm = cipher_suite.variant.into();
        // No salt used for the extraction: https://www.rfc-editor.org/rfc/rfc9605.html#name-key-derivation
        let pseudo_random_key =
            ring::hkdf::Salt::new(algorithm, b"").extract(key_material.as_ref());

        let key = expand_key(
            &pseudo_random_key,
            &get_hkdf_key_expand_label(key_id, cipher_suite.variant),
            cipher_suite.key_len,
        )?;
        let salt = expand_key(
            &pseudo_random_key,
            &get_hkdf_salt_expand_label(key_id, cipher_suite.variant),
            cipher_suite.nonce_len,
        )?;

        Ok(Secret {
            key,
            salt,
            auth: None,
        })
    }
}

impl Ratcheting for Vec<u8> {
    fn ratchet(&self, cipher_suite: &CipherSuite) -> Result<Vec<u8>>
    where
        Self: AsRef<[u8]>,
    {
        let algorithm = cipher_suite.variant.into();
        let pseudo_random_key = ring::hkdf::Salt::new(algorithm, b"").extract(self);

        expand_key(
            &pseudo_random_key,
            get_hkdf_ratchet_expand_label(),
            cipher_suite.key_len,
        )
        .map_err(|_| SframeError::RatchetingFailure)
    }
}

struct OkmKeyLength(usize);

impl ring::hkdf::KeyType for OkmKeyLength {
    fn len(&self) -> usize {
        self.0
    }
}

impl From<CipherSuiteVariant> for ring::hkdf::Algorithm {
    fn from(variant: CipherSuiteVariant) -> Self {
        match variant {
            CipherSuiteVariant::AesGcm128Sha256 => ring::hkdf::HKDF_SHA256,
            CipherSuiteVariant::AesGcm256Sha512 => ring::hkdf::HKDF_SHA512,
        }
    }
}

fn expand_key(prk: &ring::hkdf::Prk, info: &[u8], key_len: usize) -> Result<Vec<u8>> {
    let mut key = vec![0_u8; key_len];

    prk.expand(&[info], OkmKeyLength(key_len))
        .and_then(|okm| okm.fill(key.as_mut_slice()))
        .map_err(|_| SframeError::KeyDerivationFailure)?;

    Ok(key)
}
