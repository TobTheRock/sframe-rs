use crate::{
    crypto::{
        cipher_suite::{CipherSuite, CipherSuiteParams},
        common::key_derivation::expand_subsecret,
        key_derivation::{
            get_hkdf_key_expand_label, get_hkdf_ratchet_expand_label, get_hkdf_salt_expand_label,
            KeyDerivation, Ratcheting,
        },
        secret::Secret,
    },
    error::{Result, SframeError},
    header::KeyId,
};
use hkdf::SimpleHkdf;
use sha2::{Digest, Sha256, Sha512};

impl KeyDerivation for Secret {
    fn expand_from<M, K>(
        cipher_suite: &CipherSuiteParams,
        key_material: M,
        key_id: K,
    ) -> Result<Secret>
    where
        M: AsRef<[u8]>,
        K: Into<KeyId>,
    {
        let key_id = key_id.into();

        let (key, salt, auth) = match cipher_suite.cipher_suite {
            CipherSuite::AesCtr128HmacSha256_80
            | CipherSuite::AesCtr128HmacSha256_64
            | CipherSuite::AesCtr128HmacSha256_32 => {
                let (base_key, salt) =
                    expand::<Sha256>(cipher_suite, key_material.as_ref(), key_id)?;
                let (key, auth) = expand_subsecret(cipher_suite, &base_key);
                (key, salt, Some(auth))
            }
            CipherSuite::AesGcm128Sha256 => {
                let (key, salt) = expand::<Sha256>(cipher_suite, key_material.as_ref(), key_id)?;
                (key, salt, None)
            }
            CipherSuite::AesGcm256Sha512 => {
                let (key, salt) = expand::<Sha512>(cipher_suite, key_material.as_ref(), key_id)?;
                (key, salt, None)
            }
        };

        Ok(Secret { key, salt, auth })
    }
}

fn expand<D>(
    cipher_suite: &CipherSuiteParams,
    key_material: &[u8],
    key_id: KeyId,
) -> Result<(Vec<u8>, Vec<u8>)>
where
    D: Digest + cipher::BlockSizeUser + Clone,
{
    let algorithm = SimpleHkdf::<D>::new(None, key_material);

    let key = expand_key(
        cipher_suite.key_len,
        &algorithm,
        &get_hkdf_key_expand_label(key_id, cipher_suite.cipher_suite),
    )?;

    let salt = expand_key(
        cipher_suite.nonce_len,
        &algorithm,
        &get_hkdf_salt_expand_label(key_id, cipher_suite.cipher_suite),
    )?;

    Ok((key, salt))
}

impl Ratcheting for Vec<u8> {
    fn ratchet(&self, cipher_suite: &CipherSuiteParams) -> Result<Vec<u8>>
    where
        Self: AsRef<[u8]>,
    {
        match cipher_suite.cipher_suite {
            CipherSuite::AesCtr128HmacSha256_80
            | CipherSuite::AesCtr128HmacSha256_64
            | CipherSuite::AesCtr128HmacSha256_32
            | CipherSuite::AesGcm128Sha256 => {
                let algorithm = SimpleHkdf::<Sha256>::new(Some(b""), self);
                expand_key(
                    cipher_suite.key_len,
                    &algorithm,
                    get_hkdf_ratchet_expand_label(),
                )
            }
            CipherSuite::AesGcm256Sha512 => {
                let algorithm = SimpleHkdf::<Sha512>::new(Some(b""), self);
                expand_key(
                    cipher_suite.key_len,
                    &algorithm,
                    get_hkdf_ratchet_expand_label(),
                )
            }
        }
    }
}

impl From<hkdf::InvalidLength> for SframeError {
    fn from(error: hkdf::InvalidLength) -> Self {
        log::error!("Cannot derive key: {error}");
        SframeError::KeyDerivationFailure
    }
}

fn expand_key<D>(len: usize, algorithm: &SimpleHkdf<D>, label: &[u8]) -> Result<Vec<u8>>
where
    D: Digest + cipher::BlockSizeUser + Clone,
{
    let mut key = vec![0_u8; len];
    algorithm.expand(label, &mut key)?;
    Ok(key)
}
