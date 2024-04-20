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
use hkdf::HmacImpl;
use hkdf::{hmac::SimpleHmac, Hkdf};
use sha2::{Digest, Sha256, Sha512};

impl KeyDerivation for Secret {
    fn expand_from<M, K>(cipher_suite: &CipherSuite, key_material: M, key_id: K) -> Result<Secret>
    where
        M: AsRef<[u8]>,
        K: Into<KeyId>,
    {
        let key_id = key_id.into();

        match cipher_suite.variant {
            CipherSuiteVariant::AesCtr128HmacSha256_80 => todo!(),
            CipherSuiteVariant::AesCtr128HmacSha256_64 => todo!(),
            CipherSuiteVariant::AesCtr128HmacSha256_32 => todo!(),
            CipherSuiteVariant::AesGcm128Sha256 => {
                expand::<Sha256>(cipher_suite, key_material.as_ref(), key_id)
            }
            CipherSuiteVariant::AesGcm256Sha512 => {
                expand::<Sha512>(cipher_suite, key_material.as_ref(), key_id)
            }
        }
    }
}

fn expand<D>(cipher_suite: &CipherSuite, key_material: &[u8], key_id: KeyId) -> Result<Secret>
where
    D: Digest + sha2::digest::core_api::CoreProxy + aes_gcm::aes::cipher::BlockSizeUser + Clone,
{
    let algorithm = Hkdf::<D, SimpleHmac<D>>::new(None, key_material);

    let mut key = vec![0_u8; cipher_suite.key_len];
    algorithm.expand(
        &get_hkdf_key_expand_label(key_id, cipher_suite.variant),
        &mut key,
    );

    let mut salt = vec![0_u8; cipher_suite.nonce_len];
    algorithm.expand(
        &get_hkdf_salt_expand_label(key_id, cipher_suite.variant),
        &mut salt,
    );

    Ok(Secret {
        key,
        salt,
        auth: None,
    })
}

impl Ratcheting for Vec<u8> {
    fn ratchet(&self, cipher_suite: &CipherSuite) -> Result<Vec<u8>>
    where
        Self: AsRef<[u8]>,
    {
        todo!();
        let pseudo_random_key = Hkdf::<Sha256>::new(Some(b""), self);

        let mut key = vec![0_u8; cipher_suite.key_len];
        // pseudo_random_key.expand(&get_hkdf_ratchet_expand_label(), &mut key)?;

        Ok(key)
    }
}
