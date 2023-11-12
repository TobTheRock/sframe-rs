// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use crate::{
    crypto::{
        cipher_suite::{CipherSuite, CipherSuiteVariant},
        key_derivation::{
            get_hkdf_aead_label, get_hkdf_key_expand_info, get_hkdf_salt_expand_info,
            KeyDerivation, SFRAME_HDKF_SUB_AUTH_EXPAND_INFO, SFRAME_HKDF_SUB_ENC_EXPAND_INFO,
        },
        secret::Secret,
    },
    error::{Result, SframeError},
};

impl KeyDerivation for Secret {
    fn expand_from<M, K>(cipher_suite: &CipherSuite, key_material: M, key_id: K) -> Result<Secret>
    where
        M: AsRef<[u8]>,
        K: Into<u64>,
    {
        let try_expand = || {
            let (base_key, salt) =
                expand_secret(cipher_suite, key_material.as_ref(), key_id.into())?;
            let (key, auth) = if cipher_suite.is_ctr_mode() {
                let (key, auth) = expand_subsecret(cipher_suite, &base_key)?;
                (key, Some(auth))
            } else {
                (base_key, None)
            };

            Ok(Secret { key, salt, auth })
        };

        try_expand().map_err(|_: openssl::error::ErrorStack| SframeError::KeyDerivation)
    }
}

fn expand_secret(
    cipher_suite: &CipherSuite,
    key_material: &[u8],
    key_id: u64,
) -> std::result::Result<(Vec<u8>, Vec<u8>), openssl::error::ErrorStack> {
    // No salt used for the extraction: https://www.ietf.org/archive/id/draft-ietf-sframe-enc-03.html#name-key-derivation
    let prk = extract_pseudo_random_key(cipher_suite, key_material, b"")?;
    let key = expand_key(
        cipher_suite,
        &prk,
        &get_hkdf_key_expand_info(key_id),
        cipher_suite.key_len,
    )?;
    let salt = expand_key(
        cipher_suite,
        &prk,
        &get_hkdf_salt_expand_info(key_id),
        cipher_suite.nonce_len,
    )?;

    Ok((key, salt))
}

fn expand_subsecret(
    cipher_suite: &CipherSuite,
    key: &[u8],
) -> std::result::Result<(Vec<u8>, Vec<u8>), openssl::error::ErrorStack> {
    let salt = get_hkdf_aead_label(cipher_suite.auth_tag_len);
    let prk = extract_pseudo_random_key(cipher_suite, key, &salt)?;
    let key = expand_key(
        cipher_suite,
        &prk,
        SFRAME_HKDF_SUB_ENC_EXPAND_INFO,
        cipher_suite.key_len,
    )?;
    let auth = expand_key(
        cipher_suite,
        &prk,
        SFRAME_HDKF_SUB_AUTH_EXPAND_INFO,
        cipher_suite.hash_len,
    )?;

    Ok((key, auth))
}

fn extract_pseudo_random_key(
    cipher_suite: &CipherSuite,
    key_material: &[u8],
    salt: &[u8],
) -> std::result::Result<Vec<u8>, openssl::error::ErrorStack> {
    let mut ctx = init_openssl_ctx(cipher_suite)?;

    ctx.set_hkdf_mode(openssl::pkey_ctx::HkdfMode::EXTRACT_ONLY)?;
    ctx.set_hkdf_salt(salt)?;
    ctx.set_hkdf_key(key_material)?;

    let mut prk = vec![];
    ctx.derive_to_vec(&mut prk)?;

    Ok(prk)
}

fn expand_key(
    cipher_suite: &CipherSuite,
    prk: &[u8],
    info: &[u8],
    key_len: usize,
) -> std::result::Result<Vec<u8>, openssl::error::ErrorStack> {
    let mut ctx = init_openssl_ctx(cipher_suite)?;

    ctx.set_hkdf_mode(openssl::pkey_ctx::HkdfMode::EXPAND_ONLY)?;
    ctx.set_hkdf_key(prk)?;
    ctx.add_hkdf_info(info)?;

    let mut key = vec![0; key_len];
    ctx.derive(Some(&mut key))?;

    Ok(key)
}

fn init_openssl_ctx(
    cipher_suite: &CipherSuite,
) -> std::result::Result<openssl::pkey_ctx::PkeyCtx<()>, openssl::error::ErrorStack> {
    let mut ctx = openssl::pkey_ctx::PkeyCtx::new_id(openssl::pkey::Id::HKDF)?;
    ctx.derive_init()?;

    let digest = cipher_suite.variant.into();
    ctx.set_hkdf_md(digest)?;

    Ok(ctx)
}

impl From<CipherSuiteVariant> for &'static openssl::md::MdRef {
    fn from(variant: CipherSuiteVariant) -> Self {
        match variant {
            CipherSuiteVariant::AesGcm128Sha256
            | CipherSuiteVariant::AesCtr128HmacSha256_80
            | CipherSuiteVariant::AesCtr128HmacSha256_64
            | CipherSuiteVariant::AesCtr128HmacSha256_32 => openssl::md::Md::sha256(),
            CipherSuiteVariant::AesGcm256Sha512 => openssl::md::Md::sha512(),
        }
    }
}
#[cfg(test)]
mod test {

    use super::*;
    use crate::{test_vectors::get_aes_ctr_test_vector, util::test::assert_bytes_eq};

    use test_case::test_case;

    #[test_case(CipherSuiteVariant::AesCtr128HmacSha256_80; "AesCtr128HmacSha256_80")]
    #[test_case(CipherSuiteVariant::AesCtr128HmacSha256_64; "AesCtr128HmacSha256_64")]
    #[test_case(CipherSuiteVariant::AesCtr128HmacSha256_32; "AesCtr128HmacSha256_32")]
    fn derive_correct_sub_keys(variant: CipherSuiteVariant) {
        let test_vec = get_aes_ctr_test_vector(&variant.to_string());
        let cipher_suite = CipherSuite::from(variant);

        let aead_salt = get_hkdf_aead_label(cipher_suite.auth_tag_len);
        let prk = extract_pseudo_random_key(&cipher_suite, &test_vec.base_key, &aead_salt).unwrap();
        assert_bytes_eq(&prk, &test_vec.enc_key);

        let (key, auth) = expand_subsecret(&cipher_suite, &test_vec.base_key).unwrap();
        assert_bytes_eq(&key, &test_vec.enc_key);
        assert_bytes_eq(&auth, &test_vec.auth_key);
    }
}
