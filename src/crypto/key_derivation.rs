// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use super::{cipher_suite::CipherSuite, secret::Secret};
use crate::error::Result;

pub trait KeyDerivation {
    fn expand_from<M, K>(cipher_suite: &CipherSuite, key_material: M, key_id: K) -> Result<Secret>
    where
        M: AsRef<[u8]>,
        K: Into<u64>;
}

pub fn get_hkdf_key_expand_info(key_id: u64, cipher_suite_id: u16) -> Vec<u8> {
    [
        SFRAME_LABEL,
        SFRAME_HKDF_KEY_EXPAND_INFO,
        &key_id.to_be_bytes(),
        &cipher_suite_id.to_be_bytes(),
    ]
    .concat()
}

pub fn get_hkdf_salt_expand_info(key_id: u64, cipher_suite_id: u16) -> Vec<u8> {
    [
        SFRAME_LABEL,
        SFRAME_HDKF_SALT_EXPAND_INFO,
        &key_id.to_be_bytes(),
        &cipher_suite_id.to_be_bytes(),
    ]
    .concat()
}

const SFRAME_LABEL: &[u8] = b"SFrame 1.0 ";

const SFRAME_HKDF_KEY_EXPAND_INFO: &[u8] = b"Secret key ";
const SFRAME_HDKF_SALT_EXPAND_INFO: &[u8] = b"Secret salt ";

#[cfg(test)]
mod test {
    use super::KeyDerivation;
    use crate::crypto::cipher_suite::CipherSuite;
    use crate::crypto::secret::Secret;
    use crate::test_vectors::get_sframe_test_vector;
    use crate::{crypto::cipher_suite::CipherSuiteVariant, util::test::assert_bytes_eq};

    mod aes_gcm {
        use super::*;
        use crate::crypto::key_derivation::{get_hkdf_key_expand_info, get_hkdf_salt_expand_info};
        use test_case::test_case;

        #[test_case(CipherSuiteVariant::AesGcm128Sha256; "AesGcm128Sha256")]
        #[test_case(CipherSuiteVariant::AesGcm256Sha512; "AesGcm256Sha512")]
        #[cfg_attr(feature = "openssl", test_case(CipherSuiteVariant::AesCtr128HmacSha256_80; "AesCtr128HmacSha256_80"))]
        #[cfg_attr(feature = "openssl", test_case(CipherSuiteVariant::AesCtr128HmacSha256_64; "AesCtr128HmacSha256_64"))]
        #[cfg_attr(feature = "openssl", test_case(CipherSuiteVariant::AesCtr128HmacSha256_32; "AesCtr128HmacSha256_32"))]
        fn extracts_correct_labels(variant: CipherSuiteVariant) {
            let test_vec = get_sframe_test_vector(&variant.to_string());
            let cipher_suite: CipherSuite = CipherSuite::from(variant);
            assert_bytes_eq(
                &get_hkdf_key_expand_info(test_vec.key_id, cipher_suite.id),
                &test_vec.sframe_key_label,
            );
            assert_bytes_eq(
                &get_hkdf_salt_expand_info(test_vec.key_id, cipher_suite.id),
                &test_vec.sframe_salt_label,
            );
        }

        #[test_case(CipherSuiteVariant::AesGcm128Sha256; "AesGcm128Sha256")]
        #[test_case(CipherSuiteVariant::AesGcm256Sha512; "AesGcm256Sha512")]
        fn derive_correct_base_keys(variant: CipherSuiteVariant) {
            let test_vec = get_sframe_test_vector(&variant.to_string());
            let cipher_suite: CipherSuite = CipherSuite::from(variant);

            let secret =
                Secret::expand_from(&cipher_suite, &test_vec.key_material, test_vec.key_id)
                    .unwrap();

            assert_bytes_eq(&secret.key, &test_vec.sframe_key);
            assert_bytes_eq(&secret.salt, &test_vec.sframe_salt);
        }
    }

    #[cfg(feature = "openssl")]
    mod aes_ctr {
        use super::*;
        use test_case::test_case;

        #[test_case(CipherSuiteVariant::AesCtr128HmacSha256_80; "AesCtr128HmacSha256_80")]
        #[test_case(CipherSuiteVariant::AesCtr128HmacSha256_64; "AesCtr128HmacSha256_64")]
        #[test_case(CipherSuiteVariant::AesCtr128HmacSha256_32; "AesCtr128HmacSha256_32")]
        fn derive_correct_sub_keys(variant: CipherSuiteVariant) {
            let test_vec = get_sframe_test_vector(&variant.to_string());
            let cipher_suite: CipherSuite = CipherSuite::from(variant);

            let secret =
                Secret::expand_from(&cipher_suite, &test_vec.key_material, test_vec.key_id)
                    .unwrap();

            assert_bytes_eq(&secret.salt, &test_vec.sframe_salt);
            // the subkeys stored in secret.key and secret.auth are not directly included in the test vectors, but we can extract them from sframe_key
            let secret_len = cipher_suite.key_len - cipher_suite.hash_len;
            assert_bytes_eq(&secret.key, &test_vec.sframe_key[..secret_len]);

            let auth_key = secret.auth.unwrap();
            assert_eq!(auth_key.len(), cipher_suite.hash_len);
            assert_bytes_eq(&auth_key, &test_vec.sframe_key[secret_len..]);
        }
    }
}
