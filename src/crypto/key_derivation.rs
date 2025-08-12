use super::cipher_suite::CipherSuiteParams;
use crate::{error::Result, header::KeyId, CipherSuite};

pub trait KeyDerivation: Sized {
    fn expand_from<M, K>(
        cipher_suite: &CipherSuiteParams,
        key_material: M,
        key_id: K,
    ) -> Result<Self>
    where
        M: AsRef<[u8]>,
        K: Into<KeyId>;
}

pub trait Ratcheting: Sized {
    fn ratchet(&self, cipher_suite: &CipherSuiteParams) -> Result<Vec<u8>>
    where
        Self: AsRef<[u8]>;
}

pub fn get_hkdf_key_expand_label(key_id: u64, cipher_suite: CipherSuite) -> Vec<u8> {
    [
        SFRAME_LABEL,
        SFRAME_HKDF_KEY_EXPAND_LABEL,
        &key_id.to_be_bytes(),
        &(cipher_suite as u16).to_be_bytes(),
    ]
    .concat()
}

pub fn get_hkdf_salt_expand_label(key_id: u64, cipher_suite: CipherSuite) -> Vec<u8> {
    [
        SFRAME_LABEL,
        SFRAME_HDKF_SALT_EXPAND_LABEL,
        &key_id.to_be_bytes(),
        &(cipher_suite as u16).to_be_bytes(),
    ]
    .concat()
}

pub const fn get_hkdf_ratchet_expand_label() -> &'static [u8] {
    b"Sframe 1.0 Ratchet"
}

const SFRAME_LABEL: &[u8] = b"SFrame 1.0 ";

const SFRAME_HKDF_KEY_EXPAND_LABEL: &[u8] = b"Secret key ";
const SFRAME_HDKF_SALT_EXPAND_LABEL: &[u8] = b"Secret salt ";

#[cfg(test)]
mod test {

    use super::{get_hkdf_key_expand_label, get_hkdf_salt_expand_label, KeyDerivation, Ratcheting};

    use crate::{
        crypto::{
            cipher_suite::{CipherSuite, CipherSuiteParams},
            secret::Secret,
        },
        test_vectors::get_sframe_test_vector,
        util::test::assert_bytes_eq,
    };

    use test_case::test_case;

    #[test_case(CipherSuite::AesGcm128Sha256; "AesGcm128Sha256")]
    #[test_case(CipherSuite::AesGcm256Sha512; "AesGcm256Sha512")]
    #[cfg_attr(any(feature = "openssl", feature = "rust-crypto"), test_case(CipherSuite::AesCtr128HmacSha256_80; "AesCtr128HmacSha256_80"))]
    #[cfg_attr(any(feature = "openssl", feature = "rust-crypto"), test_case(CipherSuite::AesCtr128HmacSha256_64; "AesCtr128HmacSha256_64"))]
    #[cfg_attr(any(feature = "openssl", feature = "rust-crypto"), test_case(CipherSuite::AesCtr128HmacSha256_32; "AesCtr128HmacSha256_32"))]
    fn extracts_correct_labels(cipher_suite: CipherSuite) {
        let test_vec = get_sframe_test_vector(&cipher_suite.to_string());
        let params: CipherSuiteParams = CipherSuiteParams::from(cipher_suite);
        assert_bytes_eq(
            &get_hkdf_key_expand_label(test_vec.key_id, params.cipher_suite),
            &test_vec.sframe_key_label,
        );
        assert_bytes_eq(
            &get_hkdf_salt_expand_label(test_vec.key_id, params.cipher_suite),
            &test_vec.sframe_salt_label,
        );
    }

    #[test_case(CipherSuite::AesGcm128Sha256; "AesGcm128Sha256")]
    #[test_case(CipherSuite::AesGcm256Sha512; "AesGcm256Sha512")]
    fn derive_correct_base_keys(cipher_suite: CipherSuite) {
        let test_vec = get_sframe_test_vector(&cipher_suite.to_string());
        let params: CipherSuiteParams = CipherSuiteParams::from(cipher_suite);

        let secret = Secret::expand_from(&params, &test_vec.key_material, test_vec.key_id).unwrap();

        assert_bytes_eq(&secret.key, &test_vec.sframe_key);
        assert_bytes_eq(&secret.salt, &test_vec.sframe_salt);
    }

    #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
    mod aes_ctr {

        use super::*;
        use test_case::test_case;

        #[test_case(CipherSuite::AesCtr128HmacSha256_80; "AesCtr128HmacSha256_80")]
        #[test_case(CipherSuite::AesCtr128HmacSha256_64; "AesCtr128HmacSha256_64")]
        #[test_case(CipherSuite::AesCtr128HmacSha256_32; "AesCtr128HmacSha256_32")]
        fn derive_correct_sub_keys(cipher_suite: CipherSuite) {
            let test_vec = get_sframe_test_vector(&cipher_suite.to_string());
            let params = CipherSuiteParams::from(cipher_suite);

            let secret =
                Secret::expand_from(&params, &test_vec.key_material, test_vec.key_id).unwrap();

            assert_bytes_eq(&secret.salt, &test_vec.sframe_salt);
            // the subkeys stored in sframe_key.key and sframe_key.auth are not directly included in the test vectors, but we can extract them from sframe_key
            let secret_len = params.key_len - params.hash_len;
            assert_bytes_eq(&secret.key, &test_vec.sframe_key[..secret_len]);

            let auth_key = secret.auth.unwrap();
            assert_eq!(auth_key.len(), params.hash_len);
            assert_bytes_eq(&auth_key, &test_vec.sframe_key[secret_len..]);
        }
    }

    #[test_case(CipherSuite::AesGcm128Sha256; "AesGcm128Sha256")]
    #[test_case(CipherSuite::AesGcm256Sha512; "AesGcm256Sha512")]
    #[cfg_attr(any(feature = "openssl", feature = "rust-crypto"), test_case(CipherSuite::AesCtr128HmacSha256_80; "AesCtr128HmacSha256_80"))]
    #[cfg_attr(any(feature = "openssl", feature = "rust-crypto"), test_case(CipherSuite::AesCtr128HmacSha256_64; "AesCtr128HmacSha256_64"))]
    #[cfg_attr(any(feature = "openssl", feature = "rust-crypto"), test_case(CipherSuite::AesCtr128HmacSha256_32; "AesCtr128HmacSha256_32"))]
    fn ratchets_key(cipher_suite: CipherSuite) {
        let original_material = Vec::from(b"SOMETHING");
        let new_material = original_material.ratchet(&cipher_suite.into()).unwrap();

        assert_ne!(new_material, original_material);
    }
}
