use super::secret::Secret;
use crate::{CipherSuite, error::Result, header::KeyId};

/// Trait for key derivation implementations as defined in [RFC 9605 Section 4.4.2](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.2).
pub trait KeyDerivation {
    /// Expands key material into a [`Secret`].
    fn expand_from<M, K>(cipher_suite: CipherSuite, key_material: M, key_id: K) -> Result<Secret>
    where
        M: AsRef<[u8]>,
        K: Into<KeyId>;
}

/// Trait for key material ratcheting as defined in [RFC 9605 Section 5.1](https://www.rfc-editor.org/rfc/rfc9605.html#section-5.1).
pub trait Ratcheting: Sized {
    /// Ratchets the key material forward, producing new key material.
    fn ratchet(&self, cipher_suite: CipherSuite) -> Result<Vec<u8>>
    where
        Self: AsRef<[u8]>;
}

/// Constructs the HKDF info label for key expansion as defined in [RFC 9605 Section 4.4.2](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.2).
pub fn get_hkdf_key_expand_label(key_id: u64, cipher_suite: CipherSuite) -> Vec<u8> {
    [
        SFRAME_LABEL,
        SFRAME_HKDF_KEY_EXPAND_LABEL,
        &key_id.to_be_bytes(),
        &(cipher_suite as u16).to_be_bytes(),
    ]
    .concat()
}

/// Constructs the HKDF info label for salt expansion as defined in [RFC 9605 Section 4.4.2](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.2).
pub fn get_hkdf_salt_expand_label(key_id: u64, cipher_suite: CipherSuite) -> Vec<u8> {
    [
        SFRAME_LABEL,
        SFRAME_HDKF_SALT_EXPAND_LABEL,
        &key_id.to_be_bytes(),
        &(cipher_suite as u16).to_be_bytes(),
    ]
    .concat()
}

/// Returns the HKDF info label for ratcheting as defined in [RFC 9605 Section 5.1](https://www.rfc-editor.org/rfc/rfc9605.html#section-5.1).
pub const fn get_hkdf_ratchet_expand_label() -> &'static [u8] {
    b"Sframe 1.0 Ratchet"
}

const SFRAME_LABEL: &[u8] = b"SFrame 1.0 ";

const SFRAME_HKDF_KEY_EXPAND_LABEL: &[u8] = b"Secret key ";
const SFRAME_HDKF_SALT_EXPAND_LABEL: &[u8] = b"Secret salt ";

#[cfg(test)]
mod test {

    use super::{KeyDerivation, Ratcheting, get_hkdf_key_expand_label, get_hkdf_salt_expand_label};

    use crate::{crypto::cipher_suite::CipherSuite, test_vectors::get_sframe_test_vector, util::test::assert_bytes_eq};

    use test_case::test_case;

    // Import the appropriate Kdf based on feature flags
    cfg_if::cfg_if! {
        if #[cfg(all(feature = "ring", not(feature = "openssl"), not(feature = "rust-crypto")))] {
            use crate::crypto::ring::Kdf;
        } else if #[cfg(all(feature = "openssl", not(feature = "ring"), not(feature = "rust-crypto")))] {
            use crate::crypto::openssl::Kdf;
        } else if #[cfg(all(feature = "rust-crypto", not(feature = "ring"), not(feature = "openssl")))] {
            use crate::crypto::rust_crypto::Kdf;
        }
    }

    #[test_case(CipherSuite::AesGcm128Sha256; "AesGcm128Sha256")]
    #[test_case(CipherSuite::AesGcm256Sha512; "AesGcm256Sha512")]
    #[cfg_attr(any(feature = "openssl", feature = "rust-crypto"), test_case(CipherSuite::AesCtr128HmacSha256_80; "AesCtr128HmacSha256_80"))]
    #[cfg_attr(any(feature = "openssl", feature = "rust-crypto"), test_case(CipherSuite::AesCtr128HmacSha256_64; "AesCtr128HmacSha256_64"))]
    #[cfg_attr(any(feature = "openssl", feature = "rust-crypto"), test_case(CipherSuite::AesCtr128HmacSha256_32; "AesCtr128HmacSha256_32"))]
    fn extracts_correct_labels(cipher_suite: CipherSuite) {
        let test_vec = get_sframe_test_vector(&cipher_suite.to_string());
        assert_bytes_eq(
            &get_hkdf_key_expand_label(test_vec.key_id, cipher_suite),
            &test_vec.sframe_key_label,
        );
        assert_bytes_eq(
            &get_hkdf_salt_expand_label(test_vec.key_id, cipher_suite),
            &test_vec.sframe_salt_label,
        );
    }

    #[test_case(CipherSuite::AesGcm128Sha256; "AesGcm128Sha256")]
    #[test_case(CipherSuite::AesGcm256Sha512; "AesGcm256Sha512")]
    fn derive_correct_base_keys(cipher_suite: CipherSuite) {
        let test_vec = get_sframe_test_vector(&cipher_suite.to_string());

        let secret = Kdf::expand_from(cipher_suite, &test_vec.key_material, test_vec.key_id).unwrap();

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

            let secret =
                Kdf::expand_from(cipher_suite, &test_vec.key_material, test_vec.key_id).unwrap();

            assert_bytes_eq(&secret.salt, &test_vec.sframe_salt);
            // the subkeys stored in sframe_key.key and sframe_key.auth are not directly included in the test vectors, but we can extract them from sframe_key
            let secret_len = cipher_suite.key_len() - cipher_suite.hash_len();
            assert_bytes_eq(&secret.key, &test_vec.sframe_key[..secret_len]);

            let auth_key = secret.auth.unwrap();
            assert_eq!(auth_key.len(), cipher_suite.hash_len());
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
        let new_material = original_material.ratchet(cipher_suite).unwrap();

        assert_ne!(new_material, original_material);
    }
}
