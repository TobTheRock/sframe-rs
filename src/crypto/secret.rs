use crate::header::Counter;

/// Secret key material derived from base key material.
/// Contains the encryption key, salt for nonce generation, and optionally an auth key for CTR mode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secret {
    /// The encryption key.
    pub key: Vec<u8>,
    /// The salt used for nonce generation.
    pub salt: Vec<u8>,
    /// The authentication key (only used for CTR mode ciphers).
    pub auth: Option<Vec<u8>>,
}

impl Secret {
    /// Creates a nonce by XORing the salt with the counter.
    /// The counter bytes are applied in little-endian order from the end of the nonce.
    pub fn create_nonce<const LEN: usize>(&self, counter: Counter) -> [u8; LEN] {
        let be_counter = counter.to_be_bytes();
        let mut counter = be_counter.iter().rev();
        let mut iv = [0u8; LEN];
        let n = self.salt.len().min(LEN);
        for i in (0..n).rev() {
            iv[i] = self.salt[i];
            if let Some(counter_byte) = counter.next() {
                iv[i] ^= counter_byte;
            }
        }

        iv
    }

    #[cfg(test)]
    pub(crate) fn from_test_vector(test_vec: &crate::test_vectors::SframeTest) -> Self {
        Self {
            key: test_vec.sframe_key.clone(),
            salt: test_vec.sframe_salt.clone(),
            auth: None,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::test_vectors::get_sframe_test_vector;
    use crate::{crypto::cipher_suite::CipherSuite, util::test::assert_bytes_eq};

    use super::Secret;
    use test_case::test_case;
    const NONCE_LEN: usize = 12;

    #[test_case(CipherSuite::AesGcm128Sha256; "AesGcm128Sha256")]
    #[test_case(CipherSuite::AesGcm256Sha512; "AesGcm256Sha512")]
    #[cfg_attr(feature = "openssl", test_case(CipherSuite::AesCtr128HmacSha256_80; "AesCtr128HmacSha256_80"))]
    #[cfg_attr(feature = "openssl", test_case(CipherSuite::AesCtr128HmacSha256_64; "AesCtr128HmacSha256_64"))]
    #[cfg_attr(feature = "openssl", test_case(CipherSuite::AesCtr128HmacSha256_32; "AesCtr128HmacSha256_32"))]
    fn create_correct_nonce(cipher_suite: CipherSuite) {
        let test_vec = get_sframe_test_vector(&cipher_suite.to_string());

        let secret = Secret {
            key: test_vec.sframe_key.clone(),
            salt: test_vec.sframe_salt.clone(),
            auth: None,
        };

        let nonce: [u8; NONCE_LEN] = secret.create_nonce(test_vec.counter);
        assert_bytes_eq(&nonce, &test_vec.nonce);
    }
}
