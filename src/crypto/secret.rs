use crate::header::Counter;

/// Secret key material used by the built-in crypto backends, derived from base key material as
/// defined in [RFC 9605 Section 4.4.2](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secret {
    /// The encryption key (`sframe_key`).
    key: Vec<u8>,
    /// The salt for nonce generation (`sframe_salt`).
    salt: Vec<u8>,
    /// The authentication key (only for CTR mode ciphers).
    auth: Option<Vec<u8>>,
}

impl Secret {
    /// Builds an AEAD (AES-GCM) secret.
    pub(crate) fn aead(key: Vec<u8>, salt: Vec<u8>) -> Self {
        Self {
            key,
            salt,
            auth: None,
        }
    }

    /// Builds an AES-CTR + HMAC secret.
    #[cfg(aes_ctr)]
    pub(crate) fn aes_ctr(key: Vec<u8>, salt: Vec<u8>, auth: Vec<u8>) -> Self {
        Self {
            key,
            salt,
            auth: Some(auth),
        }
    }

    /// The encryption key (`sframe_key`).
    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }

    /// The salt used for nonce generation (`sframe_salt`).
    pub(crate) fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// The HMAC authentication key, present only for CTR-mode secrets.
    #[cfg(aes_ctr)]
    pub(crate) fn auth(&self) -> Option<&[u8]> {
        self.auth.as_deref()
    }

    /// Creates a nonce as defined in [RFC 9605 Section 4.4.3](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.3).
    pub(crate) fn create_nonce<const LEN: usize>(&self, counter: Counter) -> [u8; LEN] {
        let salt = self.salt();
        let be_counter = counter.to_be_bytes();
        let mut counter = be_counter.iter().rev();
        let mut iv = [0u8; LEN];
        let n = salt.len().min(LEN);
        for i in (0..n).rev() {
            iv[i] = salt[i];
            if let Some(counter_byte) = counter.next() {
                iv[i] ^= counter_byte;
            }
        }

        iv
    }

    #[cfg(all(test, crypto_backend))]
    pub(crate) fn from_test_vector(test_vec: &crate::test_vectors::SframeTest) -> Self {
        Secret::aead(test_vec.sframe_key.clone(), test_vec.sframe_salt.clone())
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

        let secret = Secret::aead(test_vec.sframe_key.clone(), test_vec.sframe_salt.clone());

        let nonce: [u8; NONCE_LEN] = secret.create_nonce(test_vec.counter);
        assert_bytes_eq(&nonce, &test_vec.nonce);
    }
}
