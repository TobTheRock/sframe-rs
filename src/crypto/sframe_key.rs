use crate::header::{FrameCount, KeyId};

use super::cipher_suite::CipherSuite;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SframeKey {
    pub key: Vec<u8>,
    pub salt: Vec<u8>,
    pub auth: Option<Vec<u8>>,
    pub cipher_suite: CipherSuite,
    pub key_id: KeyId,
}

impl SframeKey {
    pub(crate) fn create_nonce<const LEN: usize>(&self, frame_count: FrameCount) -> [u8; LEN] {
        let be_frame_count = frame_count.to_be_bytes();
        let mut counter = be_frame_count.iter().rev();
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
}

#[cfg(test)]
mod test {
    use crate::test_vectors::get_sframe_test_vector;
    use crate::{crypto::cipher_suite::CipherSuiteVariant, util::test::assert_bytes_eq};

    use super::SframeKey;
    use test_case::test_case;
    const NONCE_LEN: usize = 12;

    #[test_case(CipherSuiteVariant::AesGcm128Sha256; "AesGcm128Sha256")]
    #[test_case(CipherSuiteVariant::AesGcm256Sha512; "AesGcm256Sha512")]
    #[cfg_attr(feature = "openssl", test_case(CipherSuiteVariant::AesCtr128HmacSha256_80; "AesCtr128HmacSha256_80"))]
    #[cfg_attr(feature = "openssl", test_case(CipherSuiteVariant::AesCtr128HmacSha256_64; "AesCtr128HmacSha256_64"))]
    #[cfg_attr(feature = "openssl", test_case(CipherSuiteVariant::AesCtr128HmacSha256_32; "AesCtr128HmacSha256_32"))]
    fn create_correct_nonce(variant: CipherSuiteVariant) {
        let test_vec = get_sframe_test_vector(&variant.to_string());

        let sframe_key = SframeKey {
            key: test_vec.sframe_key.clone(),
            salt: test_vec.sframe_salt.clone(),
            auth: None,
            cipher_suite: variant.into(),
            key_id: test_vec.key_id,
        };

        let nonce: [u8; NONCE_LEN] = sframe_key.create_nonce(test_vec.frame_count);
        assert_bytes_eq(&nonce, &test_vec.nonce);
    }
}
