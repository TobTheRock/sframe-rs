use crate::{error::Result, header::FrameCount};

pub trait AeadEncrypt {
    type AuthTag: AsRef<[u8]>;
    fn encrypt<IoBuffer, Aad>(
        &self,
        io_buffer: &mut IoBuffer,
        aad_buffer: &Aad,
        frame_count: FrameCount,
    ) -> Result<Self::AuthTag>
    where
        IoBuffer: AsMut<[u8]> + ?Sized,
        Aad: AsRef<[u8]> + ?Sized;
}

pub trait AeadDecrypt {
    fn decrypt<'a, IoBuffer, Aad>(
        &self,
        io_buffer: &'a mut IoBuffer,
        aad_buffer: &Aad,
        frame_count: FrameCount,
    ) -> Result<&'a mut [u8]>
    where
        IoBuffer: AsMut<[u8]> + ?Sized,
        Aad: AsRef<[u8]> + ?Sized;
}

#[cfg(test)]
mod test {

    use super::{AeadDecrypt, AeadEncrypt};
    use crate::{
        crypto::cipher_suite::CipherSuiteVariant,
        header::{KeyId, SframeHeader},
        key::SframeKey,
        test_vectors::get_sframe_test_vector,
        util::test::assert_bytes_eq,
    };

    use rand::{thread_rng, Rng};
    use test_case::test_case;

    const KEY_MATERIAL: &str = "THIS_IS_RANDOM";

    #[test]
    fn encrypt_random_frame() {
        let mut data = vec![0u8; 1024];
        thread_rng().fill(data.as_mut_slice());
        let header = SframeHeader::new(0, 0);
        let sframe_key = SframeKey::expand_from(
            CipherSuiteVariant::AesGcm256Sha512,
            KeyId::default(),
            KEY_MATERIAL.as_bytes(),
        )
        .unwrap();

        let _tag = sframe_key
            .encrypt(&mut data, &Vec::from(&header), header.frame_count())
            .unwrap();
    }

    #[test_case(CipherSuiteVariant::AesGcm128Sha256; "AesGcm128Sha256")]
    #[test_case(CipherSuiteVariant::AesGcm256Sha512; "AesGcm256Sha512")]
    #[cfg_attr(feature = "openssl", test_case(CipherSuiteVariant::AesCtr128HmacSha256_80; "AesCtr128HmacSha256_80"))]
    #[cfg_attr(feature = "openssl", test_case(CipherSuiteVariant::AesCtr128HmacSha256_64; "AesCtr128HmacSha256_64"))]
    #[cfg_attr(feature = "openssl", test_case(CipherSuiteVariant::AesCtr128HmacSha256_32; "AesCtr128HmacSha256_32"))]
    fn encrypt_test_vector(variant: CipherSuiteVariant) {
        let test_vec = get_sframe_test_vector(&variant.to_string());

        let sframe_key = SframeKey::from_test_vector(variant, test_vec);

        let mut data_buffer = test_vec.plain_text.clone();

        let header = SframeHeader::new(test_vec.key_id, test_vec.frame_count);
        let header_buffer = Vec::from(&header);

        let aad_buffer = [header_buffer.as_slice(), test_vec.metadata.as_slice()].concat();

        let tag = sframe_key
            .encrypt(&mut data_buffer, &aad_buffer, header.frame_count())
            .unwrap();

        let full_frame: Vec<u8> = header_buffer
            .into_iter()
            .chain(data_buffer)
            .chain(tag.as_ref().iter().cloned())
            .collect();

        assert_bytes_eq(&aad_buffer, &test_vec.aad);
        assert_bytes_eq(&full_frame, &test_vec.cipher_text);
    }

    #[test_case(CipherSuiteVariant::AesGcm128Sha256; "AesGcm128Sha256")]
    #[test_case(CipherSuiteVariant::AesGcm256Sha512; "AesGcm256Sha512")]
    #[cfg_attr(feature = "openssl", test_case(CipherSuiteVariant::AesCtr128HmacSha256_80; "AesCtr128HmacSha256_80"))]
    #[cfg_attr(feature = "openssl", test_case(CipherSuiteVariant::AesCtr128HmacSha256_64; "AesCtr128HmacSha256_64"))]
    #[cfg_attr(feature = "openssl", test_case(CipherSuiteVariant::AesCtr128HmacSha256_32; "AesCtr128HmacSha256_32"))]
    fn decrypt_test_vector(variant: CipherSuiteVariant) {
        let test_vec = get_sframe_test_vector(&variant.to_string());

        let sframe_key = SframeKey::from_test_vector(variant, test_vec);
        let header = SframeHeader::new(test_vec.key_id, test_vec.frame_count);
        let header_buffer = Vec::from(&header);

        let aad_buffer = [header_buffer.as_slice(), test_vec.metadata.as_slice()].concat();
        assert_bytes_eq(&aad_buffer, &test_vec.aad);

        let mut data = Vec::from(&test_vec.cipher_text[header.len()..]);

        let decrypted = sframe_key
            .decrypt(&mut data, &aad_buffer, header.frame_count())
            .unwrap();

        assert_bytes_eq(decrypted, &test_vec.plain_text);
    }
}
