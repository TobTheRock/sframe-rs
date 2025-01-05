use crate::{
    crypto::buffer::{decryption::DecryptionBufferView, encryption::EncryptionBufferView},
    error::Result,
    header::Counter,
};

pub trait AeadEncrypt {
    fn encrypt<'a, B>(&self, buffer: B, counter: Counter) -> Result<()>
    where
        B: Into<EncryptionBufferView<'a>>;
}

pub trait AeadDecrypt {
    fn decrypt<'a, B>(&self, buffer: B, counter: Counter) -> Result<()>
    where
        B: Into<DecryptionBufferView<'a>>;
}

#[cfg(test)]
mod test {

    use super::{AeadDecrypt, AeadEncrypt};
    use crate::{
        crypto::{
            buffer::{
                decryption::DecryptionBufferView,
                encryption::{EncryptionBuffer, EncryptionBufferView},
            },
            cipher_suite::CipherSuiteVariant,
        },
        header::{KeyId, SframeHeader},
        key::{DecryptionKey, EncryptionKey},
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
        let enc_key = EncryptionKey::derive_from(
            CipherSuiteVariant::AesGcm256Sha512,
            KeyId::default(),
            KEY_MATERIAL.as_bytes(),
        )
        .unwrap();

        let mut frame_buffer = Vec::new();
        let mut encryption_buffer = EncryptionBuffer::try_allocate(
            &mut frame_buffer,
            enc_key.cipher_suite(),
            &Vec::from(&header),
            &data,
        )
        .unwrap();
        enc_key
            .encrypt(&mut encryption_buffer, header.counter())
            .unwrap();
    }

    #[test_case(CipherSuiteVariant::AesGcm128Sha256; "AesGcm128Sha256")]
    #[test_case(CipherSuiteVariant::AesGcm256Sha512; "AesGcm256Sha512")]
    #[cfg_attr(any(feature = "openssl", feature = "rust-crypto"), test_case(CipherSuiteVariant::AesCtr128HmacSha256_80; "AesCtr128HmacSha256_80"))]
    #[cfg_attr(any(feature = "openssl", feature = "rust-crypto"), test_case(CipherSuiteVariant::AesCtr128HmacSha256_64; "AesCtr128HmacSha256_64"))]
    #[cfg_attr(any(feature = "openssl", feature = "rust-crypto"), test_case(CipherSuiteVariant::AesCtr128HmacSha256_32; "AesCtr128HmacSha256_32"))]
    fn encrypt_test_vector(variant: CipherSuiteVariant) {
        let test_vec = get_sframe_test_vector(&variant.to_string());

        let enc_key = EncryptionKey::from_test_vector(variant, test_vec);

        let header = SframeHeader::new(test_vec.key_id, test_vec.counter);
        let header_buffer = Vec::from(&header);

        let mut aad = [header_buffer.as_slice(), test_vec.metadata.as_slice()].concat();
        assert_bytes_eq(&aad, &test_vec.aad);

        let mut cipher_text = test_vec.plain_text.clone();
        let mut tag = vec![0u8; enc_key.cipher_suite().auth_tag_len];
        let encryption_buffer = EncryptionBufferView {
            aad: &mut aad,
            cipher_text: &mut cipher_text,
            tag: &mut tag,
        };

        enc_key
            .encrypt(encryption_buffer, header.counter())
            .unwrap();

        let full_frame = [header_buffer, cipher_text, tag].concat().to_vec();
        assert_bytes_eq(&full_frame, &test_vec.cipher_text);
    }

    #[test_case(CipherSuiteVariant::AesGcm128Sha256; "AesGcm128Sha256")]
    #[test_case(CipherSuiteVariant::AesGcm256Sha512; "AesGcm256Sha512")]
    #[cfg_attr(any(feature = "openssl", feature = "rust-crypto"), test_case(CipherSuiteVariant::AesCtr128HmacSha256_80; "AesCtr128HmacSha256_80"))]
    #[cfg_attr(any(feature = "openssl", feature = "rust-crypto"), test_case(CipherSuiteVariant::AesCtr128HmacSha256_64; "AesCtr128HmacSha256_64"))]
    #[cfg_attr(any(feature = "openssl", feature = "rust-crypto"), test_case(CipherSuiteVariant::AesCtr128HmacSha256_32; "AesCtr128HmacSha256_32"))]
    fn decrypt_test_vector(variant: CipherSuiteVariant) {
        let test_vec = get_sframe_test_vector(&variant.to_string());

        let dec_key = DecryptionKey::from_test_vector(variant, test_vec);
        let header: SframeHeader = SframeHeader::new(test_vec.key_id, test_vec.counter);
        let header_buffer = Vec::from(&header);

        let mut aad = [header_buffer.as_slice(), test_vec.metadata.as_slice()].concat();
        assert_bytes_eq(&aad, &test_vec.aad);

        let mut data = Vec::from(&test_vec.cipher_text[header.len()..]);

        let decryption_buffer = DecryptionBufferView {
            aad: &mut aad,
            cipher_text: &mut data,
        };

        dec_key
            .decrypt(decryption_buffer, header.counter())
            .unwrap();
        data.truncate(data.len() - dec_key.cipher_suite().auth_tag_len);

        assert_bytes_eq(&data, &test_vec.plain_text);
    }
}
