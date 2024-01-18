use crate::{
    crypto::aead::{AeadDecrypt, AeadEncrypt},
    error::Result,
    header::FrameCount,
};

use crate::{
    crypto::{cipher_suite::CipherSuiteVariant, secret::Secret},
    error::SframeError,
};

use super::tag::Tag;

const AES_GCM_IV_LEN: usize = 12;
const AES_CTR_IVS_LEN: usize = 16;

impl AeadEncrypt for Secret {
    type AuthTag = Tag;
    fn encrypt<IoBuffer, Aad>(
        &self,
        io_buffer: &mut IoBuffer,
        aad_buffer: &Aad,
        frame_count: FrameCount,
    ) -> Result<Tag>
    where
        IoBuffer: AsMut<[u8]> + ?Sized,
        Aad: AsRef<[u8]> + ?Sized,
    {
        let io_buffer = io_buffer.as_mut();

        let (out, tag) = if self.cipher_suite.is_ctr_mode() {
            self.encrypt_aes_ctr(io_buffer, aad_buffer.as_ref(), frame_count)
        } else {
            self.encrypt_aead(io_buffer, aad_buffer.as_ref(), frame_count)
        }?;

        debug_assert!(
            out.len() == io_buffer.len(),
            "For a symmetric encryption it is given that the output has the same length as the input"
        );
        io_buffer.copy_from_slice(&out[..io_buffer.len()]);

        Ok(tag)
    }
}

impl AeadDecrypt for Secret {
    fn decrypt<'a, IoBuffer, Aad>(
        &self,
        io_buffer: &'a mut IoBuffer,
        aad_buffer: &Aad,
        frame_count: FrameCount,
    ) -> Result<&'a mut [u8]>
    where
        IoBuffer: AsMut<[u8]> + ?Sized,
        Aad: AsRef<[u8]> + ?Sized,
    {
        let cipher_suite = self.cipher_suite;

        let io_buffer = io_buffer.as_mut();
        if io_buffer.len() < cipher_suite.auth_tag_len {
            return Err(SframeError::DecryptionFailure);
        }

        // TODO maybe we could store the cipher permanently, small performance gain (similar for ring)
        let cipher = cipher_suite.variant.into();

        let encrypted_len = io_buffer.len() - cipher_suite.auth_tag_len;
        let encrypted = &io_buffer[..encrypted_len];
        let tag = &io_buffer[encrypted_len..];

        let out = if cipher_suite.is_ctr_mode() {
            self.decrypt_aes_ctr(cipher, frame_count, aad_buffer.as_ref(), encrypted, tag)
        } else {
            let nonce = self.create_nonce::<AES_GCM_IV_LEN>(frame_count);
            openssl::symm::decrypt_aead(
                cipher,
                &self.key,
                Some(&nonce),
                aad_buffer.as_ref(),
                encrypted,
                tag,
            )
            .map_err(|err| {
                log::debug!("Decryption failed, OpenSSL error stack: {}", err);
                SframeError::DecryptionFailure
            })
        }?;

        debug_assert!(
            out.len() == encrypted_len,
            "For a symmetric encryption it is given that the output has the same length as the input"
        );
        io_buffer[..encrypted_len].copy_from_slice(&out);

        Ok(&mut io_buffer[..encrypted_len])
    }
}

impl Secret {
    fn encrypt_aead(
        &self,
        plain_text: &[u8],
        aad: &[u8],
        frame_count: FrameCount,
    ) -> Result<(Vec<u8>, Tag)> {
        let nonce = self.create_nonce::<AES_GCM_IV_LEN>(frame_count);

        let mut tag = Tag::new(self.cipher_suite.auth_tag_len);
        let out = openssl::symm::encrypt_aead(
            self.cipher_suite.variant.into(),
            &self.key,
            Some(&nonce),
            aad,
            plain_text,
            tag.as_mut(),
        )?;
        Ok((out, tag))
    }

    fn encrypt_aes_ctr(
        &self,
        plain_text: &[u8],
        aad: &[u8],
        frame_count: FrameCount,
    ) -> Result<(Vec<u8>, Tag)> {
        let auth_key = self.auth.as_ref().ok_or(SframeError::EncryptionFailure)?;
        // openssl expects a fixed iv length of 16 byte, thus we needed to pad the sframe nonce
        let iv = self.create_nonce::<AES_CTR_IVS_LEN>(frame_count);
        let nonce = &iv[..self.cipher_suite.nonce_len];

        let encrypted = openssl::symm::encrypt(
            self.cipher_suite.variant.into(),
            &self.key,
            Some(&iv),
            plain_text,
        )?;
        let tag = self.compute_tag(auth_key, aad, nonce, &encrypted)?;
        Ok((encrypted, tag))
    }

    fn decrypt_aes_ctr(
        &self,
        cipher: openssl::symm::Cipher,
        frame_count: FrameCount,
        aad: &[u8],
        encrypted: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>> {
        let iv: [u8; 16] = self.create_nonce::<AES_CTR_IVS_LEN>(frame_count);
        let nonce = &iv[..self.cipher_suite.nonce_len];
        let auth_key = self.auth.as_ref().ok_or(SframeError::DecryptionFailure)?;

        let candidate_tag = self
            .compute_tag(auth_key, aad, nonce, encrypted)
            .map_err(|err| {
                log::debug!("Decryption failed, OpenSSL error stack: {}", err);
                SframeError::DecryptionFailure
            })?;

        if !openssl::memcmp::eq(tag, candidate_tag.as_ref()) {
            log::debug!("Tags mismatching, discarding frame.");
            return Err(SframeError::DecryptionFailure);
        }
        openssl::symm::decrypt(cipher, &self.key, Some(&iv), encrypted).map_err(|err| {
            log::debug!("Decryption failed, OpenSSL error stack: {}", err);
            SframeError::DecryptionFailure
        })
    }

    fn compute_tag(
        &self,
        auth_key: &[u8],
        aad: &[u8],
        nonce: &[u8],
        encrypted: &[u8],
    ) -> std::result::Result<Tag, openssl::error::ErrorStack> {
        let key = openssl::pkey::PKey::hmac(auth_key)?;
        let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key)?;

        // for current platforms there is no issue casting from usize to u64
        signer.update(&(aad.len() as u64).to_be_bytes())?;
        signer.update(&(encrypted.len() as u64).to_be_bytes())?;
        signer.update(&(self.cipher_suite.auth_tag_len as u64).to_be_bytes())?;
        signer.update(nonce)?;
        signer.update(aad)?;
        signer.update(encrypted)?;

        let mut tag = signer.sign_to_vec()?;
        tag.resize(self.cipher_suite.auth_tag_len, 0);

        Ok(tag.into())
    }
}

impl From<openssl::error::ErrorStack> for SframeError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        log::debug!("Encryption failed, OpenSSL error stack: {}", err);
        SframeError::EncryptionFailure
    }
}

impl From<CipherSuiteVariant> for openssl::symm::Cipher {
    fn from(variant: CipherSuiteVariant) -> Self {
        match variant {
            CipherSuiteVariant::AesCtr128HmacSha256_80
            | CipherSuiteVariant::AesCtr128HmacSha256_64
            | CipherSuiteVariant::AesCtr128HmacSha256_32 => openssl::symm::Cipher::aes_128_ctr(),
            CipherSuiteVariant::AesGcm128Sha256 => openssl::symm::Cipher::aes_128_gcm(),
            CipherSuiteVariant::AesGcm256Sha512 => openssl::symm::Cipher::aes_256_gcm(),
        }
    }
}
