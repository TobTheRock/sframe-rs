use crate::{
    crypto::{
        aead::{AeadDecrypt, AeadEncrypt},
        buffer::{decryption::DecryptionBufferView, encryption::EncryptionBufferView},
        cipher_suite::CipherSuite,
    },
    error::Result,
    header::Counter,
    key::{DecryptionKey, EncryptionKey},
};

use crate::{crypto::cipher_suite::CipherSuiteVariant, error::SframeError};

const AES_GCM_IV_LEN: usize = 12;
const AES_CTR_IVS_LEN: usize = 16;

impl AeadEncrypt for EncryptionKey {
    fn encrypt<'a, B>(&self, buffer: B, counter: Counter) -> Result<()>
    where
        B: Into<EncryptionBufferView<'a>>,
    {
        let buffer_view = buffer.into();
        if self.cipher_suite().is_ctr_mode() {
            self.encrypt_aes_ctr(buffer_view, counter)
        } else {
            self.encrypt_aead(buffer_view, counter)
        }?;

        Ok(())
    }
}

impl AeadDecrypt for DecryptionKey {
    fn decrypt<'a, B>(&self, buffer: B, counter: Counter) -> Result<()>
    where
        B: Into<DecryptionBufferView<'a>>,
    {
        let buffer_view = buffer.into();
        let cipher_text = buffer_view.cipher_text;
        let cipher_suite = self.cipher_suite();
        let secret = self.secret();

        if cipher_text.len() < cipher_suite.auth_tag_len {
            return Err(SframeError::DecryptionFailure);
        }

        // TODO maybe we could store the cipher permanently, small performance gain (similar for ring)
        let cipher = cipher_suite.variant.into();

        let encrypted_len = cipher_text.len() - cipher_suite.auth_tag_len;
        let encrypted = &cipher_text[..encrypted_len];
        let tag = &cipher_text[encrypted_len..];

        let out = if cipher_suite.is_ctr_mode() {
            self.decrypt_aes_ctr(cipher, counter, buffer_view.aad, encrypted, tag)
        } else {
            let nonce = secret.create_nonce::<AES_GCM_IV_LEN>(counter);
            openssl::symm::decrypt_aead(
                cipher,
                &secret.key,
                Some(&nonce),
                buffer_view.aad,
                encrypted,
                tag,
            )
            .map_err(|err| {
                log::debug!("Decryption failed, OpenSSL error stack: {err}");
                SframeError::DecryptionFailure
            })
        }?;

        debug_assert!(
            out.len() == encrypted_len,
            "For a symmetric encryption it is given that the output has the same length as the input"
        );
        cipher_text[..encrypted_len].copy_from_slice(&out);

        Ok(())
    }
}

impl EncryptionKey {
    fn encrypt_aead(&self, buffer_view: EncryptionBufferView, counter: Counter) -> Result<()> {
        let secret = self.secret();
        let nonce = secret.create_nonce::<AES_GCM_IV_LEN>(counter);

        // TODO this allocates a new vec, maybe use the openssl cipher API direct instead of allocating
        let out = openssl::symm::encrypt_aead(
            self.cipher_suite().variant.into(),
            &secret.key,
            Some(&nonce),
            buffer_view.aad,
            buffer_view.cipher_text,
            buffer_view.tag,
        )?;
        EncryptionKey::copy_encrypted_to_buffer(buffer_view, out);

        Ok(())
    }

    fn encrypt_aes_ctr(&self, buffer_view: EncryptionBufferView, counter: Counter) -> Result<()> {
        let secret = self.secret();
        let auth_key = secret.auth.as_ref().ok_or(SframeError::EncryptionFailure)?;
        // openssl expects a fixed iv length of 16 byte, thus we needed to pad the sframe nonce
        let initial_counter = secret.create_nonce::<AES_CTR_IVS_LEN>(counter);
        let nonce = &initial_counter[..self.cipher_suite().nonce_len];

        // TODO this allocates a new vec, maybe use the openssl cipher API direct instead of allocating
        let encrypted = openssl::symm::encrypt(
            self.cipher_suite().variant.into(),
            &secret.key,
            Some(&initial_counter),
            buffer_view.cipher_text,
        )?;

        let tag = compute_tag(
            self.cipher_suite(),
            auth_key,
            buffer_view.aad,
            nonce,
            &encrypted,
        )?;
        buffer_view.tag.copy_from_slice(&tag);

        EncryptionKey::copy_encrypted_to_buffer(buffer_view, encrypted);

        Ok(())
    }

    fn copy_encrypted_to_buffer(buffer_view: EncryptionBufferView, encrypted: Vec<u8>) {
        let cipher_text_len = buffer_view.cipher_text.len();
        debug_assert!(
            encrypted.len() == cipher_text_len,
            "For a symmetric encryption it is given that the output has the same length as the input"
        );
        buffer_view
            .cipher_text
            .copy_from_slice(&encrypted[..cipher_text_len]);
    }
}

impl DecryptionKey {
    fn decrypt_aes_ctr(
        &self,
        cipher: openssl::symm::Cipher,
        counter: Counter,
        aad: &[u8],
        encrypted: &[u8],
        tag: &[u8],
    ) -> Result<Vec<u8>> {
        let secret = self.secret();
        let initial_counter: [u8; 16] = secret.create_nonce::<AES_CTR_IVS_LEN>(counter);
        let nonce = &initial_counter[..self.cipher_suite().nonce_len];
        let auth_key = secret.auth.as_ref().ok_or(SframeError::DecryptionFailure)?;

        let candidate_tag = compute_tag(self.cipher_suite(), auth_key, aad, nonce, encrypted)
            .map_err(|err| {
                log::debug!("Decryption failed, OpenSSL error stack: {err}");
                SframeError::DecryptionFailure
            })?;

        if !openssl::memcmp::eq(tag, candidate_tag.as_ref()) {
            log::debug!("Tags mismatching, discarding frame.");
            return Err(SframeError::DecryptionFailure);
        }
        openssl::symm::decrypt(cipher, &secret.key, Some(&initial_counter), encrypted).map_err(
            |err| {
                log::debug!("Decryption failed, OpenSSL error stack: {err}");
                SframeError::DecryptionFailure
            },
        )
    }
}

fn compute_tag(
    &cipher_suite: &CipherSuite,
    auth_key: &[u8],
    aad: &[u8],
    nonce: &[u8],
    encrypted: &[u8],
) -> std::result::Result<Vec<u8>, openssl::error::ErrorStack> {
    let key = openssl::pkey::PKey::hmac(auth_key)?;
    let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key)?;

    // for current platforms there is no issue casting from usize to u64
    signer.update(&(aad.len() as u64).to_be_bytes())?;
    signer.update(&(encrypted.len() as u64).to_be_bytes())?;
    signer.update(&(cipher_suite.auth_tag_len as u64).to_be_bytes())?;
    signer.update(nonce)?;
    signer.update(aad)?;
    signer.update(encrypted)?;

    let mut tag = signer.sign_to_vec()?;
    tag.resize(cipher_suite.auth_tag_len, 0);

    Ok(tag)
}

impl From<openssl::error::ErrorStack> for SframeError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        log::debug!("Encryption failed, OpenSSL error stack: {err}");
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
