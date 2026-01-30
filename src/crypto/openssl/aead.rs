//! AEAD implementation for OpenSSL backend.

use super::Aead;
use crate::{
    crypto::{
        aead::{AeadDecrypt, AeadEncrypt},
        buffer::{DecryptionBufferView, EncryptionBufferView},
        cipher_suite::CipherSuite,
        secret::Secret,
    },
    error::{Result, SframeError},
    header::Counter,
};

const AES_GCM_IV_LEN: usize = 12;
const AES_CTR_IVS_LEN: usize = 16;

/// Performs in-place encryption/decryption using OpenSSL's Crypter.
///
/// # Safety
/// OpenSSL's `EVP_CipherUpdate` explicitly supports in-place operations:
/// "The pointers out and in may point to the same location, in which case the
/// encryption will be done in-place."
/// See: <https://manpages.debian.org/experimental/libssl-doc/EVP_EncryptUpdate.3ssl.en.html>
///
/// The buffer must be valid for `buffer.len()` bytes and we process it in a single call.
fn update_inplace(
    crypter: &mut openssl::symm::Crypter,
    buffer: &mut [u8],
) -> std::result::Result<usize, openssl::error::ErrorStack> {
    let len = buffer.len();
    let ptr = buffer.as_mut_ptr();
    // SAFETY: See function documentation above.
    let input = unsafe { std::slice::from_raw_parts(ptr, len) };
    crypter.update(input, buffer)
}

impl AeadEncrypt for Aead {
    fn encrypt<'a, B>(&self, secret: &Secret, buffer: B, counter: Counter) -> Result<()>
    where
        B: Into<EncryptionBufferView<'a>>,
    {
        let buffer_view = buffer.into();

        if self.cipher_suite.is_ctr_mode() {
            encrypt_aes_ctr(self.cipher_suite, secret, buffer_view, counter)
        } else {
            encrypt_aead(self.cipher_suite, secret, buffer_view, counter)
        }?;

        Ok(())
    }
}

impl AeadDecrypt for Aead {
    fn decrypt<'a, B>(&self, secret: &Secret, buffer: B, counter: Counter) -> Result<()>
    where
        B: Into<DecryptionBufferView<'a>>,
    {
        let buffer_view = buffer.into();
        let cipher_text = buffer_view.cipher_text;

        if cipher_text.len() < self.cipher_suite.auth_tag_len() {
            return Err(SframeError::DecryptionFailure);
        }

        let cipher = self.cipher_suite.into();
        let encrypted_len = cipher_text.len() - self.cipher_suite.auth_tag_len();

        if self.cipher_suite.is_ctr_mode() {
            let (encrypted, tag) = cipher_text.split_at_mut(encrypted_len);
            decrypt_aes_ctr_inplace(
                self.cipher_suite,
                secret,
                cipher,
                counter,
                buffer_view.aad,
                encrypted,
                tag,
            )?;
        } else {
            decrypt_aead_inplace(
                secret,
                cipher,
                counter,
                buffer_view.aad,
                cipher_text,
                encrypted_len,
            )?;
        }

        Ok(())
    }
}

fn encrypt_aead(
    cipher_suite: CipherSuite,
    secret: &Secret,
    buffer_view: EncryptionBufferView,
    counter: Counter,
) -> Result<()> {
    let nonce = secret.create_nonce::<AES_GCM_IV_LEN>(counter);
    let cipher: openssl::symm::Cipher = cipher_suite.into();

    let mut crypter = openssl::symm::Crypter::new(
        cipher,
        openssl::symm::Mode::Encrypt,
        &secret.key,
        Some(&nonce),
    )?;

    crypter.aad_update(buffer_view.aad)?;

    let plaintext_len = buffer_view.cipher_text.len();
    let encrypted_len = update_inplace(&mut crypter, buffer_view.cipher_text)?;
    let final_len = crypter.finalize(&mut buffer_view.cipher_text[encrypted_len..])?;

    debug_assert!(
        encrypted_len + final_len == plaintext_len,
        "For a symmetric encryption it is given that the output has the same length as the input"
    );

    crypter.get_tag(buffer_view.tag)?;

    Ok(())
}

fn encrypt_aes_ctr(
    cipher_suite: CipherSuite,
    secret: &Secret,
    buffer_view: EncryptionBufferView,
    counter: Counter,
) -> Result<()> {
    let auth_key = secret.auth.as_ref().ok_or(SframeError::EncryptionFailure)?;
    let cipher: openssl::symm::Cipher = cipher_suite.into();
    // openssl expects a fixed iv length of 16 byte, thus we needed to pad the sframe nonce
    let initial_counter = secret.create_nonce::<AES_CTR_IVS_LEN>(counter);
    let nonce = &initial_counter[..cipher_suite.nonce_len()];

    let mut crypter = openssl::symm::Crypter::new(
        cipher,
        openssl::symm::Mode::Encrypt,
        &secret.key,
        Some(&initial_counter),
    )?;

    let plaintext_len = buffer_view.cipher_text.len();
    let encrypted_len = update_inplace(&mut crypter, buffer_view.cipher_text)?;
    let final_len = crypter.finalize(&mut buffer_view.cipher_text[encrypted_len..])?;

    debug_assert!(
        encrypted_len + final_len == plaintext_len,
        "For a symmetric encryption it is given that the output has the same length as the input"
    );

    let tag = compute_tag(
        cipher_suite,
        auth_key,
        buffer_view.aad,
        nonce,
        buffer_view.cipher_text,
    )?;
    buffer_view.tag.copy_from_slice(&tag);

    Ok(())
}

fn decrypt_aead_inplace(
    secret: &Secret,
    cipher: openssl::symm::Cipher,
    counter: Counter,
    aad: &[u8],
    cipher_text: &mut [u8],
    encrypted_len: usize,
) -> Result<()> {
    let nonce = secret.create_nonce::<AES_GCM_IV_LEN>(counter);

    let mut crypter = openssl::symm::Crypter::new(
        cipher,
        openssl::symm::Mode::Decrypt,
        &secret.key,
        Some(&nonce),
    )
    .map_err(|err| {
        log::debug!("Decryption failed, OpenSSL error stack: {err}");
        SframeError::DecryptionFailure
    })?;

    crypter.aad_update(aad).map_err(|err| {
        log::debug!("Decryption failed, OpenSSL error stack: {err}");
        SframeError::DecryptionFailure
    })?;

    // Set the authentication tag before decryption
    crypter
        .set_tag(&cipher_text[encrypted_len..])
        .map_err(|err| {
            log::debug!("Decryption failed, OpenSSL error stack: {err}");
            SframeError::DecryptionFailure
        })?;

    let decrypted_len = update_inplace(&mut crypter, &mut cipher_text[..encrypted_len]).map_err(
        |err| {
            log::debug!("Decryption failed, OpenSSL error stack: {err}");
            SframeError::DecryptionFailure
        },
    )?;

    let final_len = crypter
        .finalize(&mut cipher_text[decrypted_len..encrypted_len])
        .map_err(|err| {
            log::debug!("Decryption failed, OpenSSL error stack: {err}");
            SframeError::DecryptionFailure
        })?;

    debug_assert!(
        decrypted_len + final_len == encrypted_len,
        "For a symmetric encryption it is given that the output has the same length as the input"
    );

    Ok(())
}

fn decrypt_aes_ctr_inplace(
    cipher_suite: CipherSuite,
    secret: &Secret,
    cipher: openssl::symm::Cipher,
    counter: Counter,
    aad: &[u8],
    encrypted: &mut [u8],
    tag: &[u8],
) -> Result<()> {
    let initial_counter: [u8; 16] = secret.create_nonce::<AES_CTR_IVS_LEN>(counter);
    let nonce = &initial_counter[..cipher_suite.nonce_len()];
    let auth_key = secret.auth.as_ref().ok_or(SframeError::DecryptionFailure)?;

    let candidate_tag = compute_tag(cipher_suite, auth_key, aad, nonce, encrypted).map_err(
        |err| {
            log::debug!("Decryption failed, OpenSSL error stack: {err}");
            SframeError::DecryptionFailure
        },
    )?;

    if !openssl::memcmp::eq(tag, candidate_tag.as_ref()) {
        log::debug!("Tags mismatching, discarding frame.");
        return Err(SframeError::DecryptionFailure);
    }

    let mut crypter = openssl::symm::Crypter::new(
        cipher,
        openssl::symm::Mode::Decrypt,
        &secret.key,
        Some(&initial_counter),
    )
    .map_err(|err| {
        log::debug!("Decryption failed, OpenSSL error stack: {err}");
        SframeError::DecryptionFailure
    })?;

    let encrypted_len = encrypted.len();
    let decrypted_len = update_inplace(&mut crypter, encrypted).map_err(|err| {
        log::debug!("Decryption failed, OpenSSL error stack: {err}");
        SframeError::DecryptionFailure
    })?;

    let final_len = crypter
        .finalize(&mut encrypted[decrypted_len..])
        .map_err(|err| {
            log::debug!("Decryption failed, OpenSSL error stack: {err}");
            SframeError::DecryptionFailure
        })?;

    debug_assert!(
        decrypted_len + final_len == encrypted_len,
        "For a symmetric decryption it is given that the output has the same length as the input"
    );

    Ok(())
}

fn compute_tag(
    cipher_suite: CipherSuite,
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
    signer.update(&(cipher_suite.auth_tag_len() as u64).to_be_bytes())?;
    signer.update(nonce)?;
    signer.update(aad)?;
    signer.update(encrypted)?;

    let mut tag = signer.sign_to_vec()?;
    tag.resize(cipher_suite.auth_tag_len(), 0);

    Ok(tag)
}

impl From<openssl::error::ErrorStack> for SframeError {
    fn from(err: openssl::error::ErrorStack) -> Self {
        log::debug!("Encryption failed, OpenSSL error stack: {err}");
        SframeError::EncryptionFailure
    }
}

impl From<CipherSuite> for openssl::symm::Cipher {
    fn from(cipher_suite: CipherSuite) -> Self {
        match cipher_suite {
            CipherSuite::AesCtr128HmacSha256_80
            | CipherSuite::AesCtr128HmacSha256_64
            | CipherSuite::AesCtr128HmacSha256_32 => openssl::symm::Cipher::aes_128_ctr(),
            CipherSuite::AesGcm128Sha256 => openssl::symm::Cipher::aes_128_gcm(),
            CipherSuite::AesGcm256Sha512 => openssl::symm::Cipher::aes_256_gcm(),
        }
    }
}
