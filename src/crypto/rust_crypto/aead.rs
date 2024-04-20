use crate::{
    crypto::{
        aead::{AeadDecrypt, AeadEncrypt},
        buffer::{decryption::DecryptionBufferView, encryption::EncryptionBufferView},
    },
    error::Result,
    header::FrameCount,
    key::{DecryptionKey, EncryptionKey},
};
use aes_gcm::{AeadCore, AeadInPlace};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use cipher::{generic_array::GenericArray, KeyInit, Unsigned};

use crate::{crypto::cipher_suite::CipherSuiteVariant, error::SframeError};

impl AeadEncrypt for EncryptionKey {
    fn encrypt<'a, B>(&self, buffer: B, frame_count: FrameCount) -> Result<()>
    where
        B: Into<EncryptionBufferView<'a>>,
    {
        let buffer_view = buffer.into();
        match self.cipher_suite().variant {
            CipherSuiteVariant::AesGcm256Sha512 => self
                .encrypt_in_place_detached::<Aes256Gcm, { Aes256Gcm::NONCE_LEN }>(
                    frame_count,
                    buffer_view,
                ),
            CipherSuiteVariant::AesGcm128Sha256 => self
                .encrypt_in_place_detached::<Aes128Gcm, { Aes128Gcm::NONCE_LEN }>(
                    frame_count,
                    buffer_view,
                ),
            _ => todo!(),
        }
        .map_err(|err| {
            log::debug!("Encryption failed: {}", err);
            SframeError::EncryptionFailure
        })
        // const NONCE_LEN = Aes256Gcm::;
    }
}

trait NonceLen {
    const NONCE_LEN: usize;
}

impl<A> NonceLen for A
where
    A: AeadCore,
{
    const NONCE_LEN: usize = <A::NonceSize as Unsigned>::USIZE;
}

impl EncryptionKey {
    fn encrypt_in_place_detached<A, const NONCE_LEN: usize>(
        &self,
        frame_count: FrameCount,
        buffer_view: EncryptionBufferView,
    ) -> std::result::Result<(), aes_gcm::Error>
    where
        A: KeyInit + AeadInPlace + AeadCore,
    {
        let secret = self.secret();
        let nonce: [u8; NONCE_LEN] = secret.create_nonce(frame_count);
        let algo = A::new_from_slice(&secret.key).map_err(|_err| aes_gcm::Error)?;

        let tag = algo
            .encrypt_in_place_detached(
                GenericArray::from_slice(&nonce),
                buffer_view.aad,
                buffer_view.cipher_text,
            )?;
        buffer_view.tag.copy_from_slice(tag.as_slice());

        Ok(())
    }
}

impl AeadDecrypt for DecryptionKey {
    fn decrypt<'a, B>(&self, buffer: B, frame_count: FrameCount) -> Result<()>
    where
        B: Into<DecryptionBufferView<'a>>,
    {
        let buffer_view = buffer.into();
        match self.cipher_suite().variant {
            CipherSuiteVariant::AesGcm256Sha512 => self
                .decrypt_in_place_detached::<Aes256Gcm, { Aes256Gcm::NONCE_LEN }>(
                    frame_count,
                    buffer_view,
                ),
            CipherSuiteVariant::AesGcm128Sha256 => self
                .decrypt_in_place_detached::<Aes128Gcm, { Aes128Gcm::NONCE_LEN }>(
                    frame_count,
                    buffer_view,
                ),
            _ => todo!(),
        }
        .map_err(|err| {
            log::debug!("Decryption failed: {}", err);
            SframeError::DecryptionFailure
        })
    }
}

impl DecryptionKey {
    fn decrypt_in_place_detached<A, const NONCE_LEN: usize>(
        &self,
        frame_count: FrameCount,
        buffer_view: DecryptionBufferView,
    ) -> std::result::Result<(), aes_gcm::Error>
    where
        A: KeyInit + AeadInPlace + AeadCore,
    {
        let cipher_suite = self.cipher_suite();
        let cipher_text = buffer_view.cipher_text;
        if cipher_text.len() < cipher_suite.auth_tag_len {
            return Err(aes_gcm::Error);
        }
        let encrypted_len = cipher_text.len() - cipher_suite.auth_tag_len;
        let (encrypted, tag) = cipher_text.split_at_mut(encrypted_len);

        let secret = self.secret();
        let nonce: [u8; NONCE_LEN] = secret.create_nonce(frame_count);
        let algo = A::new_from_slice(&secret.key).map_err(|_err| aes_gcm::Error)?;

        algo.decrypt_in_place_detached(
            GenericArray::from_slice(&nonce),
            buffer_view.aad,
            encrypted,
            GenericArray::from_slice(tag),
        )?;

        Ok(())
    }
}
