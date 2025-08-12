use crate::{
    crypto::{
        aead::{AeadDecrypt, AeadEncrypt},
        buffer::{decryption::DecryptionBufferView, encryption::EncryptionBufferView},
        secret::Secret,
    },
    error::Result,
    header::Counter,
    key::{DecryptionKey, EncryptionKey},
};

use ring::aead::{BoundKey, SealingKey};

use crate::{crypto::cipher_suite::CipherSuite, error::SframeError};

struct FrameNonceSequence {
    buffer: [u8; ring::aead::NONCE_LEN],
}

impl From<[u8; ring::aead::NONCE_LEN]> for FrameNonceSequence {
    fn from(buffer: [u8; ring::aead::NONCE_LEN]) -> Self {
        Self { buffer }
    }
}

impl ring::aead::NonceSequence for FrameNonceSequence {
    fn advance(&mut self) -> std::result::Result<ring::aead::Nonce, ring::error::Unspecified> {
        let nonce = ring::aead::Nonce::assume_unique_for_key(std::mem::take(&mut self.buffer));
        Ok(nonce)
    }
}

impl From<CipherSuite> for &'static ring::aead::Algorithm {
    fn from(cipher_suite: CipherSuite) -> Self {
        use CipherSuite::*;
        match cipher_suite {
            AesGcm128Sha256 => &ring::aead::AES_128_GCM,
            AesGcm256Sha512 => &ring::aead::AES_256_GCM,
        }
    }
}

fn unbound_encryption_key(
    cipher_suite: CipherSuite,
    secret: &Secret,
) -> Result<ring::aead::UnboundKey> {
    let algorithm = cipher_suite.into();
    ring::aead::UnboundKey::new(algorithm, secret.key.as_slice())
        .map_err(|_| SframeError::KeyDerivationFailure)
}

impl AeadEncrypt for EncryptionKey {
    fn encrypt<'a, B>(&self, buffer: B, counter: Counter) -> Result<()>
    where
        B: Into<EncryptionBufferView<'a>>,
    {
        let buffer_view: EncryptionBufferView = buffer.into();
        let mut sealing_key = SealingKey::<FrameNonceSequence>::new(
            unbound_encryption_key(self.cipher_suite(), self.secret())?,
            self.secret().create_nonce(counter).into(),
        );

        let aad = ring::aead::Aad::from(buffer_view.aad);
        let auth_tag = sealing_key
            .seal_in_place_separate_tag(aad, buffer_view.cipher_text)
            .map_err(|_| SframeError::EncryptionFailure)?;

        buffer_view.tag.copy_from_slice(auth_tag.as_ref());

        // TODO implement auth tag shortening, see 4.4.1

        Ok(())
    }
}

impl AeadDecrypt for DecryptionKey {
    fn decrypt<'a, B>(&self, buffer: B, counter: Counter) -> Result<()>
    where
        B: Into<DecryptionBufferView<'a>>,
    {
        let buffer_view: DecryptionBufferView = buffer.into();
        let aad = ring::aead::Aad::from(buffer_view.aad);

        let mut opening_key = ring::aead::OpeningKey::<FrameNonceSequence>::new(
            unbound_encryption_key(self.cipher_suite(), self.secret())?,
            self.secret().create_nonce(counter).into(),
        );
        opening_key
            .open_in_place(aad, buffer_view.cipher_text)
            .map_err(|_| SframeError::DecryptionFailure)?;
        Ok(())
    }
}
