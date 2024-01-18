use crate::{
    crypto::aead::{AeadDecrypt, AeadEncrypt},
    error::Result,
    header::FrameCount,
};

use ring::aead::{BoundKey, SealingKey, Tag};

use crate::{
    crypto::{cipher_suite::CipherSuiteVariant, secret::Secret},
    error::SframeError,
};

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

impl From<CipherSuiteVariant> for &'static ring::aead::Algorithm {
    fn from(variant: CipherSuiteVariant) -> Self {
        use CipherSuiteVariant::*;
        match variant {
            AesGcm128Sha256 => &ring::aead::AES_128_GCM,
            AesGcm256Sha512 => &ring::aead::AES_256_GCM,
        }
    }
}

impl Secret {
    fn unbound_encryption_key(&self) -> Result<ring::aead::UnboundKey> {
        let algorithm = self.cipher_suite.variant.into();
        ring::aead::UnboundKey::new(algorithm, self.key.as_slice())
            .map_err(|_| SframeError::KeyDerivation)
    }
}

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
        let mut sealing_key = SealingKey::<FrameNonceSequence>::new(
            self.unbound_encryption_key()?,
            self.create_nonce(frame_count).into(),
        );

        let aad = ring::aead::Aad::from(aad_buffer);
        let auth_tag = sealing_key
            .seal_in_place_separate_tag(aad, io_buffer.as_mut())
            .map_err(|_| SframeError::EncryptionFailure)?;

        // TODO implement auth tag shortening, see 4.4.1

        Ok(auth_tag)
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
        let aad = ring::aead::Aad::from(&aad_buffer);

        let mut opening_key = ring::aead::OpeningKey::<FrameNonceSequence>::new(
            self.unbound_encryption_key()?,
            self.create_nonce(frame_count).into(),
        );
        opening_key
            .open_in_place(aad, io_buffer.as_mut())
            .map_err(|_| SframeError::DecryptionFailure)
    }
}
