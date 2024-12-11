use crate::{
    crypto::{
        aead::{AeadDecrypt, AeadEncrypt},
        buffer::{decryption::DecryptionBufferView, encryption::EncryptionBufferView},
        secret::Secret,
    },
    error::Result,
    header::FrameCount,
    key::{DecryptionKey, EncryptionKey},
};
use aes_gcm::{aes::Aes128, AeadCore, AeadInPlace, Aes128Gcm, Aes256Gcm};
use cipher::{
    consts::{U10, U4, U8},
    generic_array::GenericArray,
    ArrayLength, IvSizeUser, KeyInit, KeyIvInit, StreamCipher, Unsigned,
};
use ctr::Ctr32BE;
use hkdf::hmac::{Mac, SimpleHmac};
use sha2::digest::Update;
use sha2::Sha256;

use crate::{crypto::cipher_suite::CipherSuiteVariant, error::SframeError};

impl AeadEncrypt for EncryptionKey {
    fn encrypt<'a, B>(&self, buffer: B, frame_count: FrameCount) -> Result<()>
    where
        B: Into<EncryptionBufferView<'a>>,
    {
        let buffer_view = buffer.into();
        match self.cipher_suite().variant {
            CipherSuiteVariant::AesGcm256Sha512 => self
                .encrypt_in_place_detached::<Aes256Gcm, { Aes256Gcm::IV_LEN }>(
                    frame_count,
                    buffer_view,
                ),
            CipherSuiteVariant::AesGcm128Sha256 => self
                .encrypt_in_place_detached::<Aes128Gcm, { Aes128Gcm::IV_LEN }>(
                    frame_count,
                    buffer_view,
                ),
            CipherSuiteVariant::AesCtr128HmacSha256_32 => self
                .encrypt_in_place_detached::<AesCtr128Hmac<U4>, { AesCtr128Hmac::<U4>::IV_LEN }>(
                    frame_count,
                    buffer_view,
                ),
            CipherSuiteVariant::AesCtr128HmacSha256_64 => self
                .encrypt_in_place_detached::<AesCtr128Hmac<U8>, { AesCtr128Hmac::<U8>::IV_LEN }>(
                    frame_count,
                    buffer_view,
                ),
            CipherSuiteVariant::AesCtr128HmacSha256_80 => self
                .encrypt_in_place_detached::<AesCtr128Hmac<U10>, { AesCtr128Hmac::<U10>::IV_LEN }>(
                    frame_count,
                    buffer_view,
                ),
        }
    }
}

impl EncryptionKey {
    fn encrypt_in_place_detached<'a, A, const NONCE_LEN: usize>(
        &'a self,
        frame_count: FrameCount,
        buffer_view: EncryptionBufferView,
    ) -> Result<()>
    where
        A: InitFromSecret<'a> + AeadInPlace + AeadCore + IvLen,
    {
        let secret = self.secret();
        let nonce: [u8; NONCE_LEN] = secret.create_nonce(frame_count);
        let algo = A::from_secret(secret)?;
        let tag = algo
            .encrypt_in_place_detached(
                GenericArray::from_slice(&nonce),
                buffer_view.aad,
                buffer_view.cipher_text,
            )
            .map_err(|err| {
                log::debug!("Encryption failed: {}", err);
                SframeError::EncryptionFailure
            })?;
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
                .decrypt_in_place_detached::<Aes256Gcm, { Aes256Gcm::IV_LEN }>(
                    frame_count,
                    buffer_view,
                ),
            CipherSuiteVariant::AesGcm128Sha256 => self
                .decrypt_in_place_detached::<Aes128Gcm, { Aes128Gcm::IV_LEN }>(
                    frame_count,
                    buffer_view,
                ),
            CipherSuiteVariant::AesCtr128HmacSha256_80 => self
                .decrypt_in_place_detached::<AesCtr128Hmac<U10>, { AesCtr128Hmac::<U10>::IV_LEN }>(
                    frame_count,
                    buffer_view,
                ),
            CipherSuiteVariant::AesCtr128HmacSha256_64 => self
                .decrypt_in_place_detached::<AesCtr128Hmac<U8>, { AesCtr128Hmac::<U8>::IV_LEN }>(
                    frame_count,
                    buffer_view,
                ),
            CipherSuiteVariant::AesCtr128HmacSha256_32 => self
                .decrypt_in_place_detached::<AesCtr128Hmac<U4>, { AesCtr128Hmac::<U4>::IV_LEN }>(
                    frame_count,
                    buffer_view,
                ),
        }
    }
}

impl DecryptionKey {
    fn decrypt_in_place_detached<'a, A, const IV_LEN: usize>(
        &'a self,
        frame_count: FrameCount,
        buffer_view: DecryptionBufferView,
    ) -> Result<()>
    where
        A: AeadInPlace + AeadCore + InitFromSecret<'a>,
    {
        let cipher_suite = self.cipher_suite();
        let cipher_text = buffer_view.cipher_text;
        if cipher_text.len() < cipher_suite.auth_tag_len {
            return Err(SframeError::DecryptionFailure);
        }
        let encrypted_len = cipher_text.len() - cipher_suite.auth_tag_len;
        let (encrypted, tag) = cipher_text.split_at_mut(encrypted_len);

        let secret = self.secret();
        let nonce: [u8; IV_LEN] = secret.create_nonce(frame_count);
        let algo = A::from_secret(secret)?;

        algo.decrypt_in_place_detached(
            GenericArray::from_slice(&nonce),
            buffer_view.aad,
            encrypted,
            GenericArray::from_slice(tag),
        )
        .map_err(|err| {
            log::debug!("Decryption failed: {}", err);
            SframeError::DecryptionFailure
        })?;

        Ok(())
    }
}

trait IvLen {
    const IV_LEN: usize;
}

impl<A> IvLen for A
where
    A: AeadCore,
{
    const IV_LEN: usize = <A::NonceSize as Unsigned>::USIZE;
}

trait InitFromSecret<'a> {
    fn from_secret(secret: &'a Secret) -> Result<Self>
    where
        Self: Sized;
}

impl<'a, A> InitFromSecret<'a> for A
where
    A: KeyInit,
{
    fn from_secret(secret: &'a Secret) -> Result<Self> {
        let key = secret.key.as_slice();
        let algo = A::new_from_slice(key).map_err(|err| SframeError::Other(err.to_string()))?;
        Ok(algo)
    }
}

struct AesCtr128Hmac<'a, T>
where
    T: ArrayLength<u8>,
{
    key: &'a [u8],
    auth_key: &'a [u8],
    _phantom: core::marker::PhantomData<T>,
}

impl<T> AeadCore for AesCtr128Hmac<'_, T>
where
    T: ArrayLength<u8>,
{
    // This is larger than the sframe spec, we need padding therefore
    type NonceSize = <Ctr32BE<Aes128> as IvSizeUser>::IvSize;
    type TagSize = T;
    type CiphertextOverhead = T;
}

impl<'a, 'b, T> InitFromSecret<'a> for AesCtr128Hmac<'b, T>
where
    T: ArrayLength<u8>,
    'a: 'b,
{
    fn from_secret(secret: &'b Secret) -> Result<Self> {
        let key = &secret.key;
        let auth_key = secret.auth.as_ref().expect("HMAC auth key not found");

        Ok(Self {
            key,
            auth_key,
            _phantom: std::marker::PhantomData,
        })
    }
}

impl<T> AesCtr128Hmac<'_, T>
where
    T: ArrayLength<u8>,
{
    fn compute_tag(&self, iv: &[u8], aad: &[u8], ct: &[u8]) -> SimpleHmac<Sha256> {
        // TODO generalize this, is given by CipherSuite
        const NONCE_LEN: usize = 12;
        let nonce = &iv[0..NONCE_LEN];

        let aad_len_u64: u64 = aad.len().try_into().unwrap();
        let ct_len_u64: u64 = ct.len().try_into().unwrap();

        let aad_len = aad_len_u64.to_be_bytes();
        let ct_len = ct_len_u64.to_be_bytes();
        let tag_len = T::to_u64().to_be_bytes();

        let h = <SimpleHmac<Sha256> as Mac>::new_from_slice(self.auth_key).expect("Invalid key");
        h.chain(aad_len)
            .chain(ct_len)
            .chain(tag_len)
            .chain(nonce)
            .chain(aad)
            .chain(ct)
    }

    fn cipher(
        &self,
        iv: &[u8],
        buffer: &mut [u8],
    ) -> std::result::Result<(), cipher::StreamCipherError> {
        let mut cipher =
            Ctr32BE::<Aes128>::new_from_slices(self.key, iv).expect("Invalid key or IV length");
        cipher.try_apply_keystream(buffer)
    }
}

impl<T> AeadInPlace for AesCtr128Hmac<'_, T>
where
    T: ArrayLength<u8>,
{
    fn encrypt_in_place_detached(
        &self,
        iv: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> std::result::Result<GenericArray<u8, Self::TagSize>, aes_gcm::Error> {
        self.cipher(iv, buffer).map_err(|err| {
            log::debug!("AesCtr: Error encrypting: {}", err);
            aes_gcm::Error
        })?;

        let long_tag = self
            .compute_tag(iv, associated_data, buffer)
            .finalize()
            .into_bytes();

        let tag_len = T::to_usize();
        let tag = &long_tag[0..tag_len];
        Ok(GenericArray::clone_from_slice(tag))
    }

    fn decrypt_in_place_detached(
        &self,
        iv: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, Self::TagSize>,
    ) -> std::result::Result<(), aes_gcm::Error> {
        let tag_len = T::to_usize();
        if buffer.len() < tag_len {
            log::debug!("Invalid cipher text, shorter than tag");
            return Err(aes_gcm::Error);
        }

        self.compute_tag(iv, associated_data, buffer)
            .verify_truncated_left(tag)
            .map_err(|err| {
                log::debug!("AesCtr: Error decrypting: {}", err);
                aes_gcm::Error
            })?;

        self.cipher(iv, buffer).map_err(|err| {
            log::debug!("AesCtr: Error encrypting: {}", err);
            aes_gcm::Error
        })
    }
}
