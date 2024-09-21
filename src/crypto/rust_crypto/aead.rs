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
    consts::{U12, U16, U4}, generic_array::GenericArray, typenum::Sum, ArrayLength, BlockCipher, BlockEncryptMut, KeyInit, KeySizeUser, StreamCipher, Unsigned
};
use ctr::Ctr32BE;
use sha2::{digest::OutputSizeUser, Digest, Sha256};

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
            CipherSuiteVariant::AesCtr128HmacSha256_32 => self
                .encrypt_in_place_detached::<AesCtr128Hmac<U4>, { AesCtr128Hmac::<U4>::NONCE_LEN }>(
                    frame_count,
                    buffer_view,
                ),
            _ => todo!(),
        }
        .map_err(|err| {
            log::debug!("Encryption failed: {}", err);
            SframeError::EncryptionFailure
        })
    }
}

impl EncryptionKey {
    fn encrypt_in_place_detached<'a, A, const NONCE_LEN: usize>(
        &'a self,
        frame_count: FrameCount,
        buffer_view: EncryptionBufferView,
        // TODO use sframe error
    ) -> std::result::Result<(), aes_gcm::Error>
    where
        A: InitFromSecret<'a> + AeadInPlace + AeadCore,
    {
        let secret = self.secret();
        let nonce: [u8; NONCE_LEN] = secret.create_nonce(frame_count);
        let algo = A::from_secret(secret).map_err(|_err| aes_gcm::Error)?;

        let tag = algo.encrypt_in_place_detached(
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
        // TODO custom initializer here
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

// TODO util trait mod

trait NonceLen {
    const NONCE_LEN: usize;
}

impl<A> NonceLen for A
where
    A: AeadCore,
{
    const NONCE_LEN: usize = <A::NonceSize as Unsigned>::USIZE;
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

// pub trait Cipher: BlockEncryptMut + BlockCipher<BlockSize = U16> + KeySizeUser + KeyInit {}
// impl<T> Cipher for T where T: BlockEncryptMut + BlockCipher<BlockSize = U16> + KeySizeUser + KeyInit {}
// trait CipherSuite {
//     type Cipher: Cipher;
//     type Digest: Digest;
//     type TagSize: ArrayLength<u8>;
// }

struct AesCtr128Hmac<'a, T>
where
    T: ArrayLength<u8>,
{
    cipher: Ctr32BE<Aes128>,
    auth: &'a [u8],

    _phantom: core::marker::PhantomData<T>,
}

// impl<T> NonceLen for AesCtr128Hmac<'_, T>
// where
//     T: ArrayLength<u8>,
// {
//     const NONCE_LEN: usize = 12;
// }

// impl<T> CipherSuite for AesCtr128Hmac<T>
// where
//     T: ArrayLength<u8>,
// {
//     type Cipher = Aes128;
//     type Digest = Sha256;
//     type TagSize = T;
// }

impl<T> AeadCore for AesCtr128Hmac<'_, T>
where
    T: ArrayLength<u8>,
{
    type NonceSize = U12;
    type TagSize = T;
    type CiphertextOverhead = T;
}

impl<'a, 'b, T> InitFromSecret<'a> for AesCtr128Hmac<'b, T>
where
    T: ArrayLength<u8>,
    'a: 'b,
{
    fn from_secret(secret: &'b Secret) -> Result<Self> {
        let cipher = Ctr32BE::<Aes128>::new(&secret.key)
            .map_err(|err| SframeError::Other(err.to_string()))?;
        let auth = secret
            .auth
            .as_ref()
            .ok_or(SframeError::Other("Auth not found".to_string()))?;

        Ok(Self {
            auth,
            cipher,
            _phantom: std::marker::PhantomData,
        })
    }
}

// impl<T: ArrayLength<u8>> KeySizeUser for AesCtr128Hmac<T> {
//     type KeySize = Sum<<Aes128 as KeySizeUser>::KeySize, <Sha256 as OutputSizeUser>::OutputSize>;
// }

// impl<T> KeyInit for AesCtr128Hmac<T>
// where
//     T: ArrayLength<u8>,
//     AesCtr128Hmac<T>: KeySizeUser,
// {
//     fn new(key: &cipher::Key<Self>) -> Self {
//         todo!()
//     }
// }

impl<T> AeadInPlace for AesCtr128Hmac<'_, T>
where
    T: ArrayLength<u8>,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> std::result::Result<GenericArray<u8, T>, aes_gcm::Error> {
        self.cipher.try_apply_keystream(buffer)
        let tag = self
            .cipher
            .encrypt_in_place_detached(nonce, associated_data, buffer)?;
        todo!()
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, Self::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, Self::TagSize>,
    ) -> std::result::Result<(), aes_gcm::Error> {
        todo!()
    }
}
