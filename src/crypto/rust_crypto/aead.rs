use crate::{
    crypto::{
        aead::{AeadDecrypt, AeadEncrypt},
        secret::Secret,
    },
    error::Result,
    header::FrameCount,
    key::{DecryptionKey, EncryptionKey},
};
use aes_gcm::aead::{generic_array::GenericArray, Aead};
use aes_gcm::Aes256Gcm; // Or Aes128Gcm

use crate::{crypto::cipher_suite::CipherSuiteVariant, error::SframeError};

impl AeadEncrypt for EncryptionKey {
    type AuthTag = [u8; 16]; // GCM tag size is always 16 bytes
    fn encrypt<IoBuffer, Aad>(
        &self,
        io_buffer: &mut IoBuffer,
        aad_buffer: &Aad,
        frame_count: FrameCount,
    ) -> Result<Self::AuthTag>
    where
        IoBuffer: AsMut<[u8]> + ?Sized,
        Aad: AsRef<[u8]> + ?Sized,
    {
        todo!()
    }
}

impl AeadDecrypt for DecryptionKey {
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
        todo!()
    }
}
