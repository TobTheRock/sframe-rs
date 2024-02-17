use crate::{
    crypto::aead::AeadEncrypt,
    error::Result,
    header::{FrameCount, SframeHeader},
    key::SframeKey,
};

use super::{encrypted_frame::EncryptedFrameView, FrameBuffer};

#[derive(Debug, PartialEq, Eq)]
pub struct MediaFrameView<'buf> {
    frame_count: FrameCount,
    meta_data: &'buf [u8],
    payload: &'buf [u8],
}

impl<'ibuf> MediaFrameView<'ibuf> {
    pub fn new<F, P>(frame_count: F, payload: &'ibuf P) -> Self
    where
        F: Into<FrameCount>,
        P: AsRef<[u8]> + ?Sized,
    {
        Self::with_meta_data(frame_count, payload, &[])
    }

    pub fn with_meta_data<F, P, M>(frame_count: F, payload: &'ibuf P, meta_data: &'ibuf M) -> Self
    where
        F: Into<FrameCount>,
        P: AsRef<[u8]> + ?Sized,
        M: AsRef<[u8]> + ?Sized,
    {
        let frame_count = frame_count.into();
        let payload = payload.as_ref();
        let meta_data = meta_data.as_ref();
        log::debug!(
            "Creating MediaFrame # {} with payload size {} using meta data of size {}",
            frame_count,
            payload.len(),
            meta_data.len(),
        );
        Self {
            frame_count,
            meta_data,
            payload,
        }
    }

    pub fn meta_data(&self) -> &[u8] {
        self.meta_data
    }

    pub fn payload(&self) -> &[u8] {
        self.payload
    }

    pub fn frame_count(&self) -> FrameCount {
        self.frame_count
    }

    pub fn encrypt_into<'obuf>(
        &self,
        key: &SframeKey,
        buffer: &'obuf mut impl FrameBuffer,
    ) -> Result<EncryptedFrameView<'obuf>>
where {
        let key_id = key.key_id();
        log::trace!(
            "Encrypting MediaFrame # {} using KeyId {} and CipherSuite {} into buffer",
            self.frame_count,
            key_id,
            key.cipher_suite_variant()
        );

        let header = SframeHeader::new(key_id, self.frame_count);
        log::trace!("MediaFrame # {} using header {}", self.frame_count, header);

        let meta_len = self.meta_data.len();
        let buffer_len_needed =
            meta_len + header.len() + self.payload.len() + key.cipher_suite().auth_tag_len;

        log::trace!(
            "MediaFrame # {} trying to allocate buffer of size {}",
            self.frame_count,
            buffer_len_needed
        );
        let io_buffer = buffer.allocate(buffer_len_needed)?.as_mut();

        log::trace!("MediaFrame # {} trying to encrypt", self.frame_count,);
        self.do_encrypt(key, &header, io_buffer)?;

        let encrypted =
            EncryptedFrameView::with_header(header, &io_buffer[meta_len..], &io_buffer[..meta_len]);

        Ok(encrypted)
    }

    fn do_encrypt(
        &self,
        key: &SframeKey,
        header: &SframeHeader,
        io_buffer: &mut [u8],
    ) -> Result<()> {
        let aad_len = header.len() + self.meta_data.len();
        let (aad_buffer, encrypt_buffer) = io_buffer.split_at_mut(aad_len);

        self.fill_aad_buffer(header, aad_buffer)?;

        let (cipher_buffer, tag_buffer) = encrypt_buffer.split_at_mut(self.payload.len());
        cipher_buffer.copy_from_slice(self.payload);

        let tag = key.encrypt(cipher_buffer, &aad_buffer, self.frame_count)?;
        tag_buffer.copy_from_slice(tag.as_ref());

        Ok(())
    }

    fn fill_aad_buffer(&self, header: &SframeHeader, aad_buffer: &mut [u8]) -> Result<()> {
        let (meta_data_buffer, header_buffer) = aad_buffer.split_at_mut(self.meta_data.len());
        meta_data_buffer.copy_from_slice(self.meta_data);
        header.serialize(header_buffer)
    }
}

#[cfg(test)]
mod test {
    use crate::{frame::media_frame::MediaFrameView, key::SframeKey, CipherSuiteVariant};

    #[test]
    fn create_media_frame_with_meta_data() {
        let meta_data = [42u8, 43u8];
        let payload = vec![6u8; 3];
        let frame_count = 42u8;

        let frame_view = MediaFrameView::with_meta_data(frame_count, &payload, &meta_data);

        assert_eq!(frame_view.payload(), payload);
        assert_eq!(frame_view.frame_count(), frame_count as u64);
        assert_eq!(frame_view.meta_data(), meta_data)
    }

    #[test]
    fn encrypt_media_frame_view() {
        let frame_count = 42u64;
        let payload = vec![6; 6];
        let key_id = 666u64;
        let key =
            SframeKey::expand_from(CipherSuiteVariant::AesGcm256Sha512, key_id, "SECRET").unwrap();
        let mut encrypt_buffer = Vec::new();

        let media_frame = MediaFrameView::new(frame_count, &payload);
        let encrypted_frame = media_frame.encrypt_into(&key, &mut encrypt_buffer).unwrap();

        assert_eq!(encrypted_frame.header().key_id(), key_id);
        assert_eq!(encrypted_frame.header().frame_count(), frame_count);
        assert!(encrypted_frame.meta_data().is_empty());
        assert!(!encrypted_frame.cipher_text().is_empty());
    }
}
