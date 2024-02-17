use crate::{
    crypto::aead::AeadDecrypt,
    error::{Result, SframeError},
    frame_validation::FrameValidation,
    header::SframeHeader,
    key::KeyStore,
};

use super::{media_frame::MediaFrameView, FrameBuffer};

#[derive(Clone, Copy, Debug)]
pub struct EncryptedFrameView<'buf> {
    header: SframeHeader,
    meta_data: &'buf [u8],
    data: &'buf [u8],
}

impl<'ibuf> EncryptedFrameView<'ibuf> {
    // TODO tryfrom trait
    // maybe name deserialize, logs!
    pub fn new<D>(data: &'ibuf D) -> Result<Self>
    where
        D: AsRef<[u8]> + ?Sized,
    {
        EncryptedFrameView::with_meta_data(data, &[])
    }

    pub fn with_meta_data<D, M>(data: &'ibuf D, meta_data: &'ibuf M) -> Result<Self>
    where
        D: AsRef<[u8]> + ?Sized,
        M: AsRef<[u8]> + ?Sized,
    {
        let header = SframeHeader::deserialize(data)?;
        log::trace!(
            "EncryptedFrame # {} with header {}",
            header.frame_count(),
            header
        );

        Ok(Self {
            header,
            meta_data: meta_data.as_ref(),
            data: &data.as_ref(),
        })
    }

    pub(super) fn with_header<D, M>(
        header: SframeHeader,
        data: &'ibuf D,
        meta_data: &'ibuf M,
    ) -> Self
    where
        D: AsRef<[u8]> + ?Sized,
        M: AsRef<[u8]> + ?Sized,
    {
        Self {
            header,
            meta_data: meta_data.as_ref(),
            data: &data.as_ref(),
        }
    }

    pub fn header(&self) -> &SframeHeader {
        &self.header
    }

    pub fn meta_data(&self) -> &[u8] {
        self.meta_data
    }

    pub fn cipher_text(&self) -> &[u8] {
        &self.data[self.header.len()..]
    }

    pub fn validate(&self, validator: &impl FrameValidation) -> &Self {
        todo!()
    }

    // TODO decrypt fn

    pub fn decrypt_into<'obuf>(
        self,
        key_store: &impl KeyStore,
        buffer: &'obuf mut impl FrameBuffer,
    ) -> Result<MediaFrameView<'obuf>>
where {
        let frame_count = self.header().frame_count();
        let key_id = self.header.key_id();

        log::trace!(
            "Trying to decrypt EncryptedFrame # {} with KeyId {}",
            frame_count,
            key_id
        );

        let key = key_store
            .get_key(key_id)
            .ok_or(SframeError::MissingDecryptionKey(key_id))?;

        let (aad_buffer, io_buffer) = self.allocate_buffers(buffer)?;

        self.fill_io_buffer(io_buffer);
        self.fill_aad_buffer(aad_buffer);

        key.decrypt(io_buffer, aad_buffer, frame_count)?;

        let (payload, meta_data) =
            self.extract_payload_and_metadata(io_buffer, aad_buffer, key.cipher_suite.auth_tag_len);

        let media_frame = MediaFrameView::with_meta_data(frame_count, payload, meta_data);
        Ok(media_frame)
    }

    fn allocate_buffers<'a>(
        &self,
        buffer: &'a mut impl FrameBuffer,
    ) -> Result<(&'a mut [u8], &'a mut [u8])> {
        let meta_len = self.meta_data.len();
        let buffer_len_needed = meta_len + self.data.len();
        log::trace!(
            "EncryptedFrame # {} trying to allocate buffer of size {}",
            self.header.frame_count(),
            buffer_len_needed
        );
        let frame_buffer = buffer.allocate(buffer_len_needed)?.as_mut();

        let aad_buffer_len = self.header.len() + meta_len;
        let (aad_buffer, io_buffer) = frame_buffer.split_at_mut(aad_buffer_len);

        Ok((aad_buffer, io_buffer))
    }

    fn fill_io_buffer(&self, io_buffer: &mut [u8]) {
        let header_len = self.header.len();

        io_buffer.copy_from_slice(&self.data[header_len..]);
    }

    fn fill_aad_buffer(&self, aad_buffer: &mut [u8]) {
        let meta_len = self.meta_data.len();
        let header_len = self.header.len();

        aad_buffer[..meta_len].copy_from_slice(self.meta_data);
        aad_buffer[meta_len..].copy_from_slice(&self.data[..header_len]);
    }

    fn extract_payload_and_metadata<'obuf>(
        &self,
        io_buffer: &'obuf [u8],
        aad_buffer: &'obuf [u8],
        auth_tag_len: usize,
    ) -> (&'obuf [u8], &'obuf [u8]) {
        let payload_len = self.data.len() - auth_tag_len - self.header.len();
        let payload = &io_buffer[..payload_len];
        let meta_data = &aad_buffer[..self.meta_data.len()];

        (payload, meta_data)
    }
}

#[cfg(test)]
mod test {
    use super::EncryptedFrameView;
    use crate::header::SframeHeader;

    #[test]
    fn new_encrypted_frame_view_with_meta_data() {
        let meta_data = [42u8, 43u8];
        let header = SframeHeader::new(42, 666);
        let header_buf = Vec::from(&header);
        let cipher_text = vec![6u8; 3];
        let data = [header_buf.clone(), cipher_text.clone()].concat();

        let frame_view = EncryptedFrameView::with_meta_data(&data, &meta_data).unwrap();

        assert_eq!(frame_view.header(), &header);
        assert_eq!(frame_view.cipher_text(), &cipher_text);
        assert_eq!(frame_view.meta_data(), meta_data)
    }
}
