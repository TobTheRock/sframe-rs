use crate::{
    crypto::aead::AeadDecrypt,
    error::{Result, SframeError},
    frame_validation::FrameValidation,
    header::SframeHeader,
    key::KeyStore,
};

use super::{
    media_frame::{MediaFrame, MediaFrameView},
    FrameBuffer,
};

#[derive(Clone, Copy, Debug)]
pub struct EncryptedFrameView<'buf> {
    header: SframeHeader,
    meta_data: &'buf [u8],
    data: &'buf [u8],
}

impl<'ibuf> EncryptedFrameView<'ibuf> {
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
            data: data.as_ref(),
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
            data: data.as_ref(),
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

    pub fn validate(self, validator: &impl FrameValidation) -> Result<Self> {
        validator.validate(&self.header)?;

        Ok(self)
    }

    pub fn decrypt(&self, key_store: &impl KeyStore) -> Result<MediaFrame> {
        let mut buffer = Vec::new();
        let view = self.decrypt_into(key_store, &mut buffer)?;

        Ok(MediaFrame::with_meta_data(
            view.frame_count(),
            view.payload(),
            view.meta_data(),
        ))
    }

    pub fn decrypt_into<'obuf>(
        &self,
        key_store: &impl KeyStore,
        buffer: &'obuf mut impl FrameBuffer,
    ) -> Result<MediaFrameView<'obuf>> {
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

        let (payload, meta_data) = self.extract_payload_and_metadata(
            io_buffer,
            aad_buffer,
            key.cipher_suite().auth_tag_len,
        );

        let media_frame = MediaFrameView::with_meta_data(frame_count, payload, meta_data);
        Ok(media_frame)
    }

    fn allocate_buffers<'obuf>(
        &self,
        buffer: &'obuf mut impl FrameBuffer,
    ) -> Result<(&'obuf mut [u8], &'obuf mut [u8])> {
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

impl<'buf> TryFrom<&'buf [u8]> for EncryptedFrameView<'buf> {
    type Error = SframeError;

    fn try_from(data: &'buf [u8]) -> Result<Self> {
        EncryptedFrameView::with_meta_data(data, &[])
    }
}

impl<'buf> TryFrom<&'buf Vec<u8>> for EncryptedFrameView<'buf> {
    type Error = SframeError;

    fn try_from(data: &'buf Vec<u8>) -> Result<Self> {
        EncryptedFrameView::with_meta_data(data, &[])
    }
}

pub struct EncryptedFrame {
    buffer: Vec<u8>,
    header: SframeHeader,
    meta_len: usize,
}

impl EncryptedFrame {
    pub fn new<D>(data: D) -> Result<Self>
    where
        D: AsRef<[u8]>,
    {
        EncryptedFrame::with_meta_data(data, &[])
    }

    pub fn with_meta_data<D, M>(data: D, meta_data: M) -> Result<Self>
    where
        D: AsRef<[u8]>,
        M: AsRef<[u8]>,
    {
        let data = data.as_ref();
        let meta_data = meta_data.as_ref();

        let header = SframeHeader::deserialize(data)?;
        log::trace!(
            "EncryptedFrame # {} with header {}",
            header.frame_count(),
            header
        );

        let meta_len = meta_data.len();
        let mut buffer = Vec::with_capacity(data.len() + meta_len);
        buffer.extend(meta_data);
        buffer.extend(data);

        Ok(Self {
            header,
            buffer,
            meta_len,
        })
    }
    pub(super) fn from_buffer(buffer: Vec<u8>, header: SframeHeader, meta_len: usize) -> Self {
        EncryptedFrame {
            buffer,
            header,
            meta_len,
        }
    }

    pub fn header(&self) -> &SframeHeader {
        &self.header
    }

    pub fn meta_data(&self) -> &[u8] {
        &self.buffer[..self.meta_len]
    }

    pub fn cipher_text(&self) -> &[u8] {
        &self.buffer[self.meta_len + self.header.len()..]
    }

    pub fn validate(self, validator: &impl FrameValidation) -> Result<Self> {
        validator.validate(&self.header)?;

        Ok(self)
    }

    pub fn decrypt(&self, key_store: &impl KeyStore) -> Result<MediaFrame> {
        let view = EncryptedFrameView::with_header(
            self.header,
            &self.buffer[self.meta_len..],
            self.meta_data(),
        );

        view.decrypt(key_store)
    }

    pub fn decrypt_into<'obuf>(
        &self,
        key_store: &impl KeyStore,
        buffer: &'obuf mut impl FrameBuffer,
    ) -> Result<MediaFrameView<'obuf>> {
        let view = EncryptedFrameView::with_header(
            self.header,
            &self.buffer[self.meta_len..],
            self.meta_data(),
        );

        view.decrypt_into(key_store, buffer)
    }
}

impl AsRef<[u8]> for EncryptedFrame {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_slice()
    }
}

#[cfg(test)]
mod test {
    use super::EncryptedFrameView;
    use crate::{frame::encrypted_frame::EncryptedFrame, header::SframeHeader};

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
        assert_eq!(frame_view.meta_data(), meta_data);
    }

    #[test]
    fn new_encrypted_frame_with_meta_data() {
        let meta_data = [42u8, 43u8];
        let header = SframeHeader::new(42, 666);
        let header_buf = Vec::from(&header);
        let cipher_text = vec![6u8; 3];
        let data = [header_buf.clone(), cipher_text.clone()].concat();

        let frame = EncryptedFrame::with_meta_data(&data, &meta_data).unwrap();

        assert_eq!(frame.header(), &header);
        assert_eq!(frame.cipher_text(), &cipher_text);
        assert_eq!(frame.meta_data(), meta_data);
    }
}
