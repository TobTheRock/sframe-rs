use crate::{
    crypto::aead::AeadDecrypt,
    error::{Result, SframeError},
    frame_validation::FrameValidation,
    header::SframeHeader,
    key::{KeyStore, SframeKey},
};

use super::{
    frame_buffer::Truncate,
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

    pub fn validate<V>(self, validator: &V) -> Result<Self>
    where
        V: FrameValidation + ?Sized,
    {
        log::trace!("Validating EncryptedFrame # {}", self.header.frame_count());
        validator.validate(&self.header)?;

        Ok(self)
    }

    pub fn decrypt(&self, key_store: &impl KeyStore) -> Result<MediaFrame> {
        let mut buffer = Vec::new();
        let view = self.decrypt_into(key_store, &mut buffer)?;

        Ok(MediaFrame::with_buffer(
            view.frame_count(),
            buffer,
            self.meta_data.len(),
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

        let key = key_store.get_key(key_id)?;

        let buffer_len = self.buffer_len(key);
        let allocate_len = buffer_len.meta + self.data.len();
        log::trace!(
            "EncryptedFrame # {} trying to allocate buffer of size {}",
            self.header.frame_count(),
            allocate_len
        );
        let frame_buffer = buffer.allocate(allocate_len)?;
        let (aad_buffer, io_buffer) = self.fill_buffers(frame_buffer.as_mut(), &buffer_len)?;

        key.decrypt(io_buffer, aad_buffer, frame_count)?;
        let (payload, meta_data) = self.truncate_buffer(frame_buffer, &buffer_len);

        let media_frame = MediaFrameView::with_meta_data(frame_count, payload, meta_data);
        Ok(media_frame)
    }

    fn fill_buffers<'obuf>(
        &self,
        frame_buffer: &'obuf mut [u8],
        buffer_len: &BufferLengths,
    ) -> Result<(&'obuf mut [u8], &'obuf mut [u8])> {
        let (aad_buffer, io_buffer) = frame_buffer.split_at_mut(buffer_len.aad_buffer);

        aad_buffer[..buffer_len.meta].copy_from_slice(self.meta_data);
        aad_buffer[buffer_len.meta..].copy_from_slice(&self.data[..buffer_len.header]);

        io_buffer.copy_from_slice(&self.data[buffer_len.header..]);

        Ok((aad_buffer, io_buffer))
    }

    fn truncate_buffer<'obuf, F>(
        &self,
        frame_buffer: &'obuf mut F,
        buffer_len: &BufferLengths,
    ) -> (&'obuf [u8], &'obuf [u8])
    where
        F: AsMut<[u8]> + AsRef<[u8]> + Truncate,
    {
        let decrypted_begin = buffer_len.aad_buffer;
        let decrypted_end = decrypted_begin + buffer_len.decrypted;

        frame_buffer
            .as_mut()
            .copy_within(decrypted_begin..decrypted_end, buffer_len.meta);

        frame_buffer.truncate(buffer_len.meta + buffer_len.decrypted);

        let (meta_data, payload) = frame_buffer.as_mut().split_at(buffer_len.meta);

        (payload, meta_data)
    }

    fn buffer_len(&self, key: &SframeKey) -> BufferLengths {
        let header = self.header.len();
        let meta = self.meta_data.len();
        let aad_buffer = header + meta;
        let decrypted = self.data.len() - key.cipher_suite().auth_tag_len - header;

        BufferLengths {
            aad_buffer,
            decrypted,
            header,
            meta,
        }
    }
}

struct BufferLengths {
    aad_buffer: usize,
    decrypted: usize,
    header: usize,
    meta: usize,
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
