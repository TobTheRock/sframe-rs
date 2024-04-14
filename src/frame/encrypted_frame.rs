use crate::{
    crypto::aead::AeadDecrypt,
    error::{Result, SframeError},
    header::SframeHeader,
    key::{DecryptionKey, KeyStore},
};

use super::{
    frame_buffer::Truncate,
    media_frame::{MediaFrame, MediaFrameView},
    FrameBuffer, FrameValidation,
};
/// A view on a buffer which contains an encrypted frame in the format as of [sframe draft 07 4.2](https://www.ietf.org/archive/id/draft-ietf-sframe-enc-07.html#section-4.2).
/// The frame is assumed to be stored in the buffer as follows:
/// ```txt
/// | Meta Data | Sframe Header | Encrypted Data | Auth Tag |
/// ````
/// where the  meta data is optional and can e.g. be a media header
#[derive(Clone, Copy, Debug)]
pub struct EncryptedFrameView<'buf> {
    header: SframeHeader,
    meta_data: &'buf [u8],
    data: &'buf [u8],
}

impl<'ibuf> EncryptedFrameView<'ibuf> {
    /// Tries to create a new view on a buffer deserializing the contained [`SframeHeader`].
    /// Fails with an [`crate::error::SframeError`] if the buffer/header is invalid
    pub fn try_new<D>(data: &'ibuf D) -> Result<Self>
    where
        D: AsRef<[u8]> + ?Sized,
    {
        EncryptedFrameView::try_with_meta_data(data, &[])
    }

    /// Tries to create a new view on a buffer deserializing the contained [`SframeHeader`].
    /// Associates the provided meta data with the frame.
    /// Fails with an [`crate::error::SframeError`] if the buffer is invalid
    pub fn try_with_meta_data<D, M>(data: &'ibuf D, meta_data: &'ibuf M) -> Result<Self>
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

    /// the header of the encrypted frame
    pub fn header(&self) -> &SframeHeader {
        &self.header
    }

    /// the associated meta data of the encrypted frame
    pub fn meta_data(&self) -> &[u8] {
        self.meta_data
    }

    /// the cipher text (Sframe Header + Encrypted Data + Authentication Tag) of the encrypted frame
    pub fn cipher_text(&self) -> &[u8] {
        &self.data[self.header.len()..]
    }

    /// Validates the header of the encrypted frame
    /// Semantic sugar to allow chaining the validation with decryption
    /// returns an [`crate::error::SframeError`] when validation fails
    pub fn validate<V>(self, validator: &V) -> Result<Self>
    where
        V: FrameValidation + ?Sized,
    {
        log::trace!("Validating EncryptedFrame # {}", self.header.frame_count());
        validator.validate(&self.header)?;

        Ok(self)
    }

    /// Tries to decrypt the encrypted frame with a key from the provided key store.
    /// As [`DecryptionKey`] implements [`KeyStore`] this can also be a single key.
    /// Dynamically allocates memory for the resulting [`MediaFrame`]
    /// returns an [`crate::error::SframeError`] if no matching key with the key id in this [`SframeHeader`] is available
    /// or if decryption has failed in general.
    pub fn decrypt(&self, key_store: &mut impl KeyStore) -> Result<MediaFrame> {
        let mut buffer = Vec::new();
        let view = self.decrypt_into(key_store, &mut buffer)?;

        Ok(MediaFrame::with_buffer(
            view.frame_count(),
            buffer,
            self.meta_data.len(),
        ))
    }

    /// Tries to decrypt the encrypted frame with a key from the provided key store and stores the result
    /// into the provided buffer. On success an [`MediaFrameView`] on the buffer is returned.
    /// As [`DecryptionKey`] implements [`KeyStore`] this can also be a single key.
    /// returns an [`crate::error::SframeError`] if no matching key with the key id in this [`SframeHeader`] is available
    /// or if decryption has failed in general.
    pub fn decrypt_into<'obuf>(
        &self,
        key_store: &mut impl KeyStore,
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

    fn buffer_len(&self, key: &DecryptionKey) -> BufferLengths {
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
        EncryptedFrameView::try_new(data)
    }
}

impl<'buf> TryFrom<&'buf Vec<u8>> for EncryptedFrameView<'buf> {
    type Error = SframeError;

    fn try_from(data: &'buf Vec<u8>) -> Result<Self> {
        EncryptedFrameView::try_new(data)
    }
}
/// An abstraction of an encrypted frame in the format as of [sframe draft 07 4.2](https://www.ietf.org/archive/id/draft-ietf-sframe-enc-07.html#section-4.2),
/// owing an internal buffer containing the cipher text and optionally associated meta data (e.g. be a media header).
pub struct EncryptedFrame {
    buffer: Vec<u8>,
    header: SframeHeader,
    meta_len: usize,
}

impl EncryptedFrame {
    /// Tries to create a new encrypted frame, copying the data of the buffer and deserializing the contained [`SframeHeader`].
    /// Fails with an [`crate::error::SframeError`] if the buffer/header is invalid.
    pub fn try_new<D>(data: D) -> Result<Self>
    where
        D: AsRef<[u8]>,
    {
        EncryptedFrame::try_with_meta_data(data, [])
    }

    /// Tries to create a new encrypted frame, copying the data of the data and meta data buffer and deserializing the contained [`SframeHeader`].
    /// Fails with an [`crate::error::SframeError`] if the buffer/header is invalid.
    pub fn try_with_meta_data<D, M>(data: D, meta_data: M) -> Result<Self>
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
            buffer,
            header,
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

    /// the header of the encrypted frame
    pub fn header(&self) -> &SframeHeader {
        &self.header
    }

    /// the associated meta data of the encrypted frame
    pub fn meta_data(&self) -> &[u8] {
        &self.buffer[..self.meta_len]
    }

    /// the cipher text (Sframe Header + Encrypted Data + Authentication Tag) of the encrypted frame
    pub fn cipher_text(&self) -> &[u8] {
        &self.buffer[self.meta_len + self.header.len()..]
    }

    /// Validates the header of the encrypted frame
    /// Semantic sugar to allow chaining the validation with decryption
    /// returns an [`crate::error::SframeError`] when validation fails
    pub fn validate<V>(self, validator: &V) -> Result<Self>
    where
        V: FrameValidation + ?Sized,
    {
        log::trace!("Validating EncryptedFrame # {}", self.header.frame_count());
        validator.validate(&self.header)?;

        Ok(self)
    }

    /// Tries to decrypt the encrypted frame with a key from the provided key store.
    /// As [`DecryptionKey`] implements [`KeyStore`] this can also be a single key.
    /// Dynamically allocats memory for the resulting [`MediaFrame`]
    /// returns an [`crate::error::SframeError`] if no matching key with the key id in this [`SframeHeader`] is available
    /// or if decryption has failed in general.
    pub fn decrypt(&self, key_store: &mut impl KeyStore) -> Result<MediaFrame> {
        let view = EncryptedFrameView::with_header(
            self.header,
            &self.buffer[self.meta_len..],
            self.meta_data(),
        );

        view.decrypt(key_store)
    }

    /// Tries to decrypt the encrypted frame with a key from the provided key store and stores the result
    /// into the provided buffer. On success an [`MediaFrameView`] on the buffer is returned.
    /// As [`DecryptionKey`] implements [`KeyStore`] this can also be a single key.
    /// returns an [`crate::error::SframeError`] if no matching key with the key id in this [`SframeHeader`] is available
    /// or if decryption has failed in general.
    pub fn decrypt_into<'obuf>(
        &self,
        key_store: &mut impl KeyStore,
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

impl TryFrom<&[u8]> for EncryptedFrame {
    type Error = SframeError;

    fn try_from(data: &[u8]) -> Result<Self> {
        EncryptedFrame::try_new(data)
    }
}

impl TryFrom<&Vec<u8>> for EncryptedFrame {
    type Error = SframeError;

    fn try_from(data: &Vec<u8>) -> Result<Self> {
        EncryptedFrame::try_new(data)
    }
}

#[cfg(test)]
mod test {
    use super::EncryptedFrameView;
    use crate::{frame::encrypted_frame::EncryptedFrame, header::SframeHeader};
    use pretty_assertions::assert_eq;

    #[test]
    fn new_encrypted_frame_view_with_meta_data() {
        let meta_data = [42u8, 43u8];
        let header = SframeHeader::new(42, 666);
        let header_buf = Vec::from(&header);
        let cipher_text = vec![6u8; 3];
        let data = [header_buf.clone(), cipher_text.clone()].concat();

        let frame_view = EncryptedFrameView::try_with_meta_data(&data, &meta_data).unwrap();

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

        let frame = EncryptedFrame::try_with_meta_data(data, meta_data).unwrap();

        assert_eq!(frame.header(), &header);
        assert_eq!(frame.cipher_text(), &cipher_text);
        assert_eq!(frame.meta_data(), meta_data);
    }
}
