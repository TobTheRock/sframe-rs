use crate::{
    crypto::{
        aead::AeadEncrypt,
        buffer::{encryption::EncryptionBuffer, AadData},
    },
    error::Result,
    header::{FrameCount, SframeHeader},
    key::EncryptionKey,
};

use super::{
    encrypted_frame::{EncryptedFrame, EncryptedFrameView},
    FrameBuffer,
};

/// A view on a buffer (as a continuous slice of memory), representing a media frame.
/// Can optionally have meta data (e.g. a header) associated to it, which is considered for authentication.
#[derive(Debug, PartialEq, Eq)]
pub struct MediaFrameView<'buf> {
    frame_count: FrameCount,
    meta_data: &'buf [u8],
    payload: &'buf [u8],
}

impl<'ibuf> MediaFrameView<'ibuf> {
    /// Creates a new view on a payload buffer and assigns it the given frame count
    pub fn new<F, P>(frame_count: F, payload: &'ibuf P) -> Self
    where
        F: Into<FrameCount>,
        P: AsRef<[u8]> + ?Sized,
    {
        Self::with_meta_data(frame_count, payload, &[])
    }

    /// Creates a new view on a payload buffer, assigns it the given frame count and associates it with the meta data
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

    /// Meta data associated with this media frame
    pub fn meta_data(&self) -> &[u8] {
        self.meta_data
    }

    /// Payload of this media frame
    pub fn payload(&self) -> &[u8] {
        self.payload
    }

    /// Frame count for the Sframe scheme associated to this media frame
    pub fn frame_count(&self) -> FrameCount {
        self.frame_count
    }

    /// Encrypts the media frame with the sframe key according to [RFC 9605 4.4.3](https://www.rfc-editor.org/rfc/rfc9605.html#name-encryption). Dynamically allocates memory for the resulting [`EncryptedFrame`].
    /// The associated meta data is not encrypted but considered for the authentication tag.
    /// Returns an [`crate::error::SframeError`] when encryption fails.
    pub fn encrypt(&self, key: &EncryptionKey) -> Result<EncryptedFrame> {
        let mut buffer = Vec::new();
        let view = self.encrypt_into(key, &mut buffer)?;

        let header = *view.header();
        let meta_len = view.meta_data().len();

        let encrypted_frame = EncryptedFrame::from_buffer(buffer, header, meta_len);

        Ok(encrypted_frame)
    }

    /// Encrypts the media frame with the sframe key according to [RFC 9605 4.4.3](https://www.rfc-editor.org/rfc/rfc9605.html#name-encryption) and stores the result, an [`EncryptedFrameView`], into the provided buffer.
    /// The associated meta data is not encrypted but considered for the authentication tag.
    /// Returns an [`crate::error::SframeError`] when encryption fails.
    pub fn encrypt_into<'obuf>(
        &self,
        key: &EncryptionKey,
        buffer: &'obuf mut impl FrameBuffer,
    ) -> Result<EncryptedFrameView<'obuf>> {
        let key_id = key.key_id();
        log::trace!(
            "Encrypting MediaFrame # {} using KeyId {} and CipherSuite {}",
            self.frame_count,
            key_id,
            key.cipher_suite_variant()
        );

        let header = SframeHeader::new(key_id, self.frame_count);
        log::trace!("MediaFrame # {} using header {}", self.frame_count, header);

        let aad = Aad {
            meta_data: self.meta_data,
            header: &header,
        };
        let mut crypto_buffer =
            EncryptionBuffer::try_allocate(buffer, key.cipher_suite(), &aad, self.payload)?;

        log::trace!("MediaFrame # {} trying to encrypt", self.frame_count);
        key.encrypt(&mut crypto_buffer, self.frame_count)?;

        let meta_len = self.meta_data().len();
        let buffer: &mut [u8] = crypto_buffer.into();
        let encrypted =
            EncryptedFrameView::with_header(header, &buffer[meta_len..], &buffer[..meta_len]);

        Ok(encrypted)
    }
}

struct Aad<'a> {
    meta_data: &'a [u8],
    header: &'a SframeHeader,
}

impl AadData for Aad<'_> {
    fn len(&self) -> usize {
        self.meta_data.len() + self.header.len()
    }

    fn serialize(&self, buffer: &mut [u8]) -> Result<()> {
        let (meta_data, header) = buffer.split_at_mut(self.meta_data.len());
        meta_data.copy_from_slice(self.meta_data);
        self.header.serialize(header)?;
        Ok(())
    }
}

/// A an abstraction of a media frame owning an internal buffer.
/// Can optionally have meta data (e.g. a header) associated to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaFrame {
    frame_count: FrameCount,
    buffer: Vec<u8>,
    meta_len: usize,
}

impl MediaFrame {
    /// Creates a new media frame by copying the data of a payload buffer and assigning it the given frame count.
    pub fn new<F, P>(frame_count: F, payload: P) -> Self
    where
        F: Into<FrameCount>,
        P: AsRef<[u8]>,
    {
        Self::with_meta_data(frame_count, payload, [])
    }

    /// Creates a new media frame and assigns it the given frame count.
    /// Payload and meta data are copied into an internal buffer.
    pub fn with_meta_data<F, P, M>(frame_count: F, payload: P, meta_data: M) -> Self
    where
        F: Into<FrameCount>,
        P: AsRef<[u8]>,
        M: AsRef<[u8]>,
    {
        let frame_count = frame_count.into();
        let payload = payload.as_ref();
        let meta_data = meta_data.as_ref();
        let meta_len = meta_data.len();
        let payload_len = payload.len();

        log::debug!(
            "Creating MediaFrame # {} with payload size {} using meta data of size {}",
            frame_count,
            payload_len,
            meta_len,
        );

        let mut buffer = Vec::with_capacity(payload_len + meta_len);
        buffer.extend(meta_data);
        buffer.extend(payload);

        Self {
            frame_count,
            buffer,
            meta_len,
        }
    }

    pub(super) fn with_buffer(frame_count: FrameCount, buffer: Vec<u8>, meta_len: usize) -> Self {
        Self {
            frame_count,
            buffer,
            meta_len,
        }
    }

    /// Meta data associated with this media frame
    pub fn meta_data(&self) -> &[u8] {
        &self.buffer[..self.meta_len]
    }

    /// Payload of this media frame
    pub fn payload(&self) -> &[u8] {
        &self.buffer[self.meta_len..]
    }

    /// Frame count for the Sframe scheme associated to this media frame
    pub fn frame_count(&self) -> FrameCount {
        self.frame_count
    }

    /// Encrypts the media frame with the sframe key according to [RFC 9605 4.4.3](https://www.rfc-editor.org/rfc/rfc9605.html#name-encryption).
    /// Dynamically allocates memory for the resulting [`EncryptedFrame`].
    /// The associated meta data is not encrypted but considered for the authentication tag.
    /// Returns an [`crate::error::SframeError`] when encryption fails
    pub fn encrypt(&self, key: &EncryptionKey) -> Result<EncryptedFrame> {
        let view =
            MediaFrameView::with_meta_data(self.frame_count, self.payload(), self.meta_data());
        view.encrypt(key)
    }

    /// Encrypts the media frame with the sframe key according to [RFC 9605 4.4.3](https://www.rfc-editor.org/rfc/rfc9605.html#name-encryption)
    /// and stores the result into the provided buffer. An [`EncryptedFrameView`] on the buffer is returned on success.
    /// The associated meta data is not encrypted but considered for the authentication tag.
    /// Returns an [`crate::error::SframeError`] when encryption fails.
    pub fn encrypt_into<'obuf>(
        &self,
        key: &EncryptionKey,
        buffer: &'obuf mut impl FrameBuffer,
    ) -> Result<EncryptedFrameView<'obuf>> {
        let view =
            MediaFrameView::with_meta_data(self.frame_count, self.payload(), self.meta_data());
        view.encrypt_into(key, buffer)
    }
}

impl AsRef<[u8]> for MediaFrame {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_slice()
    }
}

#[cfg(test)]
mod test {
    use crate::{
        frame::media_frame::{MediaFrame, MediaFrameView},
        key::EncryptionKey,
        util::test::assert_bytes_eq,
        CipherSuiteVariant,
    };
    use pretty_assertions::assert_eq;

    const FRAME_COUNT: u64 = 42;
    const PAYLOAD: &[u8] = &[6, 6, 6, 6, 6, 6];
    const KEY_ID: u64 = 666;
    const META_DATA: &[u8] = b"META";

    #[test]
    fn create_media_frame_with_meta_data() {
        let frame_view = MediaFrameView::with_meta_data(FRAME_COUNT, &PAYLOAD, &META_DATA);

        assert_eq!(frame_view.payload(), PAYLOAD);
        assert_eq!(frame_view.frame_count(), FRAME_COUNT);
        assert_eq!(frame_view.meta_data(), META_DATA);
    }

    #[test]
    fn encrypt_media_frame_view() {
        let key = EncryptionKey::derive_from(CipherSuiteVariant::AesGcm256Sha512, KEY_ID, "SECRET")
            .unwrap();
        let mut encrypt_buffer = Vec::new();

        let media_frame = MediaFrameView::with_meta_data(FRAME_COUNT, &PAYLOAD, META_DATA);
        let encrypted_frame = media_frame.encrypt_into(&key, &mut encrypt_buffer).unwrap();

        assert_eq!(encrypted_frame.header().key_id(), KEY_ID);
        assert_eq!(encrypted_frame.header().frame_count(), FRAME_COUNT);
        assert_bytes_eq(encrypted_frame.meta_data(), META_DATA);
        assert!(!encrypted_frame.cipher_text().is_empty());
    }

    #[test]
    fn encrypt_media_frame() {
        let key = EncryptionKey::derive_from(CipherSuiteVariant::AesGcm256Sha512, KEY_ID, "SECRET")
            .unwrap();

        let media_frame = MediaFrame::with_meta_data(FRAME_COUNT, PAYLOAD, META_DATA);
        let encrypted_frame = media_frame.encrypt(&key).unwrap();

        assert_eq!(encrypted_frame.header().key_id(), KEY_ID);
        assert_eq!(encrypted_frame.header().frame_count(), FRAME_COUNT);
        assert_bytes_eq(encrypted_frame.meta_data(), META_DATA);
        assert!(!encrypted_frame.cipher_text().is_empty());
    }
}
