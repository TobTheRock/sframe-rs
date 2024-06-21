use crate::{crypto::cipher_suite::CipherSuite, error::Result, frame::FrameBuffer};

pub trait AadData {
    fn len(&self) -> usize;
    fn serialize(&self, buffer: &mut [u8]) -> Result<()>;
}

impl AadData for Vec<u8> {
    fn len(&self) -> usize {
        self.len()
    }

    fn serialize(&self, buffer: &mut [u8]) -> Result<()> {
        buffer.copy_from_slice(self);
        Ok(())
    }
}

pub struct EncryptionBufferView<'a> {
    pub aad: &'a mut [u8],
    pub cipher_text: &'a mut [u8],
    pub tag: &'a mut [u8],
}

pub struct EncryptionBuffer<'a> {
    io_buffer: &'a mut [u8],
    aad_len: usize,
    cipher_text_len: usize,
}

impl<'a> EncryptionBuffer<'a> {
    pub fn try_allocate<U: AsRef<[u8]>>(
        buffer: &'a mut impl FrameBuffer,
        cipher_suite: &CipherSuite,
        aad_data: &impl AadData,
        unencrypted_data: U,
    ) -> Result<Self> {
        let unencrypted_data = unencrypted_data.as_ref();

        let aad_len = aad_data.len();
        let cipher_text_len = unencrypted_data.len();

        let buffer_len_needed = cipher_text_len + aad_len + cipher_suite.auth_tag_len;

        log::trace!("Trying to allocate buffer of size {}", buffer_len_needed);
        let io_buffer = buffer.allocate(buffer_len_needed)?.as_mut();
        let mut encryption_buffer = Self {
            io_buffer,
            aad_len,
            cipher_text_len,
        };

        encryption_buffer.try_fill(aad_data, unencrypted_data)?;

        Ok(encryption_buffer)
    }

    fn try_fill(&mut self, aad_data: &impl AadData, unencrypted_data: &[u8]) -> Result<()> {
        let buffers = EncryptionBufferView::from(self);

        aad_data.serialize(buffers.aad)?;
        buffers.cipher_text.copy_from_slice(unencrypted_data);

        Ok(())
    }
}

impl<'a> From<EncryptionBuffer<'a>> for &'a mut [u8] {
    fn from(val: EncryptionBuffer<'a>) -> Self {
        val.io_buffer
    }
}

impl<'a, 'buf> From<&'a mut EncryptionBuffer<'buf>> for EncryptionBufferView<'a> {
    fn from(unencrypted_data: &'a mut EncryptionBuffer<'buf>) -> Self {
        let (aad, remain) = unencrypted_data
            .io_buffer
            .split_at_mut(unencrypted_data.aad_len);
        let (cipher_text, tag) = remain.split_at_mut(unencrypted_data.cipher_text_len);

        EncryptionBufferView {
            aad,
            cipher_text,
            tag,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::CipherSuiteVariant;

    use super::*;

    struct TestAadData {
        data: [u8; 4],
    }

    impl AadData for TestAadData {
        fn len(&self) -> usize {
            self.data.len()
        }

        fn serialize(&self, buffer: &mut [u8]) -> Result<()> {
            buffer.copy_from_slice(&self.data);
            Ok(())
        }
    }

    #[test]
    fn test_encryption_buffer() {
        let mut buffer = Vec::new();
        let aad_data = TestAadData { data: [1, 2, 3, 4] };
        let unencrypted_data = [5, 6, 7, 8, 9];
        let cipher_suite = CipherSuiteVariant::AesGcm128Sha256.into();

        let mut encryption_buffer =
            EncryptionBuffer::try_allocate(&mut buffer, &cipher_suite, &aad_data, unencrypted_data)
                .unwrap();

        let view = EncryptionBufferView::from(&mut encryption_buffer);
        assert_eq!(view.aad, [1, 2, 3, 4]);
        assert_eq!(view.cipher_text, [5, 6, 7, 8, 9]);
        assert_eq!(view.tag.len(), cipher_suite.auth_tag_len);
    }
}
