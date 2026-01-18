use crate::{
    crypto::cipher_suite::CipherSuite,
    error::Result,
    frame::{FrameBuffer, Truncate},
};

use super::{AadData, DecryptionBufferView};

pub struct DecryptionBuffer<'a, F>
where
    F: FrameBuffer,
{
    io_buffer: &'a mut F::BufferSlice,
    aad_len: usize,
    cipher_text_len: usize,
}

impl<'a, F> DecryptionBuffer<'a, F>
where
    F: FrameBuffer,
{
    pub fn try_allocate(
        buffer: &'a mut F,
        aad_data: &impl AadData,
        encrypted_data: &[u8],
    ) -> Result<Self> {
        let aad_len = aad_data.len();
        let cipher_text_len = encrypted_data.len();

        let buffer_len_needed = cipher_text_len + aad_len;
        log::trace!("Trying to allocate buffer of size {buffer_len_needed}");
        let io_buffer = buffer.allocate(buffer_len_needed)?;
        let mut decryption_buffer = Self {
            io_buffer,
            aad_len,
            cipher_text_len,
        };

        decryption_buffer.try_fill(aad_data, encrypted_data)?;

        Ok(decryption_buffer)
    }
    pub fn truncate(&mut self, cipher_suite: CipherSuite, dest: usize) {
        let decrypted_begin = self.aad_len;
        let decrypted_len = self.cipher_text_len - cipher_suite.auth_tag_len();
        let decrypted_end = decrypted_begin + decrypted_len;

        self.io_buffer
            .as_mut()
            .copy_within(decrypted_begin..decrypted_end, dest);
        self.io_buffer.truncate(dest + decrypted_len);
    }

    fn try_fill(&mut self, aad_data: &impl AadData, unencrypted_data: &[u8]) -> Result<()> {
        let buffers = DecryptionBufferView::from(self);

        aad_data.serialize(buffers.aad)?;
        buffers.cipher_text.copy_from_slice(unencrypted_data);

        Ok(())
    }
}

impl<'a, F> From<DecryptionBuffer<'a, F>> for &'a mut [u8]
where
    F: FrameBuffer,
{
    fn from(val: DecryptionBuffer<'a, F>) -> Self {
        val.io_buffer.as_mut()
    }
}

impl<'a, 'buf, F> From<&'a mut DecryptionBuffer<'buf, F>> for DecryptionBufferView<'a>
where
    F: FrameBuffer,
{
    fn from(unencrypted_data: &'a mut DecryptionBuffer<'buf, F>) -> Self {
        let (aad, cipher_text) = unencrypted_data
            .io_buffer
            .as_mut()
            .split_at_mut(unencrypted_data.aad_len);

        DecryptionBufferView { aad, cipher_text }
    }
}

#[cfg(test)]
mod test {

    use crate::{CipherSuite, crypto::buffer::test::TestAadData};

    use super::{DecryptionBuffer, DecryptionBufferView};

    const AAD_DATA: TestAadData = TestAadData { data: [1, 2, 3, 4] };

    #[test]
    fn allocate_decryption_buffer() {
        let mut buf = vec![];
        let encrypted_data = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut dec_buf =
            DecryptionBuffer::try_allocate(&mut buf, &AAD_DATA, &encrypted_data).unwrap();

        let view = DecryptionBufferView::from(&mut dec_buf);
        assert_eq!(view.aad, AAD_DATA.data);
        assert_eq!(view.cipher_text, encrypted_data.as_slice());
    }

    #[test]
    fn truncate_decryption_buffer() {
        let mut buf = vec![];
        let cipher_suite = CipherSuite::AesGcm128Sha256;
        let encrypted_data: Vec<u8> = (5..5 + cipher_suite.auth_tag_len())
            .map(|x| x as u8)
            .collect();
        let mut dec_buf =
            DecryptionBuffer::try_allocate(&mut buf, &AAD_DATA, &encrypted_data).unwrap();

        dec_buf.truncate(CipherSuite::AesGcm128Sha256, 2);
        assert_eq!(buf, AAD_DATA.data[0..2]);
    }
}
