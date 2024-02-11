use crate::error::Result;

pub trait FrameBuffer {
    type BufferSlice: AsMut<[u8]> + AsRef<[u8]>;
    fn allocate<'buf>(&'buf mut self, size: usize) -> Result<&'buf mut Self::BufferSlice>;
}

impl FrameBuffer for Vec<u8> {
    type BufferSlice = Self;
    fn allocate<'buf>(&'buf mut self, size: usize) -> Result<&'buf mut Self::BufferSlice> {
        log::trace!("Allocating buffer of size {}", size);
        self.resize(size, 0);
        Ok(self)
    }
}

#[cfg(test)]
mod test {
    use super::FrameBuffer;

    #[test]
    fn allocate_vec_buffer() {
        let mut buf = vec![42u8];
        let allocated: &mut [u8] = buf.allocate(3).unwrap();

        allocated.fill_with(|| 6u8);

        assert_eq!(buf.len(), 3);
        assert_eq!(buf, vec![6; 3]);
    }
}
