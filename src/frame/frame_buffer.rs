use crate::error::Result;

pub trait Truncate {
    fn truncate(&mut self, size: usize);
}

pub trait FrameBuffer {
    type BufferSlice: AsMut<[u8]> + AsRef<[u8]> + Truncate;
    fn allocate(&mut self, size: usize) -> Result<&mut Self::BufferSlice>;
}

impl Truncate for Vec<u8> {
    fn truncate(&mut self, size: usize) {
        self.truncate(size);
    }
}

impl FrameBuffer for Vec<u8> {
    type BufferSlice = Self;
    fn allocate(&mut self, size: usize) -> Result<&mut Self::BufferSlice> {
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
