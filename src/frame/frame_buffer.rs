use crate::error::Result;

/// Representation of a frame buffer which allows to allocate continuous slices of memory as bytes
/// Already implemented for `Vec<u8>`
pub trait FrameBuffer {
    /// The type representing a slice of the buffer.
    type BufferSlice: AsMut<[u8]> + AsRef<[u8]> + Truncate;
    /// Tries to allocate a continuous slice of memory in the buffer.
    /// If allocation fails an [`crate::error::SframeError`] is returned.
    fn allocate(&mut self, size: usize) -> Result<&mut Self::BufferSlice>;
}

/// During decryption a larger buffer is temporarily needed than the size of resulting decrypted payload.
/// Due to this, the size of the buffer can be truncated after the decryption was successful.
/// However, as this is purely optional and sometimes only informative (depending on the buffer design),
/// the truncation is implemented as a NOOP per default.  
pub trait Truncate {
    /// shortens the allocated memory in the  buffer by keeping the first `len` bytes and dropping the rest
    fn truncate(&mut self, _len: usize) {
        // NOOP per default
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

impl Truncate for Vec<u8> {
    fn truncate(&mut self, len: usize) {
        self.truncate(len);
    }
}

#[cfg(test)]
mod test {
    use super::FrameBuffer;
    use pretty_assertions::assert_eq;

    #[test]
    fn allocate_vec_buffer() {
        let mut buf = vec![42u8];
        let allocated: &mut [u8] = buf.allocate(3).unwrap();

        allocated.fill_with(|| 6u8);

        assert_eq!(buf.len(), 3);
        assert_eq!(buf, vec![6; 3]);
    }
}
