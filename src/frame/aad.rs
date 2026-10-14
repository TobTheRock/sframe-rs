use crate::{crypto::buffer::AadData, error::Result, header::SframeHeader};

/// The AAD as of [RFC 9605 4.4.3](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.3):
/// `header | meta data`. A frame is stored as `meta data | header` though, so the AAD region of
/// the frame buffer has to be brought into the frame layout after the AEAD operation.
pub struct Aad<'a> {
    header: &'a SframeHeader,
    meta_data: &'a [u8],
}

impl<'a> Aad<'a> {
    pub fn new(header: &'a SframeHeader, meta_data: &'a [u8]) -> Self {
        Self { header, meta_data }
    }

    /// Reorders the serialized AAD in place into the frame layout `meta data | header`
    pub fn to_frame_layout(&self, aad: &mut [u8]) {
        aad.rotate_left(self.header.len());
    }
}

impl AadData for Aad<'_> {
    fn len(&self) -> usize {
        self.header.len() + self.meta_data.len()
    }

    fn serialize(&self, buffer: &mut [u8]) -> Result<()> {
        let (header, meta_data) = buffer.split_at_mut(self.header.len());
        self.header.serialize(header)?;
        meta_data.copy_from_slice(self.meta_data);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::Aad;
    use crate::{crypto::buffer::AadData, header::SframeHeader, util::test::assert_bytes_eq};

    const META_DATA: &[u8] = b"META";

    #[test]
    fn serialize_the_header_before_the_meta_data() {
        let header = SframeHeader::new(42, 666);
        let aad = Aad::new(&header, META_DATA);
        let mut buffer = vec![0u8; aad.len()];

        aad.serialize(&mut buffer).unwrap();

        assert_bytes_eq(
            &buffer,
            &[Vec::from(&header).as_slice(), META_DATA].concat(),
        );
    }

    #[test]
    fn reorder_into_the_frame_layout() {
        let header = SframeHeader::new(42, 666);
        let aad = Aad::new(&header, META_DATA);
        let mut buffer = vec![0u8; aad.len()];
        aad.serialize(&mut buffer).unwrap();

        aad.to_frame_layout(&mut buffer);

        assert_bytes_eq(
            &buffer,
            &[META_DATA, Vec::from(&header).as_slice()].concat(),
        );
    }
}
