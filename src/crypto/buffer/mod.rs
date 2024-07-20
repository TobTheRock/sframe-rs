pub mod decryption;
pub mod encryption;

use crate::error::Result;

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

#[cfg(test)]
mod test {
    use super::AadData;
    use crate::error::Result;

    pub(super) struct TestAadData {
        pub data: [u8; 4],
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
}
