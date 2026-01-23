//! Buffer types for AEAD encryption and decryption operations
//! as defined in [RFC 9605 Section 4.4](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4).

pub(crate) mod decryption;
pub(crate) mod encryption;

use crate::error::Result;

/// A view into a buffer for AEAD decryption operations.
pub struct DecryptionBufferView<'a> {
    /// The Additional Authenticated Data (AAD).
    pub aad: &'a mut [u8],
    /// The ciphertext to decrypt (includes authentication tag).
    pub cipher_text: &'a mut [u8],
}

/// A view into a buffer for AEAD encryption operations.
pub struct EncryptionBufferView<'a> {
    /// The Additional Authenticated Data (AAD).
    pub aad: &'a mut [u8],
    /// The plaintext to encrypt.
    pub cipher_text: &'a mut [u8],
    /// The buffer for the authentication tag.
    pub tag: &'a mut [u8],
}

/// Trait for types that can provide Additional Authenticated Data (AAD)
/// as specified in [RFC 9605 Section 4.4.3](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.3).
pub trait AadData {
    /// Returns the length in bytes of the serialized AAD.
    fn len(&self) -> usize;
    /// Returns true if the AAD data is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Serializes the AAD into the provided buffer.
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
