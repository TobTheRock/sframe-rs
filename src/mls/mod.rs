//! # MLS
//!
//! Deriving `SFrame` keys from an [MLS](https://datatracker.ietf.org/doc/html/rfc9420) group as of
//! [RFC 9605 Section 5.2](https://www.rfc-editor.org/rfc/rfc9605.html#name-mls), so a conference
//! does not need to distribute key material of its own.
//!
//! Implement [`MlsExporter`] on top of the MLS library in use, then `derive_from_mls` on the
//! keys of [`crate::key`] exports the base key from the group and derives the `SFrame` key
//! from it.
//!
//! An [`MlsKeyId`] splits the 64 bit `SFrame` Key ID into three fields, so every sender in the
//! group gets its own key id without any further coordination:
//!
//! ```text
//!  64-S-E bits   S bits   E bits
//! <-----------> <------> <------>
//! +-------------+--------+-------+
//! | Context ID  | Index  | Epoch |
//! +-------------+--------+-------+
//! ```
//!
//! - **Epoch**: the `E` least significant bits of the MLS epoch, so a key id changes whenever the
//!   group does
//! - **Index**: the MLS member index of the sender, the group size must fit into `S` bits
//! - **Context ID**: chosen by the sender, `0` produces the shortest Key ID on the wire
//!
//! How many bits each field gets is fixed for the session by an [`MlsKeyIdBitRange`].
//!
//! ## Example
//!
//! ```rust
//! use sframe::{
//!     CipherSuite,
//!     key::EncryptionKey,
//!     mls::{MlsExporter, MlsKeyId, MlsKeyIdBitRange},
//! };
//!
//! // in a real application this delegates to the MLS library holding the group state
//! struct Group;
//!
//! impl MlsExporter for Group {
//!     type BaseKey = Vec<u8>;
//!     type Error = std::convert::Infallible;
//!
//!     fn export_secret(
//!         &self,
//!         label: &str,
//!         context: &[u8],
//!         key_length: usize,
//!     ) -> Result<Self::BaseKey, Self::Error> {
//!         Ok(vec![0x2a; key_length])
//!     }
//! }
//!
//! # fn main() -> sframe::error::Result<()> {
//! // 4 bits of epoch and 4 bits of member index, the rest is context
//! let bit_range = MlsKeyIdBitRange::new(4, 4);
//! // member 3 of the group, at MLS epoch 7
//! let key_id = MlsKeyId::try_new(0u64, 7u64, 3u64, bit_range)?;
//!
//! let key = EncryptionKey::derive_from_mls(CipherSuite::AesGcm256Sha512, &Group, key_id)?;
//!
//! assert_eq!(key_id.member_index(), 3);
//! assert_eq!(key_id.epoch_lsb(), 7);
//! # Ok(())
//! # }
//! ```

use crate::{
    CipherSuite,
    crypto::{AeadDecrypt, AeadEncrypt, KeyDerivation},
    error::SframeError,
    key::{GenericDecryptionKey, GenericEncryptionKey},
};
use log::error;

/// definitions of a key id according to [RFC 9605 Section 5.2](https://www.rfc-editor.org/rfc/rfc9605.html#section-5.2)
mod mls_key_id;

pub use mls_key_id::{MlsKeyId, MlsKeyIdBitRange};

/// Trait abstraction for an MLS exporter defined in [RFC 9420](https://datatracker.ietf.org/doc/html/rfc9420#exporters).
/// As of [RFC 9605 Section 5.2](https://www.rfc-editor.org/rfc/rfc9605.html#section-5.2) this exporter
/// can be used to derive the `SFrame` keys of [`crate::key`].
pub trait MlsExporter {
    /// Type of the base key returned by the MLS exporter
    type BaseKey: AsRef<[u8]>;
    /// Error type of the MLS exporter
    type Error: std::error::Error;
    /// Tries to export a secret from MLS, which can be used as a base key for Sframe
    fn export_secret(
        &self,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Self::BaseKey, Self::Error>;
}

macro_rules! mls_key {
    ($name:ident, $aead:ident) => {
        impl<A, D> $name<A, D>
        where
            A: $aead<Secret = D::Secret>,
            D: KeyDerivation,
        {
            /// Derives a new sframe key from the base key provided by the MLS exporter.
            /// Associates it with an MLS specific Key ID.
            pub fn derive_from_mls(
                cipher_suite: CipherSuite,
                exporter: &impl MlsExporter,
                key_id: MlsKeyId,
            ) -> crate::error::Result<Self> {
                let base_key = exporter
                    .export_secret("SFrame 1.0 Base Key", b"", cipher_suite.key_len())
                    .map_err(|err| {
                        error!("Failed to export base key from MLS: {}", err);
                        SframeError::KeyDerivationFailure
                    })?;

                Self::derive_from(cipher_suite, key_id, base_key)
            }
        }
    };
}

mls_key!(GenericDecryptionKey, AeadDecrypt);
mls_key!(GenericEncryptionKey, AeadEncrypt);

#[cfg(all(test, crypto_backend))]
mod test {
    use super::{MlsExporter, MlsKeyId, MlsKeyIdBitRange};
    use crate::key::EncryptionKey;

    #[derive(Debug, thiserror::Error)]
    #[error("the MLS group could not export a secret")]
    struct ExportFailed;

    struct TestMlsExporter {
        fail: bool,
    }
    impl MlsExporter for TestMlsExporter {
        type BaseKey = &'static str;
        type Error = ExportFailed;

        fn export_secret(
            &self,
            _label: &str,
            _context: &[u8],
            _key_length: usize,
        ) -> Result<Self::BaseKey, Self::Error> {
            if self.fail {
                Err(ExportFailed)
            } else {
                Ok("BASE_KEY")
            }
        }
    }

    #[test]
    fn derive_key_from_mls() {
        let exporter = TestMlsExporter { fail: false };
        let key_id = MlsKeyId::try_new(0u64, 3u64, 5u64, MlsKeyIdBitRange::new(4, 4)).unwrap();

        let _key =
            EncryptionKey::derive_from_mls(crate::CipherSuite::AesGcm256Sha512, &exporter, key_id)
                .unwrap();
    }

    #[test]
    fn derive_key_from_mls_failed_export() {
        let exporter = TestMlsExporter { fail: true };
        let key_id = MlsKeyId::try_new(0u64, 3u64, 5u64, MlsKeyIdBitRange::new(4, 4)).unwrap();

        let result =
            EncryptionKey::derive_from_mls(crate::CipherSuite::AesGcm256Sha512, &exporter, key_id);

        assert!(result.is_err());
    }
}
