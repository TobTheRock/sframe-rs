use crate::{
    crypto::cipher_suite::CipherSuite,
    error::SframeError,
    key::{DecryptionKey, EncryptionKey},
    CipherSuiteVariant,
};
use log::error;

/// definitions of a key id according to [sframe draft 07 5.2](https://www.ietf.org/archive/id/draft-ietf-sframe-enc-07.html#section-5.2)
pub mod mls_key_id;

pub use mls_key_id::{MlsKeyId, MlsKeyIdBitRange};

/// Trait abstraction for an MLS exporter defined in [RFC 9420](https://datatracker.ietf.org/doc/html/rfc9420#exporters).
/// As of  [sframe draft 07 5.2](https://www.ietf.org/archive/id/draft-ietf-sframe-enc-07.html#section-5.2) this exporter
/// can be used to derive an [`EncryptionKey`].
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
    ($name:ident) => {
        impl $name {
            /// Derives a new sframe key from the base key provided by the MLS exporter.
            /// Associates it with an MLS specific Key ID.
            pub fn derive_from_mls(
                variant: CipherSuiteVariant,
                exporter: &impl MlsExporter,
                key_id: MlsKeyId,
            ) -> crate::error::Result<Self> {
                let cipher_suite = CipherSuite::from(variant);
                let base_key = exporter
                    .export_secret("SFrame 1.0 Base Key", b"", cipher_suite.key_len)
                    .map_err(|err| {
                        error!("Failed to export base key from MLS: {}", err);
                        SframeError::KeyDerivation
                    })?;

                $name::derive_from(variant, key_id, base_key)
            }
        }
    };
}

mls_key!(DecryptionKey);
mls_key!(EncryptionKey);

#[cfg(test)]
mod test {
    use super::{MlsExporter, MlsKeyId, MlsKeyIdBitRange};
    use crate::{error::SframeError, key::EncryptionKey};

    struct TestMlsExporter {
        fail: bool,
    }
    impl MlsExporter for TestMlsExporter {
        type BaseKey = &'static str;
        type Error = SframeError;

        fn export_secret(
            &self,
            _label: &str,
            _context: &[u8],
            _key_length: usize,
        ) -> Result<Self::BaseKey, Self::Error> {
            if self.fail {
                Err(SframeError::Other("FAIL".to_owned()))
            } else {
                Ok("BASE_KEY")
            }
        }
    }

    #[test]
    fn derive_key_from_mls() {
        let exporter = TestMlsExporter { fail: false };
        let key_id = MlsKeyId::new(0u64, 3u64, 5u64, MlsKeyIdBitRange::new(4, 4));

        let _key = EncryptionKey::derive_from_mls(
            crate::CipherSuiteVariant::AesGcm256Sha512,
            &exporter,
            key_id,
        )
        .unwrap();
    }

    #[test]
    fn derive_key_from_mls_failed_export() {
        let exporter = TestMlsExporter { fail: true };
        let key_id = MlsKeyId::new(0u64, 3u64, 5u64, MlsKeyIdBitRange::new(4, 4));

        let result = EncryptionKey::derive_from_mls(
            crate::CipherSuiteVariant::AesGcm256Sha512,
            &exporter,
            key_id,
        );

        assert!(result.is_err());
    }
}
