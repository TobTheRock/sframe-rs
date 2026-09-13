//! Covers deriving an sframe key from an MLS epoch secret, and what a receiver is told when the
//! MLS exporter it is handed fails.

#![cfg(crypto_backend)]

use sframe::{
    CipherSuite,
    key::EncryptionKey,
    mls::{MlsExporter, MlsKeyId, MlsKeyIdBitRange},
};

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
        EncryptionKey::derive_from_mls(CipherSuite::AesGcm256Sha512, &exporter, key_id).unwrap();
}

#[test]
fn derive_key_from_mls_failed_export() {
    let exporter = TestMlsExporter { fail: true };
    let key_id = MlsKeyId::try_new(0u64, 3u64, 5u64, MlsKeyIdBitRange::new(4, 4)).unwrap();

    let result = EncryptionKey::derive_from_mls(CipherSuite::AesGcm256Sha512, &exporter, key_id);

    assert!(result.is_err());
}
