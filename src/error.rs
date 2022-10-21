use std::error::Error;

use crate::header::KeyId;

pub type GenericResult<OkType> = std::result::Result<OkType, Box<dyn Error>>;

pub type Result<T> = std::result::Result<T, SframeError>;

#[derive(PartialEq, Eq, Debug, thiserror::Error)]
pub enum SframeError {
    #[error("Key Id {0} is not valid")]
    InvalidKeyId(u64),

    #[error("No EncryptionKey has been set")]
    MissingEncryptionKey,

    #[error("No DecryptionKey has been found")]
    MissingDecryptionKey(KeyId),

    #[error("Failed to Decrypt")]
    DecryptionFailure,

    #[error("Failed to Encrypt")]
    EncryptionFailure,

    #[error("Invalid MediaType")]
    InvalidMediaType,

    #[error("Unable to create unbound encryption key")]
    KeyExpansion,

    #[error("{0}")]
    Other(String),
}
