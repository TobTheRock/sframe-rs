use crate::header::KeyId;

/// Represents either success(T) or an failure ([`SframeError`])
pub type Result<T> = std::result::Result<T, SframeError>;

/// Represents an error which has occured in the sframe-rs library
#[derive(PartialEq, Eq, Debug, thiserror::Error)]
pub enum SframeError {
    /// no valid decryption key has been found
    #[error("No DecryptionKey has been found")]
    MissingDecryptionKey(KeyId),

    /// Failed to decrypt a frame with AEAD
    #[error("Failed to Decrypt")]
    DecryptionFailure,

    /// Failed to encrypt a frame with AEAD
    #[error("Failed to Encrypt")]
    EncryptionFailure,

    /// Could not expand encryption/decryption key with HKDF
    #[error("Unable to create unbound encryption key")]
    KeyDerivationFailure,

    /// Could not ratchet an decryption key with HKDF
    #[error("Unable to create unbound encryption key")]
    RatchetingFailure,

    /// The cipher suite is not supported by the current crypto backend
    #[error("Cipher suite is not supported by this backend")]
    UnsupportedCipherSuite,

    /// frame validation failed before decryption
    #[error("{0}")]
    FrameValidationFailed(String),

    /// buffer was too small to deserialize into/ serialize from
    #[error("buffer with size {0} is too small")]
    InvalidBuffer(usize),

    /// any arbitrary error
    #[error("{0}")]
    Other(String),
}
