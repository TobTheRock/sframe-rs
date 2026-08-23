use crate::header::KeyId;

/// Represents either success(T) or an failure ([`SframeError`])
pub type Result<T> = std::result::Result<T, SframeError>;

/// Represents an error which has occured in the sframe-rs library
///
/// Non-exhaustive: match with a `_` arm, new variants may be added in minor releases.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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

    /// Could not ratchet an decryption key with HKDF, or too many ratchet steps were requested
    #[error("Unable to ratchet the decryption key")]
    RatchetingFailure,

    /// The cipher suite is not supported by the current crypto backend
    #[error("Cipher suite is not supported by this backend")]
    UnsupportedCipherSuite,

    /// frame validation failed before decryption
    #[error("{0}")]
    FrameValidationFailed(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// buffer was too small to deserialize into/ serialize from
    #[error("buffer with size {0} is too small")]
    InvalidBuffer(usize),

    /// any arbitrary error
    #[error("{0}")]
    Other(String),
}
