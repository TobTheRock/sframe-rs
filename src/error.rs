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

impl SframeError {
    /// Recovers the error of a custom component, e.g. the rejection of a
    /// [`FrameValidation`](crate::frame::validation::FrameValidation).
    ///
    /// Name the type you installed to get its error back, [`None`] if this error
    /// came from elsewhere.
    ///
    /// ```ignore
    /// let error = encrypted
    ///     .validated_decrypt_into(&mut dec_key, &mut buffer, &mut validator)
    ///     .unwrap_err();
    ///
    /// if let Some(ReplayAttackProtectionError::DuplicatedFrame { .. }) =
    ///     error.source_as::<ReplayAttackProtectionError>()
    /// {
    ///     // ...
    /// }
    /// ```
    pub fn source_as<E>(&self) -> Option<&E>
    where
        E: std::error::Error + 'static,
    {
        std::error::Error::source(self)?.downcast_ref()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[derive(Debug, PartialEq, Eq, thiserror::Error)]
    #[error("the custom component rejected it")]
    struct CustomError;

    #[test]
    fn recovers_the_error_of_a_custom_component() {
        let error = SframeError::FrameValidationFailed(Box::new(CustomError));

        assert_eq!(error.source_as::<CustomError>(), Some(&CustomError));
    }

    #[test]
    fn recovers_nothing_of_another_type() {
        let error = SframeError::FrameValidationFailed(Box::new(CustomError));

        assert!(error.source_as::<std::fmt::Error>().is_none());
    }

    #[test]
    fn recovers_nothing_without_a_source() {
        let error = SframeError::DecryptionFailure;

        assert!(error.source_as::<CustomError>().is_none());
    }
}
