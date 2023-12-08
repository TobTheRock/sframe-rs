// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

use crate::header::KeyId;

/// Represents either success(T) or an failure ([`SframeError`])
pub type Result<T> = std::result::Result<T, SframeError>;

/// Represents an error which has occured in the sframe-rs library
#[derive(PartialEq, Eq, Debug, thiserror::Error)]
pub enum SframeError {
    /// [`Sender`] has no valid encryption key set
    #[error("No EncryptionKey has been set")]
    MissingEncryptionKey,

    /// `Receiver` has no valid encryption key set
    #[error("No DecryptionKey has been found")]
    MissingDecryptionKey(KeyId),

    /// Failed to decrypt a frame with AEAD
    #[error("Failed to Decrypt")]
    DecryptionFailure,

    /// Failed to encrypt a frame with AEAD
    #[error("Failed to Encrypt")]
    EncryptionFailure,

    /// Could not expand encryption key for [`Sender`] or decryption key for [`Receiver`] with HKDF
    #[error("Unable to create unbound encryption key")]
    KeyDerivation,

    /// frame validation failed in the [`Receiver`] before decryption
    #[error("{0}")]
    FrameValidationFailed(String),

    /// buffer was too small to deserialize into/ serialize from
    #[error("buffer with size {0} is too small")]
    InvalidBuffer(usize),

    /// any arbitrary error
    #[error("{0}")]
    Other(String),
}
