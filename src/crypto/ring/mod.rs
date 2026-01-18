//! Ring backend implementation for SFrame crypto operations.

mod aead;
mod key_derivation;

use crate::{CipherSuite, error::SframeError};

/// AEAD implementation using the ring library.
///
/// Supports AES-GCM cipher suites only (ring does not support AES-CTR).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aead {
    cipher_suite: CipherSuite,
}

impl TryFrom<CipherSuite> for Aead {
    type Error = SframeError;

    fn try_from(cipher_suite: CipherSuite) -> Result<Self, Self::Error> {
        // Ring only supports GCM modes
        match cipher_suite {
            CipherSuite::AesGcm128Sha256 | CipherSuite::AesGcm256Sha512 => {
                Ok(Self { cipher_suite })
            }
            #[allow(unreachable_patterns)]
            _ => Err(SframeError::UnsupportedCipherSuite),
        }
    }
}

/// Key derivation implementation using the ring library.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Kdf;
