//! RustCrypto-based cryptographic operations.
//!
//! This module uses pure Rust implementations from the RustCrypto project.

mod aead;
mod key_derivation;

use crate::{CipherSuite, error::SframeError};

/// AEAD implementation using RustCrypto libraries.
///
/// Supports both AES-GCM and AES-CTR cipher suites.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aead {
    cipher_suite: CipherSuite,
}

impl TryFrom<CipherSuite> for Aead {
    type Error = SframeError;

    fn try_from(cipher_suite: CipherSuite) -> Result<Self, Self::Error> {
        // RustCrypto supports all cipher suites
        Ok(Self { cipher_suite })
    }
}

/// Key derivation implementation using RustCrypto libraries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Kdf;
