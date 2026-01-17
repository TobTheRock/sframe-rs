//! OpenSSL-based cryptographic operations.
//!
//! This module uses unsafe code for in-place encryption/decryption operations.
#[allow(unsafe_code)]
pub mod aead;
pub mod key_derivation;
