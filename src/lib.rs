//! # Secure Frame (`SFrame`)
//! This library is an implementation of [SFrame (RFC 9605)](https://www.rfc-editor.org/rfc/rfc9605.html).
//!
//! # Usage
//!
//! [`frame`] is the main API. It encrypts and decrypts whole media frames with a key from
//! [`key`], writing and parsing the `SFrame` header on the way:
//!
//! ```rust
//! use sframe::{
//!     CipherSuite,
//!     frame::{MediaFrame, MonotonicCounter},
//!     key::{DecryptionKey, EncryptionKey},
//! };
//!
//! # fn main() -> sframe::error::Result<()> {
//! const CIPHER_SUITE: CipherSuite = CipherSuite::AesGcm256Sha512;
//! let key_id = 42u64;
//!
//! // both sides derive their key from key material shared out of band
//! let enc_key = EncryptionKey::derive_from(CIPHER_SUITE, key_id, "pw123")?;
//! let dec_key = DecryptionKey::derive_from(CIPHER_SUITE, key_id, "pw123")?;
//!
//! let mut counter = MonotonicCounter::default();
//! let media_frame = MediaFrame::try_new(&mut counter, "Something secret")?;
//! let encrypted_frame = media_frame.encrypt(&enc_key)?;
//!
//! assert_eq!(encrypted_frame.decrypt(&dec_key)?, media_frame);
//! # Ok(())
//! # }
//! ```
//!
//! [`frame::MediaFrame`] and [`frame::EncryptedFrame`] own their buffer. The [`frame`] module
//! additionally offers:
//! - the **view API**, [`frame::MediaFrameView`] and [`frame::EncryptedFrameView`], which read
//!   from a buffer you hold and write into one you supply through [`frame::FrameBuffer`], so no
//!   copy is needed
//! - **meta data**, which stays unencrypted so a packetizer downstream can still read it, but is
//!   authenticated with the frame, so it cannot be tampered with
//!
//! Beyond a single key:
//! - [`key::KeyStore`] looks a decryption key up per Key ID, for a call with several senders
//! - [`frame::validation`] screens incoming frames before decryption, e.g. against replays
//! - [`ratchet`] ratchets a key forward instead of distributing a new one
//! - [`mls`] derives keys from an MLS group
//!
//! # Optional features
//!
//! Using optional features `sframe` allows to configure different crypto libraries.
//! Be aware that those features are mutually exlusive, if multiple are configured `sframe` issues a compiler error.
//!
//! - **`ring`** *(enabled by default)* — Uses the [ring](https://crates.io/crates/ring) library which allows compilation to Wasm32.
//!   AES-CTR mode ciphers are not supported.
//! - **`openssl`** — Uses the [rust-openssl](https://crates.io/crates/openssl) crate, which provides bindings to OpenSSL.
//!   Per default the OpenSSL library is locally compiled and then statically linked. The build process requires a C compiler,
//!   `perl` (and `perl-core`), and `make`. For further options see the [openssl crate documentation](https://docs.rs/openssl/0.10.55/openssl/).
//!   Compilation to Wasm32 is not yet supported.
//! - **`rust-crypto`** - Uses pure rust implementations of the  [RustCrypto](https://github.com/RustCrypto) project. Compilation to Wasm32 is supported.
//!
//! If none of these features is enabled, only the generic crypto traits in [`crypto`] are exposed and a
//! custom crypto backend has to be provided by implementing [`crypto::AeadEncrypt`], [`crypto::AeadDecrypt`]
//! and [`crypto::KeyDerivation`], then parameterizing [`key::GenericEncryptionKey`] /
//! [`key::GenericDecryptionKey`] with your types. See the `custom-crypto-backend` example for a
//! walkthrough.
//!
//! With a backend feature enabled, `key::EncryptionKey` and `key::DecryptionKey` are aliases
//! of those pinned to it, so the type parameters never have to be spelled out.

#![deny(clippy::missing_panics_doc)]
#![deny(
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unused_import_braces,
    unused_qualifications
)]
#![warn(
    missing_docs,
    clippy::doc_markdown,
    clippy::semicolon_if_nothing_returned,
    clippy::single_match_else,
    clippy::inconsistent_struct_constructor,
    clippy::map_unwrap_or,
    clippy::match_same_arms
)]

pub(crate) mod cipher_suite;
pub mod crypto;
pub mod error;
pub mod frame;
pub mod header;
pub mod key;
pub mod mls;
pub mod ratchet;

mod util;

pub use cipher_suite::CipherSuite;

#[cfg(test)]
#[allow(clippy::all)]
pub mod test_vectors;

/// Compiles the README's code examples as doctests, so they cannot rot.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
