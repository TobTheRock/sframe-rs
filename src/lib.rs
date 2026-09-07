//! # Secure Frame (`SFrame`)
//! This library is an implementation of [SFrame (RFC 9605)](https://www.rfc-editor.org/rfc/rfc9605.html).
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
//!
//! # Module layout
//!
//! - [`frame`] — encrypting and decrypting media frames. The main API: [`frame::MediaFrameView`]
//!   and [`frame::EncryptedFrameView`] borrow a caller supplied buffer, [`frame::MediaFrame`] and
//!   [`frame::EncryptedFrame`] own one. Also the counters feeding the `SFrame` header and the
//!   [`frame::FrameBuffer`] trait to encrypt into a buffer of your own.
//! - [`frame::validation`] — screening incoming frames before decryption and recording them after,
//!   e.g. [`frame::validation::ReplayAttackProtectionStore`] against replay attacks.
//! - [`key`] — `EncryptionKey` and `DecryptionKey`, derived from shared key material,
//!   plus the [`key::KeyStore`] trait the decryption side looks keys up through.
//! - [`ratchet`] — the same keys, ratcheted forward per key generation, and the key ids encoding it.
//! - [`mls`] — deriving keys from an MLS group, and the key ids encoding epoch and member.
//! - [`header`] — the `SFrame` header on the wire, if you need to inspect or build one yourself.
//! - [`error`] — [`error::SframeError`] and the crate's [`error::Result`].
//! - [`crypto`] — only needed to bring your own crypto backend, see above.
//!
//! [`CipherSuite`] is at the crate root, every key derivation and crypto backend takes one.

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
