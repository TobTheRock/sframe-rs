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

mod crypto;
mod util;

/// error definitions
pub mod error;
pub mod frame;
/// Sframe header definitions as of [RFC 9605 4.3](https://www.rfc-editor.org/rfc/rfc9605.html#name-sframe-header)
pub mod header;
/// sframe key definitions as of [RFC 9605 4.4.2](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.2)
pub mod key;
/// Sframe MLS definitions as of [RFC 9605 5.2](https://www.rfc-editor.org/rfc/rfc9605.html#name-mls)
pub mod mls;
/// Ratchet support as of [RFC 9605 5.1](https://www.rfc-editor.org/rfc/rfc9605.html#section-5.1)
pub mod ratchet;

pub use crypto::cipher_suite::CipherSuite;

#[cfg(test)]
#[allow(clippy::all)]
pub mod test_vectors;
