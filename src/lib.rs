//! # Secure Frame (`SFrame`)
//! This library is an implementation of [draft-ietf-sframe-enc-06](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-06).
//!
//! # Optional features
//!
//! Using optional features `sframe` allows to configure different crypto libraries.
//! Be aware that those features are mutually exlusive, if multiple are configured `sframe` issues a compiler error.
//!
//! - **`ring`** *(enabled by default)* — Uses the [ring](https://crates.io/crates/ring) library which allows compilation to Wasm32.
//! AES-CTR mode ciphers are not supported.
//! - **`openssl`** — Uses the [rust-openssl](https://crates.io/crates/openssl) crate, which provides bindings to OpenSSL.
//! Per default the OpenSSL library is locally compiled and then statically linked. The build process requires a C compiler,
//! `perl` (and `perl-core`), and `make`. For further options see the [openssl crate documentation](https://docs.rs/openssl/0.10.55/openssl/).
//! Compilation to Wasm32 is not yet supported.

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
    // missing_docs,
    clippy::doc_markdown,
    clippy::semicolon_if_nothing_returned,
    clippy::single_match_else,
    clippy::inconsistent_struct_constructor,
    clippy::map_unwrap_or,
    clippy::match_same_arms
)]

mod crypto;
mod frame_count_generator;
mod util;

/// error definitions
pub mod error;
pub mod frame;
/// sframe header validation before decryption, e.g. to detect replay attacks see [sframe draft 06 9.3](https://www.ietf.org/archive/id/draft-ietf-sframe-enc-06.html#name-anti-replay)
pub mod frame_validation;
/// sframe header definitions as of [sframe draft 06 4.3](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-06#name-sframe-header)
pub mod header;
pub mod key;
/// ratchet support as of [sframe draft 06 5.1](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-06#section-5.1)
pub mod ratchet;
/// models the sframe decryption block in the receiver path, see [sframe draft 06 4.1](https://www.ietf.org/archive/id/draft-ietf-sframe-enc-06.html#name-application-context)
pub mod receiver;
/// models the sframe encryption block in the sender path, [sframe draft 06 4.1](https://www.ietf.org/archive/id/draft-ietf-sframe-enc-06.html#name-application-context)
pub mod sender;

pub use crypto::cipher_suite::CipherSuiteVariant;

#[cfg(test)]
pub mod test_vectors;
