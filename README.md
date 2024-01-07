Secure Frame (SFrame)
=======================
[![build](https://img.shields.io/github/actions/workflow/status/goto-opensource/secure-frame-rs/ci_cd.yml?branch=main)](https://github.com/goto-opensource/secure-frame-rs/actions?query=workflow%3A"Continuous+Integration")
[![version](https://img.shields.io/crates/v/sframe)](https://crates.io/crates/sframe/)
[![Crates.io](https://img.shields.io/crates/d/sframe)](https://crates.io/crates/sframe)
[![license](https://img.shields.io/crates/l/sframe.svg?style=flat)](https://crates.io/crates/sframe/)
[![documentation](https://img.shields.io/badge/docs-latest-blue.svg)](https://docs.rs/sframe/)
![maintenance](https://img.shields.io/maintenance/yes/2024)


This library is an implementation of [draft-ietf-sframe-enc-03](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-03) and provides and end-to-end encryption mechanism for media frames that is suited for WebRTC conferences.
It is in it's current form a subset of the specification.
There is an alternative implementation under [goto-opensource/secure-frame-ts](https://github.com/goto-opensource/secure-frame-ts)

## Differences from the sframe draft
* ratcheting is not implemented
* no metadata authentication

## Supported crypto libraries
Currently two crypto libraries are supported:
- [ring](https://crates.io/crates/ring)
    - is enabled per default with the feature `ring`
    - supports compilation to Wasm32
    - Aes-CTR mode ciphers are not supported
- [openssl](https://crates.io/crates/openssl)
    - is enabled with the feature `openssl`
        - To build e.g. use `cargo build --features openssl --no-default-features`
    - uses rust bindings to OpenSSL.
    - Per default the OpenSSL library is locally compiled and then statically linked. The build process requires a C compiler, `perl` (and `perl-core`), and `make`. For further options see the [openssl crate documentation](https://docs.rs/openssl/0.10.55/openssl/).
    - Compilation to Wasm32 is [not yet supported](https://github.com/sfackler/rust-openssl/issues/1016)

Both cannot be enabled at the same time, thus on conflict `sframe` issues a compiler error.
## License
Licensed under either of Apache License, Version 2.0 or MIT license at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Contribution
Any help in form of descriptive and friendly issues or comprehensive pull requests are welcome!

The Changelog of this library is generated from its commit log, there any commit message must conform with https://www.conventionalcommits.org/en/v1.0.0/. For simplicity you could make your commits with convco.
