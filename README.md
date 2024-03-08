# Secure Frame (SFrame)

[![build](https://img.shields.io/github/actions/workflow/status/TobTheRock/sframe-rs/ci_cd.yml?branch=main)](https://github.com/TobTheRock/sframe-rs/actions?query=workflow%3A"Continuous+Integration")
[![version](https://img.shields.io/crates/v/sframe)](https://crates.io/crates/sframe/)
[![Crates.io](https://img.shields.io/crates/d/sframe)](https://crates.io/crates/sframe)
[![license](https://img.shields.io/crates/l/sframe.svg?style=flat)](https://crates.io/crates/sframe/)
[![documentation](https://img.shields.io/badge/docs-latest-blue.svg)](https://docs.rs/sframe/)
![maintenance](https://img.shields.io/maintenance/yes/2024)

This library is an implementation of [draft-ietf-sframe-enc-06](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-06) and provides and end-to-end encryption mechanism for media frames that is suited for WebRTC conferences.
It was forked from the original [goto-opensource/secure-frame-rs](https://github.com/goto-opensource/secure-frame-rs) and is continued here.

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

## Usage

Depending on your use case, this library offers two distinct APIs.

### Sender / Receiver API

This API provides an easy to use interface to the `Sframe` implementation. The `Sender` / `Receiver`:

- model the sframe encryption/decryption block in the data path, see [sframe draft 06 4.1](https://www.ietf.org/archive/id/draft-ietf-sframe-enc-06.html#name-application-context)
- derive and store the necessary `Sframe` key(s)
- keep an internal, dynamic buffer to encrypt/ decrypt a single frame at one time
- provide ratchet support as of [sframe draft 06 5.1](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-06#section-5.1)
- optional frame validation before decryption
- For example you can use them like this:

```rust
...

let key_id = 123;
let key_material = "pw123";
let skipped_payload = 1; // payload bytes which are skipped for encryption
let media_frame = b"SOME DATA";

let mut sender = Sender::new(key_id);
sender.set_encryption_key(key_material).unwrap();
let encrypted_frame = sender
  .encrypt(media_frame, skipped_payload)
  .unwrap();

let mut receiver = Receiver::default();
receiver
    .set_encryption_key(key_id, key_material)
    .unwrap();
let decrypted_frame = receiver.decrypt(encrypted_frame, skipped_payload).unwrap();

assert_eq!(media_frame, decrypted_frame);
```

For more options see the [encrypt_decrypt example](https://github.com/TobTheRock/sframe-rs/blob/feat/low-level-api/examples/encrypt_decrypt.rs).

### Frame-based API

This API provides low-level access to encryption and decryption at the frame level, offering granular control.
It allows the use of arbitrary buffers, enabling the creation of views to avoid unnecessary copies:

- `MediaFrameView` for unencrypted data
- `EncryptedFrameView` for encrypted data

For encryption and decryption, a buffer must be provided implementing the `FrameBuffer` trait to allocate the necessary memory. For convenience, this trait has already been implemented for `Vec<u8>`.
For example:

```rust
...

let mut key: SframeKey = ...;

let frame_count = 1u8;
let payload = "Something secret";

let mut encrypt_buffer = Vec::new();
let mut decrypt_buffer = Vec::new();
let media_frame = MediaFrameView::new(frame_count, payload);

let encrypted_frame = media_frame.encrypt_into(&key, &mut encrypt_buffer).unwrap();

let decrypted_media_frame = encrypted_frame
  .decrypt_into(&mut key, &mut decrypt_buffer)
  .unwrap();

assert_eq!(decrypted_media_frame, media_frame);

```

- `MediaFrame` for unencrypted data
- `EncryptedFrame` for encrypted data

To see how the API is used with another buffer type, you can check out the [bip_frame_buffer example](https://github.com/TobTheRock/sframe-rs/blob/main/examples/bip_frame_buffer.rs).

## Benchmarks

The `criterion` benchmarks located at [./benches](https://github.com/TobTheRock/sframe-rs/tree/feat/low-level-api/benches) currently test

- encryption/decryption with all available cipher suites and different frame size
- key derivation with all available cipher suites
- header (de)serialization

They are tracked continously with a [Bencher Perf Page](https://bencher.dev/perf/sframe-rs?back=L2NvbnNvbGUvb3JnYW5pemF0aW9ucy90b2J0aGVyb2NrL3Byb2plY3RzP3Blcl9wYWdlPTgmcGFnZT0x&key=true&reports_per_page=4&branches_per_page=8&testbeds_per_page=8&benchmarks_per_page=8&reports_page=1&branches_page=1&testbeds_page=1&benchmarks_page=1):
<a href="https://bencher.dev/perf/sframe-rs?back=L2NvbnNvbGUvb3JnYW5pemF0aW9ucy90b2J0aGVyb2NrL3Byb2plY3RzP3Blcl9wYWdlPTgmcGFnZT0x&key=true&reports_per_page=4&branches_per_page=8&testbeds_per_page=8&benchmarks_per_page=8&reports_page=1&branches_page=1&testbeds_page=1&benchmarks_page=1"><img src="https://api.bencher.dev/v0/projects/sframe-rs/perf/img?branches=99fe8511-3287-48d2-93f3-36379605c572&testbeds=b02e6299-bb69-4543-a09f-e168f88d72a0%2C388324aa-501e-49ca-b012-3e1054b4b2a5&benchmarks=ac01dbfe-7841-4813-9016-e6c2fb5b3e2a%2C7dab951e-b008-4748-9467-bceddbdc6c97%2Caa4e3c86-7cbe-4531-9cda-f1718843eece%2C49f6ad47-88db-4648-82f2-cbd9f6c8c0dd%2Ca8fc78f0-437f-4015-bbca-54988a7ef2c3&measures=e050a8d7-e788-4ce5-9e95-48870f805da3&title=Decryption" title="Decryption" alt="Decryption for sframe-rs - Bencher" /></a>
<a href="https://bencher.dev/perf/sframe-rs?back=L2NvbnNvbGUvb3JnYW5pemF0aW9ucy90b2J0aGVyb2NrL3Byb2plY3RzP3Blcl9wYWdlPTgmcGFnZT0x&key=true&reports_per_page=4&branches_per_page=8&testbeds_per_page=8&benchmarks_per_page=8&reports_page=1&branches_page=1&testbeds_page=1&benchmarks_page=1"><img src="https://api.bencher.dev/v0/projects/sframe-rs/perf/img?branches=99fe8511-3287-48d2-93f3-36379605c572&testbeds=b02e6299-bb69-4543-a09f-e168f88d72a0%2C388324aa-501e-49ca-b012-3e1054b4b2a5&benchmarks=acf725e4-cd56-4471-bd94-ef143db7da78%2C8fa81434-f422-4dbf-b209-df4a7ec710a8%2C757fa277-0938-49d6-8627-4502a9de9a29%2C957e48a3-1efe-4fe5-a1dd-d8c5405d77d9%2C8a5754f5-c03a-495d-b9a8-9ab927ccfebf&measures=e050a8d7-e788-4ce5-9e95-48870f805da3&title=Encryption" title="Encryption" alt="Encryption for sframe-rs - Bencher" /></a>
<a href="https://bencher.dev/perf/sframe-rs?back=L2NvbnNvbGUvb3JnYW5pemF0aW9ucy90b2J0aGVyb2NrL3Byb2plY3RzP3Blcl9wYWdlPTgmcGFnZT0x&key=true&reports_per_page=4&branches_per_page=8&testbeds_per_page=8&benchmarks_per_page=8&reports_page=1&branches_page=1&testbeds_page=1&benchmarks_page=1"><img src="https://api.bencher.dev/v0/projects/sframe-rs/perf/img?branches=99fe8511-3287-48d2-93f3-36379605c572&testbeds=b02e6299-bb69-4543-a09f-e168f88d72a0%2C388324aa-501e-49ca-b012-3e1054b4b2a5&benchmarks=f817d982-5073-45d1-8727-021569683502%2Cf144e648-b192-4514-81fc-f14bca4fba41%2Cabd325b0-57e2-411c-8a86-4ef6d1c45279%2C8c97fef3-a7e3-48ea-b20b-16c26f5d6a98%2Cabca60fb-54e9-4dff-9041-81314d0012d5&measures=e050a8d7-e788-4ce5-9e95-48870f805da3&title=Key+Derivation" title="Key Derivation" alt="Key Derivation for sframe-rs - Bencher" /></a>

## Contribution

Any help in form of descriptive and friendly issues or comprehensive pull requests are welcome!

The Changelog of this library is generated from its commit log, there any commit message must conform with https://www.conventionalcommits.org/en/v1.0.0/. For simplicity you could make your commits with convco.

#### License

<sup>
Licensed under either of Apache License, Version 2.0 or MIT license at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
</sub>
