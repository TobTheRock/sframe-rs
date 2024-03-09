# Changelog

All notable changes to this project will be documented in this file.

## [0.5.2] - 2024-03-03

### Features

- MLS definitions as of section 5.2

### Performance

- Do not copy media frame data in sframe sender

## [0.5.1] - 2024-03-01

### Features

- Add bencher benchmark tracking
- Frame based API
- Add a public sframe key implementation

## [0.5.0] - 2024-02-04

### Features

- [**breaking**] Using meta data as AD
  > As due to this change the AAD used for authenticity protection now differs, encryption/decryption is longer compatible with older library version .
- Update to draft 06

## [0.4.2] - 2024-01-28

### Features

- Implement key id with ratcheting support
- Ratcheting support of section 5.1

## [0.4.1] - 2024-01-10

### Bug Fixes

- Frame counter never reached u64:max

### Features

- Create Receiver with optional frame_validation
- Configure max frame count for Sender

## [0.4.0] - 2024-01-07

### Features

- [**breaking**] Update key derivation to draft-04
  > due to the changes in the key derivation
  > encryption/decryption is incompatible with previous versions.
- [**breaking**] Implement header according to draft 04
  > Due to the changes in the draft, the frame count is now serialized differently
  > if it is < 8. As a result it is no longer compatible with previous drafts
  > See the [diff](https://author-tools.ietf.org/iddiff?url1=draft-ietf-sframe-enc-03&url2=draft-ietf-sframe-enc-04&difftype=--html) for details. Also `header::Header` was reimplemented as `header::SframeHeader`.
- Implement Display for SframeHeader

## [0.3.0] - 2023-10-28

### Features

- [**breaking**] Update key derivation / tag computation to draft-03
  > The latest [changes in the draft](https://author-tools.ietf.org/diff?doc_1=draft-ietf-sframe-enc-01&doc_2=draft-ietf-sframe-enc-03) regarding the key derivation and tag computation, make theimplementation incompatible with previous versions

## [0.2.2] - 2023-08-02

### Features

- Aes ctr mode ciphers for openssl

## [0.2.1] - 2023-07-17

### Bug Fixes

- Wrong auth tag size

### Features

- Update to draft enc-01
- Add openssl crypto crate stub
- Implement hkdf with openssl
- Openssl aead implemenation
- Crypto library feature handling

## [0.2.0] - 2023-04-28

### Features

- Add Receiver::remove_encryption_key()
- Add FrameValidation in Receiver
- Impl from trait for KeyId
- Implement AesGcm128Sha256
- Allow configuring ciphersuite of sender and receiver
- Github actions

### Performance

- Set participant key in decrypt benchmark
- Avoid some allocation in extended header parsing
- Avoid some allocation in basic header parsing
- Improved nonce creation
- [**breaking**] Reusable, internal buffer in sender/receiver
  > decrypt requires receiver to be mutable.

The user is now responsible of copying data on subsequential encrypt/decrypt calls. E.g.

```rust
        let frame = sender
            .encrypt(&data, 0)?;
        let frame2 = sender
            .encrypt(&data2, 0)?;
// could be replaced with
        let frame = sender
            .encrypt(&data, 0)?
            .to_vec();
        let frame2 = sender
            .encrypt(&data2, 0)?;
```

## [0.1.0] - 2022-12-16

### Features

- Add Receiver::remove_encryption_key()
- Add FrameValidation in Receiver
- Impl from trait for KeyId
- Implement AesGcm128Sha256
- Allow configuring ciphersuite of sender and receiver
- Github actions

### Performance

- Set participant key in decrypt benchmark
- Avoid some allocation in extended header parsing
- Avoid some allocation in basic header parsing
