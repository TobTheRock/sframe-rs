# Changelog

All notable changes to this project will be documented in this file.

## [0.4.0] - 2024-01-07

### Bug Fixes

- Wrong auth tag size

### Features

- Add Receiver::remove_encryption_key()
- Add FrameValidation in Receiver
- Impl from trait for KeyId
- Implement AesGcm128Sha256
- Allow configuring ciphersuite of sender and receiver
- Github actions
- Update to draft enc-01
- Add openssl crypto crate stub
- Implement hkdf with openssl
- Openssl aead implemenation
- Crypto library feature handling
- Aes ctr mode ciphers for openssl
- [**breaking**] Update key derivation / tag computation to draft-03
The latest [changes in the draft](https://author-tools.ietf.org/diff?doc_1=draft-ietf-sframe-enc-01&doc_2=draft-ietf-sframe-enc-03) regarding the key derivation and tag computation, make theimplementation incompatible with previous versions
- [**breaking**] Update key derivation to draft-04
due to the changes in the key derivation
encryption/decryption is incompatible with previous versions.
- [**breaking**] Implement header according to draft 04
Due to the changes in the draft, the frame count is now serialized differently
if it is < 8. As a result it is no longer compatible with previous drafts
See the (diff)[https://author-tools.ietf.org/iddiff?url1=draft-ietf-sframe-enc-03&url2=draft-ietf-sframe-enc-04&difftype=--html] for details. Also `header::Header` was reimplemented as `header::SframeHeader`.
- Implement Display for SframeHeader

### Performance

- Set participant key in decrypt benchmark
- Avoid some allocation in extended header parsing
- Avoid some allocation in basic header parsing
- Improved nonce creation
- [**breaking**] Reusable, internal buffer in sender/receiver
decrypt requires receiver to be mutable.

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

## [0.3.0] - 2023-10-28

### Features

- [**breaking**] Update key derivation / tag computation to draft-03
The latest [changes in the draft](https://author-tools.ietf.org/diff?doc_1=draft-ietf-sframe-enc-01&doc_2=draft-ietf-sframe-enc-03) regarding the key derivation and tag computation, make theimplementation incompatible with previous versions

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
decrypt requires receiver to be mutable.

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

* github actions
  ([bc1c759](https://github.com/goto-opensource/secure-frame-rs/commit/bc1c7591959bb2ff5a1cb6d2e7434517d2264bae))
* allow configuring ciphersuite of sender and receiver
  ([ca15a48](https://github.com/goto-opensource/secure-frame-rs/commit/ca15a480178ef127940aee7c757f5b75c99f9ca0))
* implement AesGcm128Sha256
  ([6b8fd43](https://github.com/goto-opensource/secure-frame-rs/commit/6b8fd43f55c3057617f802f2d895dcf6068db267))
* impl from trait for KeyId
  ([37873e1](https://github.com/goto-opensource/secure-frame-rs/commit/37873e1fd8e0c0576c84bd08300ba36cec713585))
* add FrameValidation in Receiver
  ([77e4f05](https://github.com/goto-opensource/secure-frame-rs/commit/77e4f05b13294198e35b8520de9a86ff6cff719f))
* add Receiver::remove_encryption_key()
  ([082e6f3](https://github.com/goto-opensource/secure-frame-rs/commit/082e6f31af783e131cc53b1d68dc155e4665ec80))
