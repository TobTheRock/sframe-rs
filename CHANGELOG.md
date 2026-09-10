# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] - 2026-09-10

### Bug Fixes

- Make the wasm-webrtc example compile again ([#114](https://github.com/TobTheRock/sframe-rs/issues/114))

### Features

- [**breaking**] Mark SframeError as non exhaustive

> **BREAKING CHANGE:** `match` on `SframeError` no longer compiles without a
> wildcard arm. Add `_ => ...` to any exhaustive match over the enum.
> Struct-like construction from outside the crate is unaffected, all
> variants stay public.
- [**breaking**] Box any error type in FrameValidationFailed

> **BREAKING CHANGE:** `SframeError` no longer implements `PartialEq`/`Eq`.
> Replace `assert_eq!(err, SframeError::X)` with
> `assert!(matches!(err, SframeError::X))`.
> `FrameValidationFailed` now holds `Box<dyn Error + Send + Sync>` instead
> of `String`: construct it with `format!(..).into()` or
- [**breaking**] Screen frames before decryption, record them after (https://github.com/TobTheRock/sframe-rs/issues/95)

> **BREAKING CHANGE:** `FrameValidation::validate` is replaced by `screen` and
> `record`, along with the associated types `Token` and `Error`. Implement
> `fn screen(&self, UnvalidatedFrame<'_>) -> Result<Self::Token, Self::Error>`
> and `fn record(&mut self, Self::Token)`, reading the header via
- [**breaking**] Protect a single KID per ReplayAttackProtection
- Recover a custom component error from SframeError
- [**breaking**] Let the frame counter fail ([#96](https://github.com/TobTheRock/sframe-rs/issues/96))

> **BREAKING CHANGE:** `FrameCounter::next` is replaced by `try_next` returning
> a `Result`. `MediaFrame::new`, `MediaFrameView::new` and their
> `with_meta_data` variants now require a counter which cannot fail, use
> `try_new`/`try_with_meta_data` or a `PanickingMonotonicCounter` instead.
- [**breaking**] Type the key id bit ranges ([#100](https://github.com/TobTheRock/sframe-rs/issues/100))

> **BREAKING CHANGE:** `RatchetingKeyId::new`, `RatchetingKeyId::from_key_id`
> and `RatchetingKeyStore::new` take a `RatchetBits` instead of a `u8`.
- [**breaking**] Address ratcheting keys by their generation ([#100](https://github.com/TobTheRock/sframe-rs/issues/100))

> **BREAKING CHANGE:** `RatchetingKeyStore::insert`, `remove` and `get` take a
> `Generation` instead of a key id. `insert` derives its key at Ratchet
> Step 0 and fails with `SframeError::OutOfRange` if the generation does
> not fit the configured ratchet bits.
- [**breaking**] Ratchet the sframe keys themselves ([#100](https://github.com/TobTheRock/sframe-rs/issues/100))

> **BREAKING CHANGE:** RatchetingBaseKey is gone, and the ratcheting key store neither
> derives keys nor knows the No. ratchet bits anymore.
> 
> To migrate:
> - senders: hold a RatchetingEncryptionKey (derive_from once, then ratchet() per
>   step) instead of feeding ratchet_encryption_key with the key id and key
>   material of a RatchetingBaseKey
> - receivers: insert a RatchetingDecryptionKey you derived, and replace
>   try_ratchet(key_id) plus the get_key lookup with
>   with_ratcheted_key(key_id, |key| ..decrypt..)
> - the store is addressed by a RatchetingKeyId now, parse the header key id with
>   RatchetingKeyId::from_key_id(key_id, n_ratchet_bits) and keep the No. ratchet
>   bits of your session yourself
> - RatchetingKeyStore::new(max_ratchet_steps) takes the No. Ratchet Steps a
>   single frame may catch up with, it is mandatory instead of
>   with_max_ratchet_steps. It stays capped at
>   RatchetBits::max_distinguishable_steps, which no longer counts the diff of
>   exactly half the steps - as many steps forward as back, so it never could be
>   told apart from a step which was already passed
> - the distance between two Ratchet Steps is a RatchetStepDiff now, as returned
>   by steps_between, max_distinguishable_steps and RatchetingKeyId::steps_to.
>   Catch a decryption key up with ratchet_to(key_id, max_steps), or ratchet() to
>   take a single step
- [**breaking**] Mark CipherSuite non exhaustive ([#114](https://github.com/TobTheRock/sframe-rs/issues/114))

> **BREAKING CHANGE:** a `match` on `CipherSuite` outside this crate now needs a
> catch-all arm.
- [**breaking**] Reject an invalid replay tolerance instead of panicking

> **BREAKING CHANGE:** `ReplayAttackProtection::new` and
- [**breaking**] Let a FrameBuffer report an error of its own

> **BREAKING CHANGE:** `FrameBuffer` has an associated `Error` type and `allocate`
> returns `Result<&mut Self::BufferSlice, Self::Error>` rather than the crate's
> `Result`. `SframeError::Other` is removed; buffer failures arrive as
- [**breaking**] Reject a key id without ratcheting bits

> **BREAKING CHANGE:** `RatchetBits::new` panics and `RatchetBits::try_new` fails with
- [**breaking**] Let a key store record the key it handed out ([#119](https://github.com/TobTheRock/sframe-rs/issues/119))

> **BREAKING CHANGE:** `KeyStore::get_key` moved to the new `KeyLookup` trait, which
> is what a store providing keys per Key ID implements now. The frame API takes
> the key store by value, so a key passed as `&mut dec_key` has to be `&dec_key`.
- [**breaking**] Decrypt against a ratcheting key store directly ([#119](https://github.com/TobTheRock/sframe-rs/issues/119))

> **BREAKING CHANGE:** `GenericRatchetingKeyStore::with_ratcheted_key` is gone, use
> the key store API (`lookup`/`record`) or hand the store to the frame API.

### Refactor

- [**breaking**] Remove FrameValidationBox

> **BREAKING CHANGE:** `FrameValidationBox` is gone. Replace it with
> `Box<dyn FrameValidation>` and pass it as `frame.validate(&*boxed)`.
- Anchor the replay window with an Option
- [**breaking**] Keep the validation types in their own namespace
- Keep the public frame fns on top
- [**breaking**] Key the ratcheting store by generation ([#100](https://github.com/TobTheRock/sframe-rs/issues/100))

> **BREAKING CHANGE:** `RatchetingKeyId::generation` returns a `Generation`,
> `ratchet_step` a `RatchetStep`, both convertible to `u64`. Equality on
> `RatchetingKeyId` covers the whole key id including the Ratchet Step,
> compare `.generation()` for the previous behaviour. It is no longer
> hashable.
- [**breaking**] Reach every sframe type through a single module path ([#114](https://github.com/TobTheRock/sframe-rs/issues/114))

> **BREAKING CHANGE:** the backend generic types moved and gained a `Generic` prefix.


## [1.4.3] - 2026-08-23

### Bug Fixes

- Decrypt short payloads with rust crypto (AES-CTR)
- Warn at the correct generation overflow boundary
- Reject a ratchet step which was already passed


## [1.4.2] - 2026-08-21

### Bug Fixes

- Ratchet the base key by every missed step
- Zeroize RatchetingBaseKey
- Limit the ratchet bits when parsing a key id


## [1.4.1] - 2026-08-19

### Bug Fixes

- Avoid unsafe code by using CipherCtx API
- Harden decryption buffer truncation against underflow


## [1.4.0] - 2026-08-16

### Features

- Non-mutating inspect for ReplayAttackProtection
- Optionally associate a KID to ReplayAttackProtection
- ReplayAttackProtection Per KID
- MonotonicCounter panics instead of wrapping


## [1.3.1] - 2026-08-10

### Bug Fixes

- Assert nonce buffer fits salt to catch silent truncating
- Zeroize secrets on drop
- Secrets are only comparable for tests
- Redacted debug impl for secrets


## [1.3.0] - 2026-07-17

### Bug Fixes

- Replay protection, reject duplicate counters

> This drastically changes the behavior of the replay protection
    implementation, previously only the newest counter was tracked
    and older frames discarded. Now duplicate frame counts are detected
    within the window tolerance. Also it is enforced that the tolerance is neither 0 nor exceeds
    OS capabailities by panicking.

## [1.2.1] - 2026-07-10

### Dependencies

- Update aes-gcm from 0.10.3 to 0.11.0
- Update cipher from 0.4 to 0.5
- Update ctr from 0.9.2 to 0.10.0
- Update getrandom from 0.2 to 0.4

## [1.2.0] - 2026-06-20

### Bug Fixes

- Update rand 0.10 API usage (Rng -> RngExt)

### Features

- Expose crypto traits/functions

### Refactor

- Example to use rexported crypto types
- Rename buffer field
- Secret as a typed parameter for the crypto traits
- Ratcheting type rexports
- Revert Secret to a struct with optional auth key
- Rename the example key store to free the KeyStore name

## 1.1 - 2026-17-01

### Performance

- Openssl: In place encryption/decryption

## [1.0.1] - 2025-08-12

### Features

- Update to rust 2024 edition

<!-- generated by git-cliff -->
## 1.0.0 - 2025-08-12

### Refactor

- [**breaking**] Rename CipherSuiteVariant to CipherSuite

> This aligns the name given with the standard, which is prefered as it
this enum is publicly facing API. Internally we can use a different name
to also have access to the parameters for each suite.

Breaking Change:
To resolve rename `CipherSuiteVariant` to `CipherSuite`

## [0.9.0] - 2025-04-13

### Refactor

- [**breaking**] Rename FrameCount to Counter

> rename FrameCount to Counter

- [**breaking**] Introduce a frame counter trait

> introduce a frame counter trait

## [0.8.0] - 2025-01-01

### Bug Fixes

- Remove unnecessary mut for frame decryption

### Refactor

- [**breaking**] Remove sender/receiver API

> remove sender/receiver API

## [0.7.3] - 2024-12-29

### Bug Fixes

- Add getrandom wasm support

### Features

- Rustcrypto AesGcm implementation
- Rust crypto AES CTR modes

## [0.7.2] - 2024-11-15

- update dependencies
- update references to RFC 9605

## [0.7.0] - 2024-04-14

### Refactor

- [**breaking**] Make get_key a const method returning an option

> make get_key a const method returning an option

- [**breaking**] Separate ratcheting and get key for Ratcheting key store

> separate ratcheting and get key for Ratcheting key store

- [**breaking**] Key derivation error defintions

> Renamed `SframeError::KeyDerivation` to `SframeError::KeyDerivationFailure`. Also ratcheting failures now no longer produce `SframeError::KeyDerivationFailure` but `SframeError::RatchetingFailure`.

## [0.6.0] - 2024-03-10

### Features

- [**breaking**] Update to draft-07

> Draft 07 states *Implementations MUST mark each base_key as usable for encryption or decryption, never both*. There for `SframeKey` was
replaced with a dedicated `EncryptionKey` (used for e.g. `MediaFrameView::encrypt_into`), `DecryptionKey` (used for e.g. `EncryptedFrameView::decrypt_into`). Both implementations offer the same interface as the `SframeKey`.

### Refactor

- [**breaking**] Make frame submodule internal

> You can use the rexports directly, e.g. instead of `frame::frame_buffer::FrameBuffer` use `frame:FrameBuffer`

- [**breaking**] Move frame validation to frame module

> The module was moved, so e.g instead of `frame_validation::FrameValidation` use `frame::FrameValidation`

- Rename sframe_key variables

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
