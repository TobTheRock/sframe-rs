# Migrating from 1.x to 2.0

## Why

Two classes of defect drove this release, and one theme runs through the rest of it.

**Nothing is recorded before it is authenticated.** In 1.x a `FrameValidation` was handed the
header of an incoming frame and updated its replay window right there - before decryption had
proven the frame genuine ([#95], [#113]). A ratcheting key store did the same: `try_ratchet`
moved the stored key forward on an unauthenticated Key ID ([#100]). Either one lets anyone who
can put bytes on the wire poison a receiver - replay windows jump forward, valid keys are evicted.
Both are split in two now: a read-only step before decryption and a recording step after, with
the frame API driving the pair. The safe order is the only one on the happy path.

**Failures are reported, not panicked.** The frame counter used to wrap around - reusing a
counter breaks the uniqueness the underlying AEAD needs - and then panicked instead. It returns
a `Result` now ([#96]). The replay tolerance, the No. ratchet bits and a `FrameBuffer`
allocation likewise report an error instead of panicking or silently truncating.

**Types instead of bare integers.** A `u8` could be ratchet bits or a step count; a `u64` could
be a Key ID, a Key Generation, a Ratchet Step or a frame counter. Mixing them up compiled.
`RatchetBits`, `Generation`, `RatchetStep`, `RatchetStepDiff` and `Tolerance` are distinct types
now, each validating its range on construction.

The rest is mechanical. Work through the modules you use.

[#95]: https://github.com/TobTheRock/sframe-rs/issues/95
[#96]: https://github.com/TobTheRock/sframe-rs/issues/96
[#100]: https://github.com/TobTheRock/sframe-rs/issues/100
[#113]: https://github.com/TobTheRock/sframe-rs/issues/113
[#114]: https://github.com/TobTheRock/sframe-rs/issues/114
[#119]: https://github.com/TobTheRock/sframe-rs/issues/119

## Module paths

Every type is reachable through exactly one path now ([#114]). Leaf modules are private and
each module re-exports its types flat, so `crypto::cipher_suite::CipherSuite` and
`key::crypto_key::EncryptionKey` are gone.

The types generic over the crypto backend gained a `Generic` prefix, which frees the plain names
for the aliases pinned to the backend you enabled - so a caller never spells out the type
parameters:

```rust
use sframe::{
    CipherSuite,                                        // was crypto::cipher_suite::CipherSuite
    key::{DecryptionKey, EncryptionKey},                // aliases of Generic{En,De}cryptionKey
    ratchet::{RatchetingDecryptionKey, RatchetingKeyStore},
};
```

Implementing your own crypto backend? Name the generic form and parameterize it yourself:
`key::GenericEncryptionKey<A, D>`, `ratchet::GenericRatchetingKeyStore<A, D>`.

`CipherSuite` moved to its own module and is `#[non_exhaustive]`, as is `SframeError` - a
`match` on either needs a catch-all arm now.

## `error`

`SframeError` no longer implements `PartialEq`/`Eq`, because the variants which wrap the error
of a component you plugged in hold a `Box<dyn Error>`:

```rust
// was: assert_eq!(error, SframeError::DecryptionFailure);
assert!(matches!(error, SframeError::DecryptionFailure));
```

`SframeError::Other` is gone. The errors of your own components - a validator rejecting a frame,
a key store with no key, a buffer which could not allocate - arrive boxed as the *source* of a
variant. Name the type again to get it back:

```rust
matches!(
    error.source_as::<ReplayAttackProtectionError>(),
    Some(ReplayAttackProtectionError::DuplicatedFrame { .. })
)
```

That is how you tell "this was a duplicate, drop it quietly" apart from "this frame did not
decrypt" without matching on a string.

## `frame`

**The counter can fail.** `FrameCounter::next` is replaced by `try_next`, with an associated
`Error` - exhaustion is what `MonotonicCounter` reports, a counter of your own may just as well
fail loading or persisting its state. `MediaFrame::new` and friends now only accept a counter
which *cannot* fail, so use `try_new` / `try_with_meta_data` (same for the view API,
`MediaFrameView::try_new` / `try_with_meta_data`):

```rust
use sframe::frame::{MediaFrame, MonotonicCounter};

let mut counter = MonotonicCounter::default();
let media_frame = MediaFrame::try_new(&mut counter, "Something secret")?;
```

If you would rather keep the infallible call, hand it a `PanickingMonotonicCounter` - the panic
is then yours, spelled out at the call site:

```rust
use sframe::frame::{MediaFrame, PanickingMonotonicCounter};

let mut counter = PanickingMonotonicCounter::default();
let media_frame = MediaFrame::new(&mut counter, "Something secret");
```

`is_exhausted()` is still there to check ahead of a frame, and `CounterExhausted::max` names the
last counter which was usable - the point to rotate or ratchet the key at.

**`FrameBuffer` reports its own error.** `allocate` returns `Result<&mut Self::BufferSlice,
Self::Error>` instead of the crate's `Result`, so a buffer of your own no longer has to borrow
an sframe error variant to say "out of memory":

```rust
use sframe::frame::FrameBuffer;

struct Arena { buffer: Vec<u8>, capacity: usize }

#[derive(Debug, thiserror::Error)]
#[error("the arena holds only {capacity} bytes, {requested} were asked for")]
struct OutOfSpace { capacity: usize, requested: usize }

impl FrameBuffer for Arena {
    type BufferSlice = Vec<u8>;
    // was: allocate returned sframe::error::Result, with no way to say why
    type Error = OutOfSpace;

    fn allocate(&mut self, size: usize) -> Result<&mut Self::BufferSlice, Self::Error> {
        if size > self.capacity {
            return Err(OutOfSpace { capacity: self.capacity, requested: size });
        }
        self.buffer.resize(size, 0);
        Ok(&mut self.buffer)
    }
}
```

It reaches the caller as `SframeError::BufferAllocationFailed`, recoverable with `source_as`.

## `frame::validation`

The validation types live in their own module now (`sframe::frame::validation::*`), and the
trait is split in two: `screen` runs before decryption and must not touch the validator's state,
`record` runs after and redeems the token `screen` handed out. `FrameValidationBox` is gone -
use `Box<dyn FrameValidation<..>>` if you need one, and `NoValidation` switches validation off
where a validator is expected.

```rust
use sframe::{
    frame::validation::{FrameValidation, UnvalidatedFrame},
    header::Counter,
};

/// Accepts a frame only once its counter reached a threshold.
struct NotBefore(Counter);

#[derive(Debug, thiserror::Error)]
#[error("frame {counter} is before {threshold}")]
struct TooEarly { counter: Counter, threshold: Counter }

impl FrameValidation for NotBefore {
    type Token = ();
    type Error = TooEarly;

    // was: fn validate(&self, header: &SframeHeader) -> sframe::error::Result<()>
    fn screen(&self, unvalidated: UnvalidatedFrame<'_>) -> Result<Self::Token, Self::Error> {
        let counter = unvalidated.header().counter();
        if counter < self.0 {
            return Err(TooEarly { counter, threshold: self.0 });
        }
        Ok(())
    }

    fn record(&mut self, _token: Self::Token) {}
}
```

`ReplayAttackProtection` protects **one** sender, and its Key ID is mandatory - in 1.x leaving
it off silently shared a single window across every sender. The tolerance is a `Tolerance`,
which rejects an unusable value instead of panicking later:

```rust
use sframe::frame::validation::{ReplayAttackProtection, ReplayAttackProtectionStore, Tolerance};

// was: ReplayAttackProtection::with_tolerance(128).for_key_id(key_id)
let single_sender = ReplayAttackProtection::new(42u8.into(), Tolerance::new(128));

// several senders: one window per Key ID
let mut many_senders = ReplayAttackProtectionStore::new(Tolerance::try_new(128)?);
```

Call sites do not change: `validated_decrypt_into` drives `screen` -> decrypt -> `record` for
you, and only records a frame which actually decrypted.

## `key`

The getter moved to its own trait. Implement `KeyLookup` if your store just holds keys; the
frame API decrypts against `KeyStore`, which is the two-phase `lookup`/`record` pair and is
implemented for `&S where S: KeyLookup` ([#119]). Implement `KeyStore` directly only if a lookup
derives a key which the store should keep once the frame decrypted:

```rust
// was: a single trait with the getter on it
pub trait KeyStore<A, D> {
    type Key: AsRef<GenericDecryptionKey<A, D>>;
    type Error: std::error::Error + Send + Sync + 'static;

    fn lookup(&self, key_id: KeyId) -> Result<Self::Key, Self::Error>;
    fn record(&mut self, key: Self::Key);
}
```

```rust
use sframe::{
    crypto::{Aead, Kdf},
    header::KeyId,
    key::{DecryptionKey, KeyLookup},
};

struct Keys(Vec<DecryptionKey>);

// was: impl KeyStore<Aead, Kdf> for Keys { fn get_key(..) }
impl KeyLookup<Aead, Kdf> for Keys {
    fn get_key<K>(&self, key_id: K) -> Option<&DecryptionKey>
    where
        K: Into<KeyId>,
    {
        let key_id = key_id.into();
        self.0.iter().find(|key| key.key_id() == key_id)
    }
}
```

Because the frame API takes the store **by value**, a store is passed the way it is used - and a
single key, which is a store of one, is now passed shared rather than mutably:

```rust
// was: encrypted_frame.decrypt(&mut dec_key)
let media_frame = encrypted_frame.decrypt(&dec_key)?;
```

## `ratchet`

This module changed the most.

**`RatchetingBaseKey` is gone.** A ratcheting key carries its own key material, so there is no
base key to keep alongside it. A sender holds a `RatchetingEncryptionKey` and ratchets it:

```rust
use sframe::{
    CipherSuite,
    frame::{MediaFrame, MonotonicCounter},
    ratchet::{RatchetBits, RatchetingEncryptionKey, RatchetingKeyId},
};

let key_id = RatchetingKeyId::try_new(42u64, RatchetBits::try_new(4)?)?;
// was: RatchetingBaseKey::ratchet_forward(key_id, "pw123", CipherSuite::AesGcm256Sha512)?
let mut enc_key = RatchetingEncryptionKey::derive_from(CipherSuite::AesGcm256Sha512, key_id, "pw123")?;

let mut counter = MonotonicCounter::default();
let frame = MediaFrame::try_new(&mut counter, "secret")?.encrypt(enc_key.as_ref())?;

// was: let (key_id, key_material) = base_key.next_base_key()?; then derive a key from it
// the next frame is encrypted with the key of the next Ratchet Step
enc_key = enc_key.ratchet()?;
```

**The store is keyed by `Generation`, and you hand it to the frame API.** `try_ratchet` and
`with_ratcheted_key` are both gone: the store *is* a `KeyStore`, passed `&mut` because it
records the key it ratcheted to. It ratchets forward to the Key ID of the frame on lookup and
keeps that key only once the frame decrypted, so a forged Key ID cannot evict a valid key.

```rust
use sframe::{
    CipherSuite,
    ratchet::{
        Generation, RatchetBits, RatchetStepDiff, RatchetingDecryptionKey, RatchetingKeyId,
        RatchetingKeyStore,
    },
};

let n_ratchet_bits = RatchetBits::try_new(4)?;
let generation = Generation::from(42);
let key_id = RatchetingKeyId::try_new(generation, n_ratchet_bits)?;

// both parameters are mandatory now, `max_ratchet_steps` is the No. steps a single frame may
// catch up with - each one costs a key derivation an attacker can trigger
let mut keys = RatchetingKeyStore::new(n_ratchet_bits, RatchetStepDiff::from(2));
// insert takes a derived key, which starts at Ratchet Step 0 of its Key Generation
keys.insert(RatchetingDecryptionKey::derive_from(CipherSuite::AesGcm256Sha512, key_id, "pw123")?);

// a frame of a sender which is one Ratchet Step ahead of the stored key
// was: keys.try_ratchet(key_id)?; then a get_key lookup
let media_frame = encrypted_frame.decrypt(&mut keys)?;

// remove and get take the Key Generation, not a Key ID
assert!(keys.get(generation).is_some());
```

**The integers became types.** `Generation`, `RatchetStep` and `RatchetStepDiff` convert from
`u64` and back. `RatchetBits` and `RatchetingKeyId` have a range to check, so each has a `new`
which panics on a value outside it and a `try_new` which reports it as
`SframeError::OutOfRange`. `RatchetBits` rejects `0`: with no bits for the Ratchet Step the Key
ID never changes, so a sender which ratchets anyway moves its key material with no signal on
the wire and its frames simply stop decrypting.

`RatchetingKeyId` equality covers the whole Key ID including the Ratchet Step (compare
`.generation()` for the 1.x behaviour) and it is no longer hashable.

## `mls`

Both constructors validated nothing and truncated silently. `MlsKeyIdBitRange::new` panics on an
out of range value now, with `try_new` next to it reporting `SframeError::OutOfRange`.
`MlsKeyId::new` is replaced by `MlsKeyId::try_new`, which reports the same.

## `header`

Unchanged.

## Checklist

- [ ] Import from the module roots, drop the leaf module paths, and take the `Generic` prefix only
      where you name a type generic over the crypto backend.
- [ ] Replace `counter.next()` with `counter.try_next()?`, or keep the infallible call with a
      `PanickingMonotonicCounter`.
- [ ] Swap `MediaFrame::new` / `with_meta_data` for `try_new` / `try_with_meta_data`.
- [ ] Give a `FrameBuffer` of your own an `Error` type.
- [ ] Wrap the replay tolerance in `Tolerance` and pass the Key ID to `ReplayAttackProtection::new`.
- [ ] Port a `FrameValidation` of your own to `screen` / `record` with its own `Token` and `Error`,
      and a key store to `KeyLookup` - or to `KeyStore`'s `lookup` / `record` if it derives keys.
- [ ] Replace `RatchetingBaseKey` with a `RatchetingEncryptionKey` and `ratchet()`.
- [ ] Hand the `RatchetingKeyStore` to the frame API instead of calling `try_ratchet`, construct it
      with `RatchetBits` and `RatchetStepDiff`, `insert` a derived key, and address `get` / `remove`
      by `Generation`.
- [ ] Replace `MlsKeyId::new` with `try_new`.
- [ ] Drop `==` on `SframeError`, add a catch-all arm to any `SframeError` or `CipherSuite` match,
      and recover a component's own error with `source_as` instead of `SframeError::Other`.
