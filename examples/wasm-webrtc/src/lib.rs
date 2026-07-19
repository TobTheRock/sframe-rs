//! End-to-end encrypted WebRTC in a single browser tab, using sframe.
//!
//! A Leptos app wires two peer connections in loopback. Outgoing VP8 frames are
//! encrypted in a [WebRTC Encoded Transform][transform] running in a worker
//! ([`bin/worker.rs`](../worker/index.html)); the receiving side decrypts them.
//! Give the two sides different passphrases and decryption fails - frames are
//! dropped and the remote video stays blank, which is the point.
//!
//! [transform]: https://developer.mozilla.org/en-US/docs/Web/API/RTCRtpScriptTransform

pub mod transform;
pub mod webrtc;

/// Key id shared by both sides of the demo. A real app would negotiate this.
pub const KEY_ID: sframe::header::KeyId = 42;
