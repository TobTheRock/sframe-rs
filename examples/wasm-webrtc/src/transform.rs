//! Encrypting/decrypting VP8 frames as they are handed to us by the WebRTC
//! Encoded Transform API.
//!
//! The VP8 payload header must survive unencrypted: the packetizer downstream
//! still has to parse it. So it is passed as sframe metadata (AAD) instead,
//! which authenticates it without hiding it.

use sframe::error::{Result, SframeError};

// ponytail: the sender_receiver example already wraps sframe with exactly the
// `(frame, skip)` API the Encoded Transform needs. Reused rather than copied.
#[path = "../../sender_receiver/receiver.rs"]
pub mod receiver;
#[path = "../../sender_receiver/sender.rs"]
pub mod sender;

pub use receiver::Receiver;
pub use sender::Sender;

/// Length of the VP8 payload header, which stays unencrypted.
///
/// Keyframes carry a 10 byte header (3 byte uncompressed chunk + 7 byte
/// keyframe header), interframes only the 3 byte chunk. The keyframe flag is
/// the inverted LSB of the first byte.
fn vp8_header_len(frame: &[u8]) -> Result<usize> {
    const KEY_FRAME: usize = 10;
    const INTER_FRAME: usize = 3;

    let is_key_frame = frame.first().ok_or(SframeError::InvalidBuffer(0))? & 1 == 0;
    let len = if is_key_frame { KEY_FRAME } else { INTER_FRAME };

    if frame.len() < len {
        return Err(SframeError::InvalidBuffer(frame.len()));
    }

    Ok(len)
}

/// Encrypts a VP8 frame, leaving its payload header in the clear.
pub fn encrypt_vp8<'a>(sender: &'a mut Sender, frame: &[u8]) -> Result<&'a [u8]> {
    let skip = vp8_header_len(frame)?;
    sender.encrypt(frame, skip)
}

/// Decrypts a VP8 frame which was encrypted by [`encrypt_vp8`].
pub fn decrypt_vp8<'a>(receiver: &'a mut Receiver, frame: &[u8]) -> Result<&'a [u8]> {
    let skip = vp8_header_len(frame)?;
    receiver.decrypt(frame, skip)
}
