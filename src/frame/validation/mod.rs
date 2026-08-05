use crate::{error::Result, header::SframeHeader};
use std::ops::{Deref, DerefMut};

mod replay_attack_protection;
mod sliding_window;

pub use replay_attack_protection::ReplayAttackProtection;

/// Allows to validate frames by their sframe header, split into two steps around decryption
/// so that state which influences subsequent frames (e.g. a replay window) can only ever be
/// mutated *after* a frame has been authenticated.
pub trait FrameValidation {
    /// Read-only screen run **before** decryption, checked against the state committed by
    /// previous, successfully authenticated frames. Must not mutate any state that influences
    /// the validation of subsequent frames. Returns an [`SframeError`] if the header is
    /// rejected, e.g. because it is a replay.
    fn pre_decrypt(&self, header: &SframeHeader) -> Result<()>;

    /// Records the header. Only ever called **after** the frame carrying it has been
    /// successfully decrypted, i.e. authenticated. This is the only place validation state
    /// may be mutated.
    fn post_decrypt(&mut self, header: &SframeHeader);
}

/// Box to any implementation of the `FrameValidation` trait
pub type FrameValidationBox = Box<dyn FrameValidation>;

impl FrameValidation for FrameValidationBox {
    fn pre_decrypt(&self, header: &SframeHeader) -> Result<()> {
        self.deref().pre_decrypt(header)
    }

    fn post_decrypt(&mut self, header: &SframeHeader) {
        self.deref_mut().post_decrypt(header);
    }
}
