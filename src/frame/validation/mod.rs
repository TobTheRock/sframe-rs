use crate::{error::Result, header::SframeHeader};
use std::ops::Deref;

mod replay_attack_protection;
mod sliding_window;

pub use replay_attack_protection::ReplayAttackProtection;

/// Allows to validate frames by their sframe header before the decryption
pub trait FrameValidation {
    /// checks if the new header is valid, returns an [`SframeError`] if not
    fn validate(&self, header: &SframeHeader) -> Result<()>;
}

/// Box to any implementation of the `FrameValidation` trait
pub type FrameValidationBox = Box<dyn FrameValidation>;

impl FrameValidation for FrameValidationBox {
    fn validate(&self, header: &SframeHeader) -> Result<()> {
        self.deref().validate(header)
    }
}
