use crate::{error::Result, header::SframeHeader};

mod replay_attack_protection;
mod replay_attack_protection_store;
mod sliding_window;

pub use replay_attack_protection::ReplayAttackProtection;
pub use replay_attack_protection_store::ReplayAttackProtectionStore;

/// Allows to validate frames by their sframe header before the decryption
pub trait FrameValidation {
    /// checks if the new header is valid, returns an [`SframeError`] if not
    // TODO(v2): validator (self) should be mutable
    fn validate(&self, header: &SframeHeader) -> Result<()>;
}
