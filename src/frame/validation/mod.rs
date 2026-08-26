use crate::header::SframeHeader;

mod replay_attack_protection;
mod replay_attack_protection_store;
mod replay_token;
mod sliding_window;
mod util;

pub use replay_attack_protection::{ReplayAttackProtection, ReplayAttackProtectionError};
pub use replay_attack_protection_store::{ReplayAttackProtectionStore, ReplayStoreToken};
pub use replay_token::ReplayToken;

/// Screens frames before decryption, records them after.
///
/// ```text
/// screen(frame)? -> Token -> decrypt()? -> record(token)
/// ```
///
/// Split in two steps because a header is unauthenticated until its frame
/// decrypts: a validator recording it beforehand could be poisoned with forged
/// frames. Dropping a token instead of recording it leaves it untouched.
pub trait FrameValidation {
    /// Evidence that a frame passed [`screen`](Self::screen), carrying what
    /// [`record`](Self::record) needs to record it. Opaque to the caller.
    type Token;

    /// Why a frame was rejected.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Screens a frame BEFORE decryption, leaving the validator's state untouched.
    /// The header is attacker controlled here: reject on it, do not record it.
    #[must_use = "a screened frame must be recorded once it decrypts, or dropped"]
    fn screen(&self, unvalidated: UnvalidatedFrame<'_>) -> Result<Self::Token, Self::Error>;

    /// Records a frame AFTER decryption authenticated it, redeeming its token.
    ///
    /// The token can only be obtained from [`screen`](Self::screen), so a frame
    /// which was never screened cannot be recorded.
    ///
    /// Infallible on purpose: every rejection belongs in
    /// [`screen`](Self::screen). A frame which got this far is authentic,
    /// failing here would discard a frame the receiver already decrypted.
    fn record(&mut self, token: Self::Token);
}

/// No validation, as permitted by RFC 9605: accepts every frame and records
/// nothing. Switches validation off wherever a validator is expected, without a
/// second code path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NoValidation;

impl FrameValidation for NoValidation {
    type Token = ();
    type Error = std::convert::Infallible;

    fn screen(&self, _unvalidated: UnvalidatedFrame<'_>) -> Result<Self::Token, Self::Error> {
        Ok(())
    }

    fn record(&mut self, _token: Self::Token) {}
}

/// The unauthenticated context a frame may be screened on, before decryption.
#[derive(Debug, Clone, Copy)]
pub struct UnvalidatedFrame<'frame> {
    header: &'frame SframeHeader,
    meta_data: &'frame [u8],
}

impl<'frame> UnvalidatedFrame<'frame> {
    /// Creates the screening context from a parsed, not yet authenticated header
    /// and the meta data associated with its frame.
    pub fn new(header: &'frame SframeHeader, meta_data: &'frame [u8]) -> Self {
        Self { header, meta_data }
    }

    /// Parsed, but not yet authenticated.
    pub fn header(&self) -> &'frame SframeHeader {
        self.header
    }

    /// The AAD supplied by the caller, e.g. an RTP header.
    pub fn meta_data(&self) -> &'frame [u8] {
        self.meta_data
    }
}
