use crate::header;

/// Evidence that a frame passed the replay check, recordable only by a
/// [`ReplayAttackProtection`](super::ReplayAttackProtection). Drop it to discard
/// the screened frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayToken {
    pub(super) key_id: header::KeyId,
    pub(super) counter: header::Counter,
}
