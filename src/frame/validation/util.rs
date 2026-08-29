use crate::header;

/// A counter is treated as newer than the window if it lies in the forward half
/// of the counter range. A window spanning more than that half would overlap it,
/// making a counter both contained in the window and newer than it.
///
/// # Panics
/// Panics if `tolerance` is `0` or exceeds `header::Counter::MAX / 2`.
pub fn assert_tolerance(tolerance: usize) {
    assert!(tolerance > 0, "Tolerance must be greater than 0");
    assert!(
        (tolerance as u64) <= header::Counter::MAX / 2,
        "Tolerance must not exceed half the frame counter range"
    );
}

#[cfg(test)]
pub mod test {
    use crate::{
        frame::validation::{FrameValidation, UnvalidatedFrame},
        header::{Counter, KeyId, SframeHeader},
    };

    /// Screens a frame of `key_id`, without recording it.
    pub fn screen<V: FrameValidation>(
        validator: &V,
        key_id: KeyId,
        counter: Counter,
    ) -> Result<V::Token, V::Error> {
        let header = SframeHeader::new(key_id, counter);
        validator.screen(UnvalidatedFrame::new(&header, &[]))
    }

    /// Screens a frame of `key_id` and records it, as a frame which decrypted.
    pub fn screen_and_record<V: FrameValidation>(
        validator: &mut V,
        key_id: KeyId,
        counter: Counter,
    ) -> Result<(), V::Error> {
        let token = screen(validator, key_id, counter)?;
        validator.record(token);
        Ok(())
    }
}
