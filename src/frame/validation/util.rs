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
