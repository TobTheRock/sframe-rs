pub mod encrypted_frame;
pub mod frame_buffer;
pub mod media_frame;

pub use frame_buffer::FrameBuffer;

#[cfg(test)]
mod test {
    use crate::{frame::encrypted_frame::EncryptedFrameView, key::SframeKey, CipherSuiteVariant};

    use super::media_frame::MediaFrameView;

    #[test]
    fn encrypt_decrypt_frame_view() {
        let frame_count = 42u64;
        let payload = vec![6; 6];
        let key_id = 666u64;
        let key =
            SframeKey::expand_from(CipherSuiteVariant::AesGcm256Sha512, key_id, "SECRET").unwrap();
        let mut encrypt_buffer = Vec::new();
        let mut decrypt_buffer = Vec::new();

        let media_frame = MediaFrameView::new(frame_count, &payload);
        media_frame.encrypt_into(&key, &mut encrypt_buffer).unwrap();

        let encrypted_frame = EncryptedFrameView::new(&encrypt_buffer).unwrap();
        let decrypted_media_frame = encrypted_frame
            .decrypt_into(&key, &mut decrypt_buffer)
            .unwrap();

        assert_eq!(decrypted_media_frame, media_frame);
    }

    #[test]
    fn encrypt_decrypt_frame_view_with_meta_data() {
        todo!()
    }
}
