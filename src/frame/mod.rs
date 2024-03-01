//! Frame API
//! TODO

/// abstractions for encrypted sframes
pub mod encrypted_frame;
/// frame buffer abstractions
pub mod frame_buffer;
/// abstractions for unencrypted media frames
pub mod media_frame;

pub use encrypted_frame::{EncryptedFrame, EncryptedFrameView};
pub use frame_buffer::{FrameBuffer, Truncate};
pub use media_frame::{MediaFrame, MediaFrameView};

#[cfg(test)]
mod test {
    use crate::{
        frame::{encrypted_frame::EncryptedFrameView, media_frame::MediaFrame},
        key::SframeKey,
        util::test::assert_bytes_eq,
        CipherSuiteVariant,
    };

    use super::media_frame::MediaFrameView;
    const FRAME_COUNT: u64 = 42;
    const PAYLOAD: &[u8] = b"TIME TO PAY";
    const META_DATA: &[u8] = b"META";
    const KEY_ID: u64 = 666u64;

    fn expand_key() -> SframeKey {
        SframeKey::derive_from(CipherSuiteVariant::AesGcm256Sha512, KEY_ID, "SECRET").unwrap()
    }

    #[test]
    fn encrypt_decrypt_frame_view() {
        let mut key = expand_key();
        let mut encrypt_buffer = Vec::new();
        let mut decrypt_buffer = Vec::new();

        let media_frame = MediaFrameView::new(FRAME_COUNT, PAYLOAD);
        media_frame.encrypt_into(&key, &mut encrypt_buffer).unwrap();

        let encrypted_frame = EncryptedFrameView::new(&encrypt_buffer).unwrap();
        let decrypted_media_frame = encrypted_frame
            .decrypt_into(&mut key, &mut decrypt_buffer)
            .unwrap();

        assert_eq!(decrypted_media_frame, media_frame);
    }

    #[test]
    fn encrypt_decrypt_frame_view_with_meta_data() {
        let mut key = expand_key();
        let mut encrypt_buffer = Vec::new();
        let mut decrypt_buffer = Vec::new();

        let media_frame = MediaFrameView::with_meta_data(FRAME_COUNT, PAYLOAD, META_DATA);
        media_frame.encrypt_into(&key, &mut encrypt_buffer).unwrap();

        let (meta_data, encrypted) = encrypt_buffer.split_at(META_DATA.len());
        assert_bytes_eq(meta_data, META_DATA);

        let encrypted_frame = EncryptedFrameView::with_meta_data(encrypted, META_DATA).unwrap();
        let decrypted_media_frame = encrypted_frame
            .decrypt_into(&mut key, &mut decrypt_buffer)
            .unwrap();

        assert_eq!(decrypted_media_frame, media_frame);
    }

    #[test]
    fn encrypt_decrypt_frame_with_meta_data() {
        let mut key = expand_key();

        let media_frame = MediaFrame::with_meta_data(FRAME_COUNT, PAYLOAD, META_DATA);
        let encrypted = media_frame.encrypt(&key).unwrap();

        assert_bytes_eq(encrypted.meta_data(), META_DATA);

        let decrypted_media_frame = encrypted.decrypt(&mut key).unwrap();

        assert_eq!(decrypted_media_frame, media_frame);
    }
}
