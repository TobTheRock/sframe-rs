//! Example demonstrating a custom crypto backend using a Caesar cipher implementation.
//!
//! This example shows how users can implement their own crypto backend by implementing
//! the `AeadEncrypt`, `AeadDecrypt`, and `KeyDerivation` traits.
//!
//! **Note**: Caesar cipher is NOT cryptographically secure - this is purely for demonstration
//! of the pluggable backend API. The cipher shifts each byte by a derived offset.

use sframe::{
    crypto::{
        aead::{AeadDecrypt, AeadEncrypt},
        buffer::{DecryptionBufferView, EncryptionBufferView},
        cipher_suite::{CipherSuite, CipherSuiteParams},
        key_derivation::KeyDerivation,
        secret::Secret,
    },
    error::{Result, SframeError},
    frame::{MediaFrame, MonotonicCounter},
    header::{Counter, KeyId},
    key::crypto_key::{DecryptionKey, EncryptionKey},
};

/// Caesar cipher AEAD implementation - shifts each byte by a derived offset.
#[derive(Clone, Debug)]
pub struct CaesarAead {
    cipher_suite: CipherSuite,
}

impl TryFrom<CipherSuite> for CaesarAead {
    type Error = SframeError;

    fn try_from(cipher_suite: CipherSuite) -> Result<Self> {
        // Accept any cipher suite for this demo
        Ok(Self { cipher_suite })
    }
}

impl CaesarAead {
    /// Derive the shift amount from key and counter
    fn derive_shift(secret: &Secret, counter: Counter) -> u8 {
        let nonce = secret.create_nonce::<12>(counter);
        // Combine first key byte with first nonce byte to get shift
        secret
            .key
            .first()
            .copied()
            .unwrap_or(0)
            .wrapping_add(nonce[0])
    }
}

impl AeadEncrypt for CaesarAead {
    fn encrypt<'a, B>(&self, secret: &Secret, buffer: B, counter: Counter) -> Result<()>
    where
        B: Into<EncryptionBufferView<'a>>,
    {
        let buffer_view: EncryptionBufferView = buffer.into();
        let shift = Self::derive_shift(secret, counter);

        // Caesar cipher: shift each byte forward
        for byte in buffer_view.cipher_text.iter_mut() {
            *byte = byte.wrapping_add(shift);
        }

        // Simple authentication tag: sum of all cipher_text bytes
        let checksum = buffer_view
            .cipher_text
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        for tag_byte in buffer_view.tag.iter_mut() {
            *tag_byte = checksum;
        }

        Ok(())
    }
}

impl AeadDecrypt for CaesarAead {
    fn decrypt<'a, B>(&self, secret: &Secret, buffer: B, counter: Counter) -> Result<()>
    where
        B: Into<DecryptionBufferView<'a>>,
    {
        let buffer_view: DecryptionBufferView = buffer.into();
        let params: CipherSuiteParams = self.cipher_suite.into();

        // Split cipher_text into actual ciphertext and tag
        let tag_len = params.auth_tag_len;
        let cipher_len = buffer_view.cipher_text.len().saturating_sub(tag_len);

        // Verify tag first (computed on encrypted data)
        let checksum = buffer_view.cipher_text[..cipher_len]
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        let tag = &buffer_view.cipher_text[cipher_len..];
        if !tag.iter().all(|&b| b == checksum) {
            return Err(SframeError::DecryptionFailure);
        }

        // Caesar cipher: shift each byte backward to decrypt
        let shift = Self::derive_shift(secret, counter);
        for byte in buffer_view.cipher_text[..cipher_len].iter_mut() {
            *byte = byte.wrapping_sub(shift);
        }

        Ok(())
    }
}

/// A fake key derivation that just copies/pads the key material.
pub struct CaesarKdf;

impl KeyDerivation for CaesarKdf {
    fn expand_from<M, K>(
        cipher_suite: &CipherSuiteParams,
        key_material: M,
        _key_id: K,
    ) -> Result<Secret>
    where
        M: AsRef<[u8]>,
        K: Into<KeyId>,
    {
        let material = key_material.as_ref();

        // Simple "derivation": just repeat/truncate the key material
        let mut key = vec![0u8; cipher_suite.key_len];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = material.get(i % material.len()).copied().unwrap_or(0);
        }

        let mut salt = vec![0u8; cipher_suite.nonce_len];
        for (i, byte) in salt.iter_mut().enumerate() {
            *byte = material
                .get((i + cipher_suite.key_len) % material.len())
                .copied()
                .unwrap_or(0);
        }

        Ok(Secret {
            key,
            salt,
            auth: None,
        })
    }
}

fn main() -> Result<()> {
    println!("Caesar Cipher Custom Backend Example");
    println!("=====================================\n");

    // Create encryption and decryption keys using our custom backend
    let cipher_suite = CipherSuite::AesGcm128Sha256;
    let key_id = 42u64;
    let key_material = b"my-secret-key-material";

    let enc_key: EncryptionKey<CaesarAead, CaesarKdf> =
        EncryptionKey::derive_from(cipher_suite, key_id, key_material)?;

    let dec_key: DecryptionKey<CaesarAead, CaesarKdf> =
        DecryptionKey::derive_from(cipher_suite, key_id, key_material)?;

    println!("Key ID: {}", enc_key.key_id());
    println!("Cipher Suite: {:?}\n", enc_key.cipher_suite());

    // Prepare some data to encrypt
    let original_data = "Hello, SFrame with custom crypto!";
    println!("Original: {:?}", original_data);

    let mut counter = MonotonicCounter::default();
    let media_frame = MediaFrame::new(&mut counter, original_data);

    let encrypted_frame = media_frame.encrypt(&enc_key)?;
    println!(
        "Encrypted Frame Payload: {:?}",
        encrypted_frame.cipher_text()
    );

    let decrypted_frame = encrypted_frame.decrypt(&dec_key)?;
    println!("Decrypted: {:?}", decrypted_frame.payload());

    assert_eq!(original_data.as_bytes(), decrypted_frame.payload());
    println!("Success! Encryption and decryption with custom backend worked.");
    Ok(())
}
