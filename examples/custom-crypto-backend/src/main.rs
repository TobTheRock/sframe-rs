//! To implement a custom crypto backend, depend on `sframe` with `default-features = false` so
//! that no built-in backend is compiled in, then implement `AeadEncrypt`, `AeadDecrypt` and
//! `KeyDerivation` together with the secret type they pass between each other. Parameterize
//! `GenericEncryptionKey`/`GenericDecryptionKey` with your types and the rest of the API follows.
//!
//! That dependency is why this is a crate of its own instead of `cargo run --example`.
//!
//! **Note**: the Caesar cipher used here is NOT cryptographically secure, it only keeps the
//! example short enough to read in one go.

use sframe::{
    CipherSuite,
    crypto::{AeadDecrypt, AeadEncrypt, DecryptionBufferView, EncryptionBufferView, KeyDerivation},
    error::{Result, SframeError},
    frame::{MediaFrame, MonotonicCounter},
    header::{Counter, KeyId},
    key::{GenericDecryptionKey, GenericEncryptionKey},
};

/// The secret material produced by [`CaesarKdf`] and consumed by [`CaesarAead`].
///
/// A custom backend defines its own secret type — it can be any shape that suits the algorithm.
/// For a Caesar cipher all we need is the byte offset to shift by.
#[derive(Clone, Debug)]
pub struct CaesarSecret {
    shift: u8,
}

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

impl AeadEncrypt for CaesarAead {
    type Secret = CaesarSecret;

    fn encrypt<'a, B>(&self, secret: &CaesarSecret, buffer: B, _counter: Counter) -> Result<()>
    where
        B: Into<EncryptionBufferView<'a>>,
    {
        let buffer_view: EncryptionBufferView = buffer.into();

        // Caesar cipher: shift each byte forward
        for byte in buffer_view.data.iter_mut() {
            *byte = byte.wrapping_add(secret.shift);
        }

        // Simple authentication tag: sum of all encrypted bytes
        let checksum = buffer_view
            .data
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        for tag_byte in buffer_view.tag.iter_mut() {
            *tag_byte = checksum;
        }

        Ok(())
    }
}

impl AeadDecrypt for CaesarAead {
    type Secret = CaesarSecret;

    fn decrypt<'a, B>(&self, secret: &CaesarSecret, buffer: B, _counter: Counter) -> Result<()>
    where
        B: Into<DecryptionBufferView<'a>>,
    {
        let buffer_view: DecryptionBufferView = buffer.into();

        // Split the data buffer into actual ciphertext and tag
        let tag_len = self.cipher_suite.auth_tag_len();
        let cipher_len = buffer_view.data.len().saturating_sub(tag_len);

        // Verify tag first (computed on encrypted data)
        let checksum = buffer_view.data[..cipher_len]
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));
        let tag = &buffer_view.data[cipher_len..];
        if !tag.iter().all(|&b| b == checksum) {
            return Err(SframeError::DecryptionFailure);
        }

        // Caesar cipher: shift each byte backward to decrypt
        for byte in buffer_view.data[..cipher_len].iter_mut() {
            *byte = byte.wrapping_sub(secret.shift);
        }

        Ok(())
    }
}

/// A fake key derivation that folds the key material into a single shift offset.
pub struct CaesarKdf;

impl KeyDerivation for CaesarKdf {
    type Secret = CaesarSecret;

    fn expand_from<M, K>(
        _cipher_suite: CipherSuite,
        key_material: M,
        _key_id: K,
    ) -> Result<CaesarSecret>
    where
        M: AsRef<[u8]>,
        K: Into<KeyId>,
    {
        // Simple "derivation": sum the key material bytes into a single offset.
        let shift = key_material
            .as_ref()
            .iter()
            .fold(0u8, |acc, &b| acc.wrapping_add(b));

        Ok(CaesarSecret { shift })
    }
}

fn main() -> Result<()> {
    println!("Caesar Cipher Custom Backend Example");
    println!("=====================================\n");

    // Create encryption and decryption keys using our custom backend
    let cipher_suite = CipherSuite::AesGcm128Sha256;
    let key_id = 42u64;
    let key_material = b"my-secret-key-material";

    let enc_key: GenericEncryptionKey<CaesarAead, CaesarKdf> =
        GenericEncryptionKey::derive_from(cipher_suite, key_id, key_material)?;

    let dec_key: GenericDecryptionKey<CaesarAead, CaesarKdf> =
        GenericDecryptionKey::derive_from(cipher_suite, key_id, key_material)?;

    println!("Key ID: {}", enc_key.key_id());
    println!("Cipher Suite: {:?}\n", enc_key.cipher_suite());

    // Prepare some data to encrypt
    let original_data = "Hello, SFrame with custom crypto!";
    println!("Original: {:?}", original_data);

    let mut counter = MonotonicCounter::default();
    let media_frame = MediaFrame::try_new(&mut counter, original_data)?;

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
