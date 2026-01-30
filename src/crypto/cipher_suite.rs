/// Depicts which AEAD algorithm is used for encryption
/// and which hashing function is used for the key expansion,
/// see [RFC 9605 4.4](https://www.rfc-editor.org/rfc/rfc9605.html#name-cipher-suites)
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
pub enum CipherSuite {
    // /// counter mode is [not implemented in ring](https://github.com/briansmith/ring/issues/656)
    #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
    /// encryption: AES CTR 128 with 80 bit HMAC authentication tag, key expansion: HKDF with SHA256,
    AesCtr128HmacSha256_80 = 0x0001,
    #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
    /// encryption: AES CTR 128 with 64 bit HMAC authentication tag, key expansion: HKDF with SHA256,
    AesCtr128HmacSha256_64 = 0x0002,
    #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
    /// encryption: AES CTR 128 with 32 bit HMAC authentication tag, key expansion: HKDF with SHA256,
    AesCtr128HmacSha256_32 = 0x0003,
    /// encryption: AES GCM 128, key expansion: HKDF with SHA256
    AesGcm128Sha256 = 0x0004,
    /// encryption: AES GCM 256, key expansion: HKDF with SHA512
    AesGcm256Sha512 = 0x0005,
}

impl std::fmt::Display for CipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
            CipherSuite::AesCtr128HmacSha256_80 => "AesCtr128HmacSha256_80",
            #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
            CipherSuite::AesCtr128HmacSha256_64 => "AesCtr128HmacSha256_64",
            #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
            CipherSuite::AesCtr128HmacSha256_32 => "AesCtr128HmacSha256_32",
            CipherSuite::AesGcm128Sha256 => "AesGcm128Sha256",
            CipherSuite::AesGcm256Sha512 => "AesGcm256Sha512",
        };
        f.write_str(str)
    }
}

impl CipherSuite {
    /// Hash.Nh - The size in bytes of the output of the hash function
    pub const fn hash_len(&self) -> usize {
        match self {
            #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
            CipherSuite::AesCtr128HmacSha256_80
            | CipherSuite::AesCtr128HmacSha256_64
            | CipherSuite::AesCtr128HmacSha256_32 => 32,
            CipherSuite::AesGcm128Sha256 => 32,
            CipherSuite::AesGcm256Sha512 => 64,
        }
    }

    /// AEAD.Nk - The size in bytes of a key for the encryption algorithm
    pub const fn key_len(&self) -> usize {
        match self {
            #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
            CipherSuite::AesCtr128HmacSha256_80
            | CipherSuite::AesCtr128HmacSha256_64
            | CipherSuite::AesCtr128HmacSha256_32 => 48,
            CipherSuite::AesGcm128Sha256 => 16,
            CipherSuite::AesGcm256Sha512 => 32,
        }
    }

    /// AEAD.Nn - The size in bytes of a nonce for the encryption algorithm
    pub const fn nonce_len(&self) -> usize {
        match self {
            #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
            CipherSuite::AesCtr128HmacSha256_80
            | CipherSuite::AesCtr128HmacSha256_64
            | CipherSuite::AesCtr128HmacSha256_32 => 12,
            CipherSuite::AesGcm128Sha256 | CipherSuite::AesGcm256Sha512 => 12,
        }
    }

    /// AEAD.Nt - The overhead in bytes of the encryption algorithm (typically the size of a "tag" that is added to the plaintext)
    pub const fn auth_tag_len(&self) -> usize {
        match self {
            #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
            CipherSuite::AesCtr128HmacSha256_80 => 10,
            #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
            CipherSuite::AesCtr128HmacSha256_64 => 8,
            #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
            CipherSuite::AesCtr128HmacSha256_32 => 4,
            CipherSuite::AesGcm128Sha256 | CipherSuite::AesGcm256Sha512 => 16,
        }
    }

    /// Returns true if this cipher suite uses CTR mode with HMAC authentication
    #[cfg(any(feature = "openssl", feature = "rust-crypto", test))]
    pub const fn is_ctr_mode(&self) -> bool {
        match self {
            #[cfg(any(feature = "openssl", feature = "rust-crypto"))]
            CipherSuite::AesCtr128HmacSha256_80
            | CipherSuite::AesCtr128HmacSha256_64
            | CipherSuite::AesCtr128HmacSha256_32 => true,
            CipherSuite::AesGcm128Sha256 | CipherSuite::AesGcm256Sha512 => false,
        }
    }
}
