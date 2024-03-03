/// Depicts which AEAD algorithm is used for encryption
/// and which hashing function is used for the key expansion,
/// see [sframe draft 06 4.4](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-06#name-cipher-suites)
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
pub enum CipherSuiteVariant {
    // /// counter mode is [not implemented in ring](https://github.com/briansmith/ring/issues/656)
    #[cfg(feature = "openssl")]
    /// encryption: AES CTR 128 with 80 bit HMAC authentication tag, key expansion: HKDF with SHA256,
    AesCtr128HmacSha256_80 = 0x0001,
    #[cfg(feature = "openssl")]
    /// encryption: AES CTR 128 with 64 bit HMAC authentication tag, key expansion: HKDF with SHA256,
    AesCtr128HmacSha256_64 = 0x0002,
    #[cfg(feature = "openssl")]
    /// encryption: AES CTR 128 with 32 bit HMAC authentication tag, key expansion: HKDF with SHA256,
    AesCtr128HmacSha256_32 = 0x0003,
    /// encryption: AES GCM 128, key expansion: HKDF with SHA256
    AesGcm128Sha256 = 0x0004,
    /// encryption: AES GCM 256, key expansion: HKDF with SHA512
    AesGcm256Sha512 = 0x0005,
}

impl std::fmt::Display for CipherSuiteVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            #[cfg(feature = "openssl")]
            CipherSuiteVariant::AesCtr128HmacSha256_80 => "AesCtr128HmacSha256_80",
            #[cfg(feature = "openssl")]
            CipherSuiteVariant::AesCtr128HmacSha256_64 => "AesCtr128HmacSha256_64",
            #[cfg(feature = "openssl")]
            CipherSuiteVariant::AesCtr128HmacSha256_32 => "AesCtr128HmacSha256_32",
            CipherSuiteVariant::AesGcm128Sha256 => "AesGcm128Sha256",
            CipherSuiteVariant::AesGcm256Sha512 => "AesGcm256Sha512",
        };
        f.write_str(str)
    }
}

/// cipher suite as of [sframe draft 06 4.5](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-06#cipher-suites)
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct CipherSuite {
    pub variant: CipherSuiteVariant,
    /// Hash.Nh - The size in bytes of the output of the hash function
    pub hash_len: usize,
    /// AEAD.Nk - The size in bytes of a key for the encryption algorithm
    pub key_len: usize,
    /// AEAD.Nn - The size in bytes of a nonce for the encryption algorithm
    pub nonce_len: usize,
    /// AEAD.Nt - The overhead in bytes of the encryption algorithm (typically the size of a "tag" that is added to the plaintext)
    pub auth_tag_len: usize,
}

impl From<CipherSuiteVariant> for CipherSuite {
    fn from(variant: CipherSuiteVariant) -> Self {
        match variant {
            #[cfg(feature = "openssl")]
            CipherSuiteVariant::AesCtr128HmacSha256_80 => CipherSuite {
                variant,
                hash_len: 32,
                key_len: 48,
                nonce_len: 12,
                auth_tag_len: 10,
            },

            #[cfg(feature = "openssl")]
            CipherSuiteVariant::AesCtr128HmacSha256_64 => CipherSuite {
                variant,
                hash_len: 32,
                key_len: 48,
                nonce_len: 12,
                auth_tag_len: 8,
            },
            #[cfg(feature = "openssl")]
            CipherSuiteVariant::AesCtr128HmacSha256_32 => CipherSuite {
                variant,
                hash_len: 32,
                key_len: 48,
                nonce_len: 12,
                auth_tag_len: 4,
            },
            CipherSuiteVariant::AesGcm128Sha256 => CipherSuite {
                variant,
                hash_len: 32,
                key_len: 16,
                nonce_len: 12,
                auth_tag_len: 16,
            },
            CipherSuiteVariant::AesGcm256Sha512 => CipherSuite {
                variant,
                hash_len: 64,
                key_len: 32,
                nonce_len: 12,
                auth_tag_len: 16,
            },
        }
    }
}

impl CipherSuite {
    #[cfg(any(feature = "openssl", test))]
    pub(crate) fn is_ctr_mode(&self) -> bool {
        match self.variant {
            #[cfg(feature = "openssl")]
            CipherSuiteVariant::AesCtr128HmacSha256_80
            | CipherSuiteVariant::AesCtr128HmacSha256_64
            | CipherSuiteVariant::AesCtr128HmacSha256_32 => true,
            CipherSuiteVariant::AesGcm128Sha256 | CipherSuiteVariant::AesGcm256Sha512 => false,
        }
    }
}
