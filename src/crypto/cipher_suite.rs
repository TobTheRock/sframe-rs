/// Depicts which AEAD algorithm is used for encryption
/// and which hashing function is used for the key expansion,
/// see [sframe draft 04 4.4](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-04#name-cipher-suites)
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(strum_macros::Display))]
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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct CipherSuite {
    pub variant: CipherSuiteVariant,
    pub hash_len: usize,
    pub key_len: usize,
    pub nonce_len: usize,
    pub auth_tag_len: usize,
}

pub type CipherSuiteRef = &'static CipherSuite;

static CIPHER_SUITE_AES_GCM128_SHA256: CipherSuite = CipherSuite {
    variant: CipherSuiteVariant::AesGcm128Sha256,
    hash_len: 32,
    key_len: 16,
    nonce_len: 12,
    auth_tag_len: 16,
};

static CIPHER_SUITE_AES_GCM256_SHA512: CipherSuite = CipherSuite {
    variant: CipherSuiteVariant::AesGcm256Sha512,
    hash_len: 64,
    key_len: 32,
    nonce_len: 12,
    auth_tag_len: 16,
};

#[cfg(feature = "openssl")]
static CIPHER_SUITE_VARIANT_AES_CTR128_HMAC_SHA256_80: CipherSuite = CipherSuite {
    variant: CipherSuiteVariant::AesCtr128HmacSha256_80,
    hash_len: 32,
    key_len: 48,
    nonce_len: 12,
    auth_tag_len: 10,
};

#[cfg(feature = "openssl")]
static CIPHER_SUITE_VARIANT_AES_CTR128_HMAC_SHA256_64: CipherSuite = CipherSuite {
    variant: CipherSuiteVariant::AesCtr128HmacSha256_64,
    hash_len: 32,
    key_len: 48,
    nonce_len: 12,
    auth_tag_len: 8,
};

#[cfg(feature = "openssl")]
static CIPHER_SUITE_VARIANT_AES_CTR128_HMAC_SHA256_32: CipherSuite = CipherSuite {
    variant: CipherSuiteVariant::AesCtr128HmacSha256_32,
    hash_len: 32,
    key_len: 48,
    nonce_len: 12,
    auth_tag_len: 4,
};

impl From<CipherSuiteVariant> for CipherSuiteRef {
    fn from(variant: CipherSuiteVariant) -> Self {
        match variant {
            CipherSuiteVariant::AesCtr128HmacSha256_80 => {
                &CIPHER_SUITE_VARIANT_AES_CTR128_HMAC_SHA256_80
            }
            CipherSuiteVariant::AesCtr128HmacSha256_64 => {
                &CIPHER_SUITE_VARIANT_AES_CTR128_HMAC_SHA256_64
            }
            CipherSuiteVariant::AesCtr128HmacSha256_32 => {
                &CIPHER_SUITE_VARIANT_AES_CTR128_HMAC_SHA256_32
            }
            CipherSuiteVariant::AesGcm128Sha256 => &CIPHER_SUITE_AES_GCM128_SHA256,
            CipherSuiteVariant::AesGcm256Sha512 => &CIPHER_SUITE_AES_GCM256_SHA512,
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
