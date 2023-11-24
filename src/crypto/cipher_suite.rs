// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT

/// Depicts which AEAD algorithm is used for encryption
/// and which hashing function is used for the key expansion,
/// see [sframe draft 03 4.4](https://datatracker.ietf.org/doc/html/draft-ietf-sframe-enc-03#name-cipher-suites)
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(test, derive(strum_macros::Display))]
pub enum CipherSuiteVariant {
    // /// counter mode is [not implemented in ring](https://github.com/briansmith/ring/issues/656)
    #[cfg(feature = "openssl")]
    AesCtr128HmacSha256_80,
    #[cfg(feature = "openssl")]
    AesCtr128HmacSha256_64,
    #[cfg(feature = "openssl")]
    AesCtr128HmacSha256_32,
    /// encryption: AES GCM 128, key expansion: HKDF with SHA256
    AesGcm128Sha256,
    /// encryption: AES GCM 256, key expansion: HKDF with SHA512
    AesGcm256Sha512,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct CipherSuite {
    pub id: u16,
    pub variant: CipherSuiteVariant,
    pub hash_len: usize,
    pub key_len: usize,
    pub nonce_len: usize,
    pub auth_tag_len: usize,
}

impl From<CipherSuiteVariant> for CipherSuite {
    fn from(variant: CipherSuiteVariant) -> Self {
        match variant {
            #[cfg(feature = "openssl")]
            CipherSuiteVariant::AesCtr128HmacSha256_80 => CipherSuite {
                id: 0x0001,
                variant,
                hash_len: 32,
                key_len: 48,
                nonce_len: 12,
                auth_tag_len: 10,
            },

            #[cfg(feature = "openssl")]
            CipherSuiteVariant::AesCtr128HmacSha256_64 => CipherSuite {
                id: 0x0002,
                variant,
                hash_len: 32,
                key_len: 48,
                nonce_len: 12,
                auth_tag_len: 8,
            },
            #[cfg(feature = "openssl")]
            CipherSuiteVariant::AesCtr128HmacSha256_32 => CipherSuite {
                id: 0x0003,
                variant,
                hash_len: 32,
                key_len: 48,
                nonce_len: 12,
                auth_tag_len: 4,
            },
            CipherSuiteVariant::AesGcm128Sha256 => CipherSuite {
                id: 0x0004,
                variant,
                hash_len: 32,
                key_len: 16,
                nonce_len: 12,
                auth_tag_len: 16,
            },
            CipherSuiteVariant::AesGcm256Sha512 => CipherSuite {
                id: 0x0005,
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
