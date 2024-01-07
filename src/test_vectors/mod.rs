// Copyright (c) 2023 GoTo Group, Inc
// SPDX-License-Identifier: Apache-2.0 AND MIT
#![allow(clippy::missing_panics_doc)]

extern crate serde;
use phf::phf_map;

#[derive(serde::Deserialize, Debug, Clone)]
pub struct TestVectors {
    pub header: Vec<HeaderTest>,
    pub aes_ctr_hmac: Vec<AesCtrHmacTest>,
    pub sframe: Vec<SframeTest>,
}

pub fn get_header_test_vectors() -> &'static Vec<HeaderTest> {
    &TEST_VECTORS.header
}

pub fn get_aes_ctr_test_vector(cipher_suite_variant: &str) -> &'static AesCtrHmacTest {
    TEST_VECTORS
        .aes_ctr_hmac
        .iter()
        .find(|v| v.cipher_suite_variant == cipher_suite_variant)
        .unwrap()
}

pub fn get_sframe_test_vector(cipher_suite_variant: &str) -> &'static SframeTest {
    TEST_VECTORS
        .sframe
        .iter()
        .find(|v| v.cipher_suite_variant == cipher_suite_variant)
        .unwrap()
}

const TEST_VECTORS_STR: &str = std::include_str!("test-vectors.json");
lazy_static::lazy_static! {
static ref TEST_VECTORS: TestVectors = {
     parse_test_vectors()
};
}

const CIPHER_SUITE_NAME_FROM_ID: phf::Map<u8, &str> = phf_map! {
        1u8 => "AesCtr128HmacSha256_80",
        2u8 => "AesCtr128HmacSha256_64",
        3u8 => "AesCtr128HmacSha256_32",
        4u8 => "AesGcm128Sha256",
        5u8 => "AesGcm256Sha512",
};

#[derive(serde::Deserialize, Debug, Clone)]
pub struct HeaderTest {
    #[serde(rename = "kid")]
    pub key_id: u64,
    #[serde(rename = "ctr")]
    pub frame_count: u64,
    #[serde(deserialize_with = "vec_from_hex_str")]
    pub encoded: Vec<u8>,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct AesCtrHmacTest {
    #[serde(
        rename = "cipher_suite",
        deserialize_with = "cipher_suite_name_from_id"
    )]
    pub cipher_suite_variant: String,

    #[serde(rename = "key", deserialize_with = "vec_from_hex_str")]
    pub base_key: Vec<u8>,

    #[serde(deserialize_with = "vec_from_hex_str")]
    pub enc_key: Vec<u8>,

    #[serde(deserialize_with = "vec_from_hex_str")]
    pub auth_key: Vec<u8>,

    #[serde(deserialize_with = "vec_from_hex_str")]
    pub nonce: Vec<u8>,

    #[serde(deserialize_with = "vec_from_hex_str")]
    pub aad: Vec<u8>,

    #[serde(rename = "pt", deserialize_with = "vec_from_hex_str")]
    pub plain_text: Vec<u8>,

    #[serde(rename = "ct", deserialize_with = "vec_from_hex_str")]
    pub cipher_text: Vec<u8>,
}

#[derive(serde::Deserialize, Debug, Clone)]
pub struct SframeTest {
    #[serde(
        rename = "cipher_suite",
        deserialize_with = "cipher_suite_name_from_id"
    )]
    pub cipher_suite_variant: String,

    #[serde(rename = "kid")]
    pub key_id: u64,

    #[serde(rename = "ctr")]
    pub frame_count: u64,

    #[serde(rename = "base_key", deserialize_with = "vec_from_hex_str")]
    pub key_material: Vec<u8>,

    #[serde(deserialize_with = "vec_from_hex_str")]
    pub sframe_key_label: Vec<u8>,

    #[serde(deserialize_with = "vec_from_hex_str")]
    pub sframe_salt_label: Vec<u8>,

    #[serde(deserialize_with = "vec_from_hex_str")]
    pub sframe_secret: Vec<u8>,

    #[serde(deserialize_with = "vec_from_hex_str")]
    pub sframe_key: Vec<u8>,

    #[serde(deserialize_with = "vec_from_hex_str")]
    pub sframe_salt: Vec<u8>,

    #[serde(deserialize_with = "vec_from_hex_str")]
    pub metadata: Vec<u8>,

    #[serde(deserialize_with = "vec_from_hex_str")]
    pub nonce: Vec<u8>,

    #[serde(deserialize_with = "vec_from_hex_str")]
    pub aad: Vec<u8>,

    #[serde(rename = "pt", deserialize_with = "vec_from_hex_str")]
    pub plain_text: Vec<u8>,

    #[serde(rename = "ct", deserialize_with = "vec_from_hex_str")]
    pub cipher_text: Vec<u8>,
}

fn vec_from_hex_str<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hex_str: &str = serde::Deserialize::deserialize(deserializer)?;
    hex::decode(hex_str).map_err(serde::de::Error::custom)
}

fn cipher_suite_name_from_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let id: u8 = serde::Deserialize::deserialize(deserializer)?;

    if let Some(&name) = CIPHER_SUITE_NAME_FROM_ID.get(&id) {
        Ok(String::from(name))
    } else {
        Err(serde::de::Error::custom(format!(
            "Invalid cipher suite id {}",
            id
        )))
    }
}

fn parse_test_vectors() -> TestVectors {
    serde_json::from_str(TEST_VECTORS_STR).unwrap()
}

#[cfg(test)]
mod test {
    use crate::test_vectors::{get_aes_ctr_test_vector, get_sframe_test_vector};

    use super::{get_header_test_vectors, CIPHER_SUITE_NAME_FROM_ID};

    #[test]
    fn should_parse_header_test_vectors() {
        let header_tests = get_header_test_vectors();
        assert_ne!(header_tests.len(), 0);
    }
    #[test]
    fn should_parse_sframe_test_vectors() {
        let valid_cipher_suite_variants = CIPHER_SUITE_NAME_FROM_ID.values();
        for &variant in valid_cipher_suite_variants {
            let sframe_test = get_sframe_test_vector(variant);
            assert_eq!(sframe_test.cipher_suite_variant, variant);
        }
    }

    #[test]
    fn should_parse_aes_test_vectors() {
        for cipher_suite_id in 1..=3u8 {
            let &variant = CIPHER_SUITE_NAME_FROM_ID.get(&cipher_suite_id).unwrap();
            let aes_ctr_test = get_aes_ctr_test_vector(variant);
            assert_eq!(aes_ctr_test.cipher_suite_variant, variant);
        }
    }
}
