use crate::{
    crypto::{cipher_suite::CipherSuite, key_derivation::KeyDerivation, secret::Secret},
    error::Result,
    header::KeyId,
    CipherSuiteVariant,
};

macro_rules! sframe_key {
    ($name:ident, $purpose:literal) => {
        /// Represents an Sframe key as described in [RFC 9605 4.4.1](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.1).
        /// It is associated with a key ID and a cipher suite which is used for
        #[doc = concat!($purpose, ".")]
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name {
            secret: Secret,
            cipher_suite: CipherSuite,
            key_id: KeyId,
        }

        impl $name {
            /// Tries to derive an Sframe key from the provided base key material using the given cipher suite variant.
            /// It is then assigned the provided key ID and the cipher suite variant.
            /// If key derivation fails an error is returned.
            pub fn derive_from<K, M>(
                variant: CipherSuiteVariant,
                key_id: K,
                key_material: M,
            ) -> Result<Self>
            where
                K: Into<KeyId>,
                M: AsRef<[u8]>,
            {
                let key_id = key_id.into();
                let cipher_suite = variant.into();

                let secret = Secret::expand_from(&cipher_suite, key_material, key_id)?;

                Ok(Self {
                    secret,
                    cipher_suite,
                    key_id,
                })
            }

            /// Returns the associated key ID.
            pub fn key_id(&self) -> KeyId {
                self.key_id
            }

            /// Returns the cipher suite variant of this key.
            pub fn cipher_suite_variant(&self) -> CipherSuiteVariant {
                self.cipher_suite.variant
            }

            /// Returns a reference to the secret associated with this key.
            pub(crate) fn secret(&self) -> &Secret {
                &self.secret
            }

            /// Returns the cipher suite of this key.
            pub(crate) fn cipher_suite(&self) -> &CipherSuite {
                &self.cipher_suite
            }

            #[cfg(test)]
            /// Creates an Sframe key from a test vector for testing purposes.
            pub(crate) fn from_test_vector(
                variant: CipherSuiteVariant,
                test_vec: &crate::test_vectors::SframeTest,
            ) -> Self {
                let cipher_suite: CipherSuite = variant.into();
                if cipher_suite.is_ctr_mode() {
                    // the test vectors do not provide the auth key, so we have to expand here
                    $name::derive_from(variant, test_vec.key_id, &test_vec.key_material).unwrap()
                } else {
                    let secret = Secret::from_test_vector(test_vec);
                    $name {
                        secret,
                        cipher_suite,
                        key_id: test_vec.key_id,
                    }
                }
            }
        }
    };
}

sframe_key!(EncryptionKey, "encryption");
sframe_key!(DecryptionKey, "decryption");
