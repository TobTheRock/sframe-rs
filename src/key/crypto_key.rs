use std::marker::PhantomData;

use crate::{
    CipherSuite,
    crypto::{
        aead::{AeadDecrypt, AeadEncrypt},
        buffer::{DecryptionBufferView, EncryptionBufferView},
        cipher_suite::CipherSuiteParams,
        key_derivation::KeyDerivation,
        secret::Secret,
    },
    error::{Result, SframeError},
    header::{Counter, KeyId},
};

/// Represents an `SFrame` encryption key as described in [RFC 9605 4.4.1](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.1).
///
/// The key is generic over:
/// - `A`: The AEAD encryption implementation
/// - `D`: The key derivation implementation
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptionKey<A, D>
where
    A: AeadEncrypt,
    D: KeyDerivation,
{
    aead: A,
    secret: Secret,
    cipher_suite: CipherSuiteParams,
    key_id: KeyId,
    _derivation: PhantomData<D>,
}

impl<A, D> EncryptionKey<A, D>
where
    A: AeadEncrypt + TryFrom<CipherSuite, Error = SframeError>,
    D: KeyDerivation,
{
    /// Tries to derive an `SFrame` key from the provided base key material using the given cipher suite variant.
    /// It is then assigned the provided key ID and the cipher suite variant.
    /// If key derivation fails an error is returned.
    pub fn derive_from<K, M>(cipher_suite: CipherSuite, key_id: K, key_material: M) -> Result<Self>
    where
        K: Into<KeyId>,
        M: AsRef<[u8]>,
    {
        let key_id = key_id.into();
        let params: CipherSuiteParams = cipher_suite.into();
        let aead = A::try_from(cipher_suite)?;
        let secret = D::expand_from(&params, key_material, key_id)?;

        Ok(Self {
            aead,
            secret,
            cipher_suite: params,
            key_id,
            _derivation: PhantomData,
        })
    }

    /// Encrypts the plaintext in the buffer in-place.
    ///
    /// This is a convenience method that passes the internal secret to the AEAD implementation.
    pub fn encrypt<'a, B>(&self, buffer: B, counter: Counter) -> Result<()>
    where
        B: Into<EncryptionBufferView<'a>>,
    {
        self.aead.encrypt(&self.secret, buffer, counter)
    }

    /// Returns the associated key ID.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Returns the cipher suite variant of this key.
    pub fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite.cipher_suite
    }

    /// Returns the cipher suite parameters of this key.
    pub(crate) fn cipher_suite_params(&self) -> &CipherSuiteParams {
        &self.cipher_suite
    }

    #[cfg(test)]
    /// Returns a reference to the secret associated with this key (for testing).
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }

    #[cfg(test)]
    /// Creates an SFrame key from a test vector for testing purposes.
    pub(crate) fn from_test_vector(
        cipher_suite: CipherSuite,
        test_vec: &crate::test_vectors::SframeTest,
    ) -> Self
    where
        A: TryFrom<CipherSuite, Error = SframeError>,
    {
        let params: CipherSuiteParams = cipher_suite.into();
        if params.is_ctr_mode() {
            // the test vectors do not provide the auth key, so we have to expand here
            Self::derive_from(cipher_suite, test_vec.key_id, &test_vec.key_material).unwrap()
        } else {
            let secret = Secret::from_test_vector(test_vec);
            let aead = A::try_from(cipher_suite).unwrap();
            Self {
                aead,
                secret,
                cipher_suite: params,
                key_id: test_vec.key_id,
                _derivation: PhantomData,
            }
        }
    }
}

/// Represents an `SFrame` decryption key as described in [RFC 9605 4.4.1](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.1).
///
/// The key is generic over:
/// - `A`: The AEAD decryption implementation
/// - `D`: The key derivation implementation
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptionKey<A, D>
where
    A: AeadDecrypt,
    D: KeyDerivation,
{
    aead: A,
    secret: Secret,
    cipher_suite: CipherSuiteParams,
    key_id: KeyId,
    _derivation: PhantomData<D>,
}

impl<A, D> DecryptionKey<A, D>
where
    A: AeadDecrypt + TryFrom<CipherSuite, Error = SframeError>,
    D: KeyDerivation,
{
    /// Tries to derive an `SFrame` key from the provided base key material using the given cipher suite variant.
    /// It is then assigned the provided key ID and the cipher suite variant.
    /// If key derivation fails an error is returned.
    pub fn derive_from<K, M>(cipher_suite: CipherSuite, key_id: K, key_material: M) -> Result<Self>
    where
        K: Into<KeyId>,
        M: AsRef<[u8]>,
    {
        let key_id = key_id.into();
        let params: CipherSuiteParams = cipher_suite.into();
        let aead = A::try_from(cipher_suite)?;
        let secret = D::expand_from(&params, key_material, key_id)?;

        Ok(Self {
            aead,
            secret,
            cipher_suite: params,
            key_id,
            _derivation: PhantomData,
        })
    }

    /// Decrypts the ciphertext in the buffer in-place.
    ///
    /// This is a convenience method that passes the internal secret to the AEAD implementation.
    pub fn decrypt<'a, B>(&self, buffer: B, counter: Counter) -> Result<()>
    where
        B: Into<DecryptionBufferView<'a>>,
    {
        self.aead.decrypt(&self.secret, buffer, counter)
    }

    /// Returns the associated key ID.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Returns the cipher suite variant of this key.
    pub fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite.cipher_suite
    }

    /// Returns the cipher suite parameters of this key.
    pub(crate) fn cipher_suite_params(&self) -> &CipherSuiteParams {
        &self.cipher_suite
    }

    #[cfg(test)]
    /// Returns a reference to the secret associated with this key (for testing).
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }

    #[cfg(test)]
    /// Creates an SFrame key from a test vector for testing purposes.
    pub(crate) fn from_test_vector(
        cipher_suite: CipherSuite,
        test_vec: &crate::test_vectors::SframeTest,
    ) -> Self
    where
        A: TryFrom<CipherSuite, Error = SframeError>,
    {
        let params: CipherSuiteParams = cipher_suite.into();
        if params.is_ctr_mode() {
            // the test vectors do not provide the auth key, so we have to expand here
            Self::derive_from(cipher_suite, test_vec.key_id, &test_vec.key_material).unwrap()
        } else {
            let secret = Secret::from_test_vector(test_vec);
            let aead = A::try_from(cipher_suite).unwrap();
            Self {
                aead,
                secret,
                cipher_suite: params,
                key_id: test_vec.key_id,
                _derivation: PhantomData,
            }
        }
    }
}
