use std::marker::PhantomData;

use crate::{
    CipherSuite,
    crypto::{
        aead::{AeadDecrypt, AeadEncrypt},
        buffer::{DecryptionBufferView, EncryptionBufferView},
        key_derivation::KeyDerivation,
    },
    error::Result,
    header::{Counter, KeyId},
};

/// Represents an `SFrame` encryption key as described in [RFC 9605 Section 4.4.1](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.1).
///
/// The key is generic over:
/// - `A`: The AEAD encryption implementation
/// - `D`: The key derivation implementation
///
/// The stored secret has the type produced by `D` ([`KeyDerivation::Secret`]); the matching
/// AEAD implementation `A` must consume the same type (`A::Secret == D::Secret`).
pub struct EncryptionKey<A, D>
where
    A: AeadEncrypt,
    D: KeyDerivation,
{
    aead: A,
    secret: D::Secret,
    cipher_suite: CipherSuite,
    key_id: KeyId,
    _derivation: PhantomData<D>,
}

impl<A, D> EncryptionKey<A, D>
where
    A: AeadEncrypt<Secret = D::Secret>,
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
        let aead = A::try_from(cipher_suite)?;
        let secret = D::expand_from(cipher_suite, key_material, key_id)?;

        Ok(Self {
            aead,
            secret,
            cipher_suite,
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
        self.cipher_suite
    }

    #[cfg(all(test, crypto_backend))]
    /// Creates an `SFrame` key from a test vector for testing purposes.
    pub(crate) fn from_test_vector(
        cipher_suite: CipherSuite,
        test_vec: &crate::test_vectors::SframeTest,
    ) -> Self
    where
        D: KeyDerivation<Secret = crate::crypto::secret::Secret>,
    {
        if cipher_suite.is_ctr_mode() {
            // the test vectors do not provide the auth key, so we have to expand here
            Self::derive_from(cipher_suite, test_vec.key_id, &test_vec.key_material).unwrap()
        } else {
            let secret = crate::crypto::secret::Secret::from_test_vector(test_vec);
            let aead = A::try_from(cipher_suite).unwrap();
            Self {
                aead,
                secret,
                cipher_suite,
                key_id: test_vec.key_id,
                _derivation: PhantomData,
            }
        }
    }
}

/// Represents an `SFrame` decryption key as described in [RFC 9605 Section 4.4.1](https://www.rfc-editor.org/rfc/rfc9605.html#section-4.4.1).
///
/// The key is generic over:
/// - `A`: The AEAD decryption implementation
/// - `D`: The key derivation implementation
///
/// The stored secret has the type produced by `D` ([`KeyDerivation::Secret`]); the matching
/// AEAD implementation `A` must consume the same type (`A::Secret == D::Secret`).
pub struct DecryptionKey<A, D>
where
    A: AeadDecrypt,
    D: KeyDerivation,
{
    aead: A,
    secret: D::Secret,
    cipher_suite: CipherSuite,
    key_id: KeyId,
    _derivation: PhantomData<D>,
}

impl<A, D> DecryptionKey<A, D>
where
    A: AeadDecrypt<Secret = D::Secret>,
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
        let aead = A::try_from(cipher_suite)?;
        let secret = D::expand_from(cipher_suite, key_material, key_id)?;

        Ok(Self {
            aead,
            secret,
            cipher_suite,
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
        self.cipher_suite
    }

    #[cfg(all(test, crypto_backend))]
    /// Returns a reference to the secret associated with this key (for testing).
    pub(crate) fn secret(&self) -> &D::Secret {
        &self.secret
    }

    #[cfg(all(test, crypto_backend))]
    /// Creates an `SFrame` key from a test vector for testing purposes.
    pub(crate) fn from_test_vector(
        cipher_suite: CipherSuite,
        test_vec: &crate::test_vectors::SframeTest,
    ) -> Self
    where
        D: KeyDerivation<Secret = crate::crypto::secret::Secret>,
    {
        if cipher_suite.is_ctr_mode() {
            // the test vectors do not provide the auth key, so we have to expand here
            Self::derive_from(cipher_suite, test_vec.key_id, &test_vec.key_material).unwrap()
        } else {
            let secret = crate::crypto::secret::Secret::from_test_vector(test_vec);
            let aead = A::try_from(cipher_suite).unwrap();
            Self {
                aead,
                secret,
                cipher_suite,
                key_id: test_vec.key_id,
                _derivation: PhantomData,
            }
        }
    }
}

// The keys store `D::Secret`, an associated type that `#[derive]` can't reason about, so the
// standard trait impls are generated here with the right bounds (note `D` itself need not be
// `Clone`/`Eq`/... since it is only a `PhantomData` marker).
macro_rules! impl_key_traits {
    ($name:ident, $aead:ident) => {
        impl<A, D> Clone for $name<A, D>
        where
            A: $aead + Clone,
            D: KeyDerivation,
            D::Secret: Clone,
        {
            fn clone(&self) -> Self {
                Self {
                    aead: self.aead.clone(),
                    secret: self.secret.clone(),
                    cipher_suite: self.cipher_suite,
                    key_id: self.key_id,
                    _derivation: PhantomData,
                }
            }
        }

        impl<A, D> std::fmt::Debug for $name<A, D>
        where
            A: $aead + std::fmt::Debug,
            D: KeyDerivation,
            D::Secret: std::fmt::Debug,
        {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("aead", &self.aead)
                    .field("secret", &self.secret)
                    .field("cipher_suite", &self.cipher_suite)
                    .field("key_id", &self.key_id)
                    .finish()
            }
        }

        impl<A, D> PartialEq for $name<A, D>
        where
            A: $aead + PartialEq,
            D: KeyDerivation,
            D::Secret: PartialEq,
        {
            fn eq(&self, other: &Self) -> bool {
                self.aead == other.aead
                    && self.secret == other.secret
                    && self.cipher_suite == other.cipher_suite
                    && self.key_id == other.key_id
            }
        }

        impl<A, D> Eq for $name<A, D>
        where
            A: $aead + Eq,
            D: KeyDerivation,
            D::Secret: Eq,
        {
        }
    };
}

impl_key_traits!(EncryptionKey, AeadEncrypt);
impl_key_traits!(DecryptionKey, AeadDecrypt);
