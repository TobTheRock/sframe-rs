use std::marker::PhantomData;

use zeroize::ZeroizeOnDrop;

use crate::{CipherSuite, crypto::key_derivation::Ratcheting, error::Result};

/// Key material which is ratcheted forward as of [RFC 9605 Section 5.1](https://www.rfc-editor.org/rfc/rfc9605.html#section-5.1),
/// deriving the material of each ratchet step with HKDF.
///
/// The original key material is not stored for security reasons.
#[derive(ZeroizeOnDrop)]
pub struct GenericRatchetingKeyMaterial<D>
where
    D: Ratcheting,
{
    #[zeroize(skip)]
    cipher_suite: CipherSuite,
    current: Vec<u8>,
    #[zeroize(skip)]
    _ratcheting: PhantomData<D>,
}

impl<D> GenericRatchetingKeyMaterial<D>
where
    D: Ratcheting,
{
    /// creates a [`GenericRatchetingKeyMaterial`] from the given key material.
    /// The cipher suite is used when ratcheting forward.
    /// Initially ratchets once to not store the original key material
    pub fn derive_from<M>(cipher_suite: CipherSuite, key_material: M) -> Result<Self>
    where
        M: AsRef<[u8]>,
    {
        let material = Self {
            cipher_suite,
            current: key_material.as_ref().into(),
            _ratcheting: PhantomData,
        };

        material.ratchet()
    }

    /// Ratchets forward, providing the key material of the next ratchet step.
    /// The material it was ratcheted from is zeroized as soon as it is dropped.
    pub fn ratchet(&self) -> Result<Self> {
        let next = D::ratchet(self.cipher_suite, &self.current)?;
        let new_material = Self {
            cipher_suite: self.cipher_suite,
            current: next,
            _ratcheting: PhantomData,
        };
        Ok(new_material)
    }
}

impl<D> Clone for GenericRatchetingKeyMaterial<D>
where
    D: Ratcheting,
{
    fn clone(&self) -> Self {
        Self {
            cipher_suite: self.cipher_suite,
            current: self.current.clone(),
            _ratcheting: PhantomData,
        }
    }
}

impl<D> AsRef<[u8]> for GenericRatchetingKeyMaterial<D>
where
    D: Ratcheting,
{
    fn as_ref(&self) -> &[u8] {
        self.current.as_ref()
    }
}

#[cfg(all(test, crypto_backend))]
mod test {
    use crate::CipherSuite;
    use crate::crypto::Kdf;

    // Exercise the generic key material with the default crypto backend.
    type RatchetingKeyMaterial = super::GenericRatchetingKeyMaterial<Kdf>;

    const SECRET: &[u8] = b"SuperSecret";

    #[test]
    fn ratchets_forward() {
        let material =
            RatchetingKeyMaterial::derive_from(CipherSuite::AesGcm128Sha256, SECRET).unwrap();

        let first = material.ratchet().unwrap();
        let second = first.ratchet().unwrap();

        // the original key material is not handed out again
        assert_ne!(SECRET, first.as_ref());
        assert_ne!(first.as_ref(), second.as_ref());
    }

    #[test]
    fn ratchets_deterministically() {
        let material =
            RatchetingKeyMaterial::derive_from(CipherSuite::AesGcm128Sha256, SECRET).unwrap();
        let same_material =
            RatchetingKeyMaterial::derive_from(CipherSuite::AesGcm128Sha256, SECRET).unwrap();

        assert_eq!(
            material.ratchet().unwrap().as_ref(),
            same_material.ratchet().unwrap().as_ref()
        );
    }
}
