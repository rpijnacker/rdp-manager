//! Versleuteling van connectie-gegevens.
//!
//! * XChaCha20-Poly1305 (AEAD): vertrouwelijkheid én integriteit.
//! * Elke waarde krijgt een willekeurige 24-byte nonce.
//! * Het connectie-id wordt als AAD meegegeven, zodat een blob niet naar een
//!   andere rij gekopieerd kan worden zonder dat de ontsleuteling faalt.
//! * De sleutel komt uit de OS-keyring (Windows Credential Manager) of wordt
//!   met Argon2id afgeleid van een hoofdwachtwoord.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305,
    aead::{Aead, Payload},
};
use zeroize::Zeroizing;

const NONCE_LEN: usize = 24;
pub const KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("ontsleutelen mislukt (verkeerde sleutel of beschadigde data)")]
    Decrypt,
    #[error("ongeldige data")]
    Format,
    #[error("willekeurige data niet beschikbaar: {0}")]
    Random(String),
    #[error("sleutelafleiding mislukt: {0}")]
    Kdf(String),
}

pub struct Vault {
    key: Zeroizing<[u8; KEY_LEN]>,
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| CryptoError::Random(e.to_string()))?;
    Ok(b)
}

/// Afleiden van een sleutel uit een hoofdwachtwoord (Argon2id, 64 MiB, t=3).
pub fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, CryptoError> {
    let params = Params::new(64 * 1024, 3, 1, Some(KEY_LEN)).map_err(|e| CryptoError::Kdf(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), salt, &mut *out)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    Ok(out)
}

impl Vault {
    pub fn new(key: Zeroizing<[u8; KEY_LEN]>) -> Self {
        Self { key }
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new_from_slice(&*self.key).expect("sleutel is 32 bytes")
    }

    /// Resultaat: nonce (24) || ciphertext+tag.
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = random_bytes::<NONCE_LEN>()?;
        let ct = self
            .cipher()
            .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
            .map_err(|_| CryptoError::Decrypt)?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn open(&self, aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        if blob.len() < NONCE_LEN + 16 {
            return Err(CryptoError::Format);
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CryptoError::Format)?;
        self.cipher()
            .decrypt((&nonce).into(), Payload { msg: ct, aad })
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault(b: u8) -> Vault {
        Vault::new(Zeroizing::new([b; KEY_LEN]))
    }

    #[test]
    fn roundtrip() {
        let v = vault(1);
        let blob = v.seal(b"id1", b"geheim").unwrap();
        assert_eq!(&**v.open(b"id1", &blob).unwrap(), b"geheim");
    }

    #[test]
    fn nonce_is_unique() {
        let v = vault(1);
        assert_ne!(v.seal(b"a", b"x").unwrap(), v.seal(b"a", b"x").unwrap());
    }

    #[test]
    fn wrong_key_or_aad_or_tamper_fails() {
        let v = vault(1);
        let mut blob = v.seal(b"id1", b"geheim").unwrap();
        assert!(vault(2).open(b"id1", &blob).is_err());
        assert!(v.open(b"id2", &blob).is_err());
        *blob.last_mut().unwrap() ^= 1;
        assert!(v.open(b"id1", &blob).is_err());
    }

    #[test]
    fn kdf_is_deterministic_per_salt() {
        let a = derive_key("pw", b"saltsaltsaltsalt").unwrap();
        let b = derive_key("pw", b"saltsaltsaltsalt").unwrap();
        let c = derive_key("pw", b"saltsaltsaltSALT").unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
    }
}
