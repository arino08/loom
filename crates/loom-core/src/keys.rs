//! Ed25519 key handling (FR-4.3, NFR-SEC-2).
//!
//! Private keys are written with mode 0600 and are only ever read by the
//! process that owns them; there is no API to export a private key over the
//! network.

use anyhow::Context;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct KeyId(pub String);

#[derive(Clone)]
pub struct SecretKey {
    pub name: String,
    inner: SigningKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    inner: VerifyingKey,
}

#[derive(Serialize, Deserialize)]
struct KeyFile {
    alg: String,
    name: String,
    private: String,
    public: String,
}

impl SecretKey {
    pub fn generate() -> Self {
        Self::generate_named("unnamed")
    }

    pub fn generate_named(name: &str) -> Self {
        let inner = SigningKey::generate(&mut rand::rngs::OsRng);
        SecretKey {
            name: name.to_string(),
            inner,
        }
    }

    pub fn from_seed(name: &str, seed: [u8; 32]) -> Self {
        SecretKey {
            name: name.to_string(),
            inner: SigningKey::from_bytes(&seed),
        }
    }

    pub fn public(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.verifying_key(),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.inner.sign(msg).to_bytes()
    }

    pub fn dalek(&self) -> &SigningKey {
        &self.inner
    }

    /// Persist with 0600 permissions. Refuses to overwrite an existing key.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let kf = KeyFile {
            alg: "ed25519".into(),
            name: self.name.clone(),
            private: B64.encode(self.inner.to_bytes()),
            public: self.public().to_b64(),
        };
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating key file {}", path.display()))?;
        f.write_all(serde_json::to_string_pretty(&kf)?.as_bytes())?;
        Ok(())
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .with_context(|| format!("reading key file {}", path.display()))?;
        if meta.permissions().mode() & 0o077 != 0 {
            anyhow::bail!(
                "private key {} is accessible by group/other (mode {:o}); refusing to use it",
                path.display(),
                meta.permissions().mode() & 0o777
            );
        }
        let kf: KeyFile = serde_json::from_slice(&std::fs::read(path)?)?;
        if kf.alg != "ed25519" {
            anyhow::bail!("unsupported key algorithm {}", kf.alg);
        }
        let raw = B64.decode(kf.private)?;
        let seed: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad private key length"))?;
        Ok(Self::from_seed(&kf.name, seed))
    }

    /// Load if present, otherwise generate and save.
    pub fn load_or_generate(path: &Path, name: &str) -> anyhow::Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            let k = Self::generate_named(name);
            k.save(path)?;
            Ok(k)
        }
    }
}

impl PublicKey {
    pub fn from_bytes(b: &[u8]) -> anyhow::Result<Self> {
        let arr: [u8; 32] = b
            .try_into()
            .map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?;
        Ok(PublicKey {
            inner: VerifyingKey::from_bytes(&arr)?,
        })
    }

    pub fn from_b64(s: &str) -> anyhow::Result<Self> {
        Self::from_bytes(&B64.decode(s.trim())?)
    }

    pub fn to_b64(&self) -> String {
        B64.encode(self.inner.to_bytes())
    }

    pub fn bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    pub fn dalek(&self) -> &VerifyingKey {
        &self.inner
    }

    /// Key ID: `ed25519:` + first 16 hex chars of SHA-256(public key).
    pub fn key_id(&self) -> KeyId {
        let h = Sha256::digest(self.inner.to_bytes());
        KeyId(format!("ed25519:{}", &hex::encode(h)[..16]))
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> anyhow::Result<()> {
        let arr: [u8; 64] = sig
            .try_into()
            .map_err(|_| anyhow::anyhow!("signature must be 64 bytes"))?;
        let sig = ed25519_dalek::Signature::from_bytes(&arr);
        // verify_strict rejects malleable / small-order edge cases.
        self.inner
            .verify_strict(msg, &sig)
            .map_err(|e| anyhow::anyhow!("bad signature: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_load_roundtrip_and_perms() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k.json");
        let k = SecretKey::generate_named("thread-a");
        k.save(&p).unwrap();
        let k2 = SecretKey::load(&p).unwrap();
        assert_eq!(k.public(), k2.public());
        assert_eq!(k2.name, "thread-a");
        // No overwrite.
        assert!(k.save(&p).is_err());
        // Loose permissions are refused.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(SecretKey::load(&p).is_err());
    }

    #[test]
    fn verify() {
        let k = SecretKey::generate();
        let s = k.sign(b"m");
        assert!(k.public().verify(b"m", &s).is_ok());
        assert!(k.public().verify(b"n", &s).is_err());
    }
}
