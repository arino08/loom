//! DSSE (Dead Simple Signing Envelope) — the envelope format used by in-toto
//! and Sigstore. The signature covers the Pre-Authentication Encoding
//! `PAE(type, body)`, so a signature over an attestation can never be replayed
//! as a signature over a revocation (distinct payload types).
//!
//! Spec: <https://github.com/secure-systems-lab/dsse/blob/master/protocol.md>

use crate::keys::{KeyId, PublicKey, SecretKey};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub keyid: String,
    pub sig: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// Base64 of the payload bytes.
    pub payload: String,
    pub signatures: Vec<Signature>,
}

/// Pre-Authentication Encoding, DSSE v1.
pub fn pae(payload_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

impl Envelope {
    pub fn sign(payload_type: &str, body: &[u8], key: &SecretKey) -> Self {
        let sig = key.sign(&pae(payload_type, body));
        Envelope {
            payload_type: payload_type.to_string(),
            payload: B64.encode(body),
            signatures: vec![Signature {
                keyid: key.public().key_id().0,
                sig: B64.encode(sig),
            }],
        }
    }

    pub fn payload_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(B64.decode(&self.payload)?)
    }

    /// Key IDs claimed by the signatures (unverified).
    pub fn claimed_keyids(&self) -> Vec<KeyId> {
        self.signatures
            .iter()
            .map(|s| KeyId(s.keyid.clone()))
            .collect()
    }

    /// Verify that at least one signature is valid under `key`. Returns the
    /// payload bytes on success. Trust is derived only from this check
    /// (FR-2.6): the caller decides which keys it is willing to pass in.
    pub fn verify(&self, key: &PublicKey) -> anyhow::Result<Vec<u8>> {
        let body = self.payload_bytes()?;
        let msg = pae(&self.payload_type, &body);
        let want = key.key_id();
        for s in &self.signatures {
            if s.keyid != want.0 {
                continue;
            }
            let raw = B64.decode(&s.sig)?;
            if key.verify(&msg, &raw).is_ok() {
                return Ok(body);
            }
        }
        anyhow::bail!("no valid DSSE signature from key {}", want.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_type_binding() {
        let k = SecretKey::generate();
        let env = Envelope::sign("application/vnd.test", b"hello", &k);
        assert_eq!(env.verify(&k.public()).unwrap(), b"hello");

        // Changing the payload type must invalidate the signature.
        let mut forged = env.clone();
        forged.payload_type = "application/vnd.other".into();
        assert!(forged.verify(&k.public()).is_err());

        // A different key must not verify.
        let other = SecretKey::generate();
        assert!(env.verify(&other.public()).is_err());
    }

    #[test]
    fn pae_matches_spec_example() {
        // Example from the DSSE protocol document.
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
        );
    }
}
