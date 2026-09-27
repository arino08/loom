//! Signed tree heads and witness cosignatures.
//!
//! * Log checkpoints follow c2sp.org/tlog-checkpoint and are signed with a
//!   standard c2sp.org/signed-note Ed25519 signature (algorithm byte 0x01).
//! * Witness cosignatures follow c2sp.org/tlog-cosignature v1: the signed
//!   message is `"cosignature/v1\ntime <ts>\n" || checkpoint body`, the
//!   signature bytes are `u64be(ts) || ed25519_sig`, and the key ID uses
//!   algorithm byte 0x04 so a witness key can never be confused with a log key.
//!
//! Text framing is delegated to the `signed_note` crate; all signing and
//! verification is Ed25519 from `ed25519-dalek` (CON-5).

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use loom_core::keys::{PublicKey, SecretKey};
use signed_note::{key_id, Note, Signer, Verifier, VerifierList};
use tlog_tiles::checkpoint::Checkpoint;
use tlog_tiles::tlog::Hash;

pub const ALG_ED25519: u8 = 0x01;
pub const ALG_COSIGNATURE_V1: u8 = 0x04;

fn prefixed(alg: u8, pk: &PublicKey) -> Vec<u8> {
    let mut v = vec![alg];
    v.extend_from_slice(&pk.bytes());
    v
}

pub fn log_key_id(name: &str, pk: &PublicKey) -> u32 {
    key_id(name, &prefixed(ALG_ED25519, pk))
}

pub fn cosig_key_id(name: &str, pk: &PublicKey) -> u32 {
    key_id(name, &prefixed(ALG_COSIGNATURE_V1, pk))
}

/// Verifier key string in the standard note format `<name>+<hex id>+<b64(alg||key)>`.
pub fn vkey(name: &str, pk: &PublicKey) -> String {
    format!(
        "{name}+{:08x}+{}",
        log_key_id(name, pk),
        B64.encode(prefixed(ALG_ED25519, pk))
    )
}

/// Parse a verifier key produced by [`vkey`].
pub fn parse_vkey(s: &str) -> anyhow::Result<(String, PublicKey)> {
    let mut parts = s.trim().splitn(3, '+');
    let (name, id, key) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    );
    let raw = B64.decode(key)?;
    if raw.len() != 33 || raw[0] != ALG_ED25519 {
        anyhow::bail!("unsupported verifier key");
    }
    let pk = PublicKey::from_bytes(&raw[1..])?;
    if format!("{:08x}", log_key_id(name, &pk)) != id {
        anyhow::bail!("verifier key id mismatch");
    }
    Ok((name.to_string(), pk))
}

pub struct LogSigner<'a> {
    pub name: String,
    pub key: &'a SecretKey,
}

impl Signer for LogSigner<'_> {
    fn name(&self) -> &str {
        &self.name
    }
    fn key_id(&self) -> u32 {
        log_key_id(&self.name, &self.key.public())
    }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, signature::Error> {
        Ok(self.key.sign(msg).to_vec())
    }
}

pub struct LogVerifier {
    pub name: String,
    pub key: PublicKey,
}

impl Verifier for LogVerifier {
    fn name(&self) -> &str {
        &self.name
    }
    fn key_id(&self) -> u32 {
        log_key_id(&self.name, &self.key)
    }
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        self.key.verify(msg, sig).is_ok()
    }
}

pub fn cosignature_message(timestamp: u64, body: &[u8]) -> Vec<u8> {
    let mut m = format!("cosignature/v1\ntime {timestamp}\n").into_bytes();
    m.extend_from_slice(body);
    m
}

pub struct CosignSigner<'a> {
    pub name: String,
    pub key: &'a SecretKey,
    pub timestamp: u64,
}

impl Signer for CosignSigner<'_> {
    fn name(&self) -> &str {
        &self.name
    }
    fn key_id(&self) -> u32 {
        cosig_key_id(&self.name, &self.key.public())
    }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, signature::Error> {
        let mut out = self.timestamp.to_be_bytes().to_vec();
        out.extend_from_slice(&self.key.sign(&cosignature_message(self.timestamp, msg)));
        Ok(out)
    }
}

pub struct CosignVerifier {
    pub name: String,
    pub key: PublicKey,
}

impl Verifier for CosignVerifier {
    fn name(&self) -> &str {
        &self.name
    }
    fn key_id(&self) -> u32 {
        cosig_key_id(&self.name, &self.key)
    }
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        if sig.len() != 72 {
            return false;
        }
        let ts = u64::from_be_bytes(sig[..8].try_into().unwrap());
        if ts > i64::MAX as u64 {
            return false;
        }
        self.key.verify(&cosignature_message(ts, msg), &sig[8..]).is_ok()
    }
}

/// A checkpoint whose log signature has been verified.
#[derive(Clone, Debug)]
pub struct SignedCheckpoint {
    pub origin: String,
    pub size: u64,
    pub root: Hash,
    /// The full note (body + all signature lines).
    pub note: Vec<u8>,
}

impl SignedCheckpoint {
    pub fn root_b64(&self) -> String {
        B64.encode(self.root.0)
    }
}

/// Create and sign a checkpoint.
pub fn sign_checkpoint(origin: &str, size: u64, root: Hash, key: &SecretKey) -> anyhow::Result<Vec<u8>> {
    let cp = Checkpoint::new(origin, size, root, "").map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut note = Note::new(&cp.to_bytes(), &[]).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let signer = LogSigner {
        name: origin.to_string(),
        key,
    };
    note.add_sigs(&[&signer]).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    Ok(note.to_bytes())
}

/// Parse a note and verify the log's signature on it.
pub fn open_checkpoint(note_bytes: &[u8], origin: &str, log_key: &PublicKey) -> anyhow::Result<SignedCheckpoint> {
    let note = Note::from_bytes(note_bytes).map_err(|e| anyhow::anyhow!("malformed note: {e:?}"))?;
    let verifiers = VerifierList::new(vec![Box::new(LogVerifier {
        name: origin.to_string(),
        key: log_key.clone(),
    })]);
    note.verify(&verifiers)
        .map_err(|e| anyhow::anyhow!("log signature verification failed: {e:?}"))?;
    let cp = Checkpoint::from_bytes(note.text()).map_err(|e| anyhow::anyhow!("{e}"))?;
    if cp.origin() != origin {
        anyhow::bail!("checkpoint origin {:?} != expected {:?}", cp.origin(), origin);
    }
    Ok(SignedCheckpoint {
        origin: origin.to_string(),
        size: cp.size(),
        root: *cp.hash(),
        note: note_bytes.to_vec(),
    })
}

/// Return the note body (text without signatures).
pub fn note_text(note_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let note = Note::from_bytes(note_bytes).map_err(|e| anyhow::anyhow!("malformed note: {e:?}"))?;
    Ok(note.text().to_vec())
}

/// Produce a witness cosignature line for a checkpoint note.
pub fn cosign(note_bytes: &[u8], name: &str, key: &SecretKey, timestamp: u64) -> anyhow::Result<Vec<u8>> {
    let mut note = Note::from_bytes(note_bytes).map_err(|e| anyhow::anyhow!("malformed note: {e:?}"))?;
    let before = note.to_bytes();
    let signer = CosignSigner {
        name: name.to_string(),
        key,
        timestamp,
    };
    note.add_sigs(&[&signer]).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let after = note.to_bytes();
    // The new signature line is the suffix added by add_sigs (or, if the
    // witness had cosigned before, the replaced line at the end).
    let line = after
        .split(|&b| b == b'\n')
        .filter(|l| l.starts_with("— ".as_bytes()))
        .last()
        .ok_or_else(|| anyhow::anyhow!("no signature produced"))?
        .to_vec();
    let _ = before;
    let mut out = line;
    out.push(b'\n');
    Ok(out)
}

/// Append signature lines (e.g. witness cosignatures) to a note.
pub fn add_signature_lines(note_bytes: &[u8], lines: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut v = note_bytes.to_vec();
    for line in lines.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if !line.starts_with("— ".as_bytes()) {
            anyhow::bail!("not a signature line");
        }
        // Skip duplicates.
        let text = String::from_utf8_lossy(&v).to_string();
        let l = String::from_utf8_lossy(line).to_string();
        if text.lines().any(|x| x == l) {
            continue;
        }
        v.extend_from_slice(line);
        v.push(b'\n');
    }
    Note::from_bytes(&v).map_err(|e| anyhow::anyhow!("resulting note malformed: {e:?}"))?;
    Ok(v)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cosig {
    pub witness: String,
    pub timestamp: u64,
}

/// Verify cosignatures from each named witness. Returns the witnesses whose
/// cosignature verified. A witness with an *invalid* cosignature is treated
/// as absent (and reported in the error list).
pub fn verify_cosignatures(
    note_bytes: &[u8],
    witnesses: &[(String, PublicKey)],
) -> (Vec<Cosig>, Vec<String>) {
    let mut ok = vec![];
    let mut bad = vec![];
    let Ok(note) = Note::from_bytes(note_bytes) else {
        return (ok, vec!["malformed note".into()]);
    };
    for (name, pk) in witnesses {
        let list = VerifierList::new(vec![Box::new(CosignVerifier {
            name: name.clone(),
            key: pk.clone(),
        })]);
        match note.verify(&list) {
            Ok((verified, _)) => {
                if let Some(s) = verified.first() {
                    let ts = u64::from_be_bytes(s.signature()[..8].try_into().unwrap());
                    ok.push(Cosig {
                        witness: name.clone(),
                        timestamp: ts,
                    });
                }
            }
            Err(signed_note::NoteError::UnverifiedNote) => {}
            Err(e) => bad.push(format!("{name}: {e:?}")),
        }
    }
    (ok, bad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::Tree;

    #[test]
    fn checkpoint_sign_open_cosign() {
        let logk = SecretKey::generate();
        let w1 = SecretKey::generate();
        let w2 = SecretKey::generate();
        let mut t = Tree::new();
        t.append(b"a".to_vec()).unwrap();
        let note = sign_checkpoint("loom.test/warp", 1, t.root(), &logk).unwrap();
        let cp = open_checkpoint(&note, "loom.test/warp", &logk.public()).unwrap();
        assert_eq!(cp.size, 1);
        assert_eq!(cp.root, t.root());

        // Wrong origin / wrong key rejected.
        assert!(open_checkpoint(&note, "other", &logk.public()).is_err());
        assert!(open_checkpoint(&note, "loom.test/warp", &w1.public()).is_err());

        let l1 = cosign(&note, "w1.test", &w1, 1000).unwrap();
        let l2 = cosign(&note, "w2.test", &w2, 1001).unwrap();
        let mut full = add_signature_lines(&note, &l1).unwrap();
        full = add_signature_lines(&full, &l2).unwrap();
        // Still verifies as a log checkpoint.
        open_checkpoint(&full, "loom.test/warp", &logk.public()).unwrap();

        let ws = vec![
            ("w1.test".to_string(), w1.public()),
            ("w2.test".to_string(), w2.public()),
            ("w3.test".to_string(), SecretKey::generate().public()),
        ];
        let (ok, bad) = verify_cosignatures(&full, &ws);
        assert!(bad.is_empty(), "{bad:?}");
        assert_eq!(ok.len(), 2);
        assert_eq!(ok[0].timestamp, 1000);

        // A log key must not validate as a cosignature (different alg byte).
        let (ok, _) = verify_cosignatures(&full, &[("loom.test/warp".into(), logk.public())]);
        assert!(ok.is_empty());
    }

    #[test]
    fn vkey_roundtrip() {
        let k = SecretKey::generate();
        let s = vkey("loom.test/warp", &k.public());
        let (n, pk) = parse_vkey(&s).unwrap();
        assert_eq!(n, "loom.test/warp");
        assert_eq!(pk, k.public());
    }
}
