//! Attestation and revocation schema.
//!
//! Attestations are in-toto Statements (v1) wrapped in DSSE envelopes. The
//! predicate is Loom-specific but follows the shape of SLSA provenance: it
//! binds *what was built* (subject digest) to *what it was built from* (source
//! commit + source digest) and *who/how* (rebuilder identity + toolchain
//! descriptor). FR-4.2 lists the mandatory fields.
//!
//! Log leaves are [`LogRecord`]s, canonically serialised (SRS §7.3).

use crate::digest::Digest;
use crate::dsse::Envelope;
use crate::keys::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const REBUILD_PREDICATE: &str = "https://loom.dev/attestation/rebuild/v1";
pub const REVOCATION_PREDICATE: &str = "https://loom.dev/attestation/revocation/v1";
pub const DSSE_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    pub name: String,
    pub digest: BTreeMap<String, String>,
}

/// Generic in-toto Statement v1.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Statement<P> {
    #[serde(rename = "_type")]
    pub type_: String,
    pub subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: P,
}

/// Outcome of a rebuild (FR-4.6).
///
/// Each rebuilder builds twice under deliberately varied environments
/// (reprotest-style). If its own builds agree it claims `Reproducible` with
/// that digest; if they disagree it reports `Unreproducible` and makes *no*
/// digest claim. Only `Reproducible` attestations can support or contradict
/// a candidate artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Reproducible,
    Unreproducible,
    BuildFailed,
}

/// Enough about the build environment to decide whether two rebuilders are
/// independent evidence (FR-4.5, FR-6.2, NFR-SEC-4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Toolchain {
    /// Stable identifier = SHA-256 over the canonical form of `image` +
    /// `components`. Two rebuilders with the same id are *correlated*.
    pub id: String,
    /// Declared builder image / distribution snapshot.
    pub image: String,
    /// Tool name -> version (bash, gcc, binutils, coreutils, ...).
    pub components: BTreeMap<String, String>,
    /// Confinement tier the build ran under (`full`, `reduced`, `unconfined-demo`).
    pub sandbox_tier: String,
}

impl Toolchain {
    pub fn new(image: &str, components: BTreeMap<String, String>, sandbox_tier: &str) -> Self {
        #[derive(Serialize)]
        struct IdInput<'a> {
            image: &'a str,
            components: &'a BTreeMap<String, String>,
        }
        let id = Digest::of(
            &crate::canon::to_vec(&IdInput {
                image,
                components: &components,
            })
            .expect("canonical toolchain"),
        );
        Toolchain {
            id: id.short(),
            image: image.to_string(),
            components,
            sandbox_tier: sandbox_tier.to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRef {
    /// Ecosystem-specific repository locator (e.g. AUR git URL).
    pub repo: String,
    /// VCS commit the build was performed from.
    pub commit: String,
    /// Digest over the complete, hash-verified build input set.
    pub digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebuilderRef {
    pub id: String,
    pub org: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observed {
    /// Publishing authority as seen by the rebuilder at build time. Lets a
    /// first-time installer see maintainer history (reduces TOFU exposure).
    pub maintainer: Option<String>,
    pub last_modified: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebuildPredicate {
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub source: SourceRef,
    pub outcome: Outcome,
    /// Present iff outcome == Reproducible.
    pub artifact: Option<Digest>,
    /// Digests of each variant build (diagnostics).
    pub variant_digests: Vec<Digest>,
    pub rebuilder: RebuilderRef,
    pub toolchain: Toolchain,
    pub observed: Observed,
    /// Unix seconds.
    pub timestamp: i64,
    /// Other reproducible digests already logged for the same source that
    /// this rebuilder disagrees with (negative attestation, FR-4.6).
    #[serde(default)]
    pub disputes: Vec<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationPredicate {
    /// Leaf index of the revoked record in the Warp log.
    pub target_index: u64,
    /// SHA-256 of the revoked leaf bytes (binds index to content).
    pub target_leaf: Digest,
    pub reason: String,
    pub revoker: String,
    pub timestamp: i64,
}

pub type RebuildStatement = Statement<RebuildPredicate>;
pub type RevocationStatement = Statement<RevocationPredicate>;

/// A Warp log leaf.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LogRecord {
    Attestation { envelope: Envelope },
    Revocation { envelope: Envelope },
}

impl LogRecord {
    pub fn canonical_bytes(&self) -> anyhow::Result<Vec<u8>> {
        crate::canon::to_vec(self)
    }

    pub fn envelope(&self) -> &Envelope {
        match self {
            LogRecord::Attestation { envelope } | LogRecord::Revocation { envelope } => envelope,
        }
    }

    /// Decode the statement *without* verifying the signature. Callers must
    /// verify with [`Envelope::verify`] against a trusted key before relying
    /// on any field.
    pub fn decode_rebuild_unverified(&self) -> anyhow::Result<RebuildStatement> {
        match self {
            LogRecord::Attestation { envelope } => {
                let st: RebuildStatement = serde_json::from_slice(&envelope.payload_bytes()?)?;
                check_statement(&st.type_, &st.predicate_type, REBUILD_PREDICATE)?;
                Ok(st)
            }
            _ => anyhow::bail!("not an attestation record"),
        }
    }

    pub fn decode_revocation_unverified(&self) -> anyhow::Result<RevocationStatement> {
        match self {
            LogRecord::Revocation { envelope } => {
                let st: RevocationStatement = serde_json::from_slice(&envelope.payload_bytes()?)?;
                check_statement(&st.type_, &st.predicate_type, REVOCATION_PREDICATE)?;
                Ok(st)
            }
            _ => anyhow::bail!("not a revocation record"),
        }
    }
}

fn check_statement(t: &str, pt: &str, want: &str) -> anyhow::Result<()> {
    if t != STATEMENT_TYPE {
        anyhow::bail!("unexpected statement type {t}");
    }
    if pt != want {
        anyhow::bail!("unexpected predicate type {pt}");
    }
    Ok(())
}

pub fn artifact_subject_name(package: &str, version: &str) -> String {
    format!("{package}-{version}.pkg.tar.gz")
}

/// Sign a rebuild predicate into a log record.
pub fn sign_rebuild(pred: RebuildPredicate, key: &SecretKey) -> anyhow::Result<LogRecord> {
    let subject = match &pred.artifact {
        Some(d) => vec![Subject {
            name: artifact_subject_name(&pred.package, &pred.version),
            digest: BTreeMap::from([("sha256".to_string(), d.hex())]),
        }],
        None => vec![],
    };
    let st = Statement {
        type_: STATEMENT_TYPE.into(),
        subject,
        predicate_type: REBUILD_PREDICATE.into(),
        predicate: pred,
    };
    let body = crate::canon::to_vec(&st)?;
    Ok(LogRecord::Attestation {
        envelope: Envelope::sign(DSSE_PAYLOAD_TYPE, &body, key),
    })
}

pub fn sign_revocation(pred: RevocationPredicate, key: &SecretKey) -> anyhow::Result<LogRecord> {
    let st = Statement {
        type_: STATEMENT_TYPE.into(),
        subject: vec![Subject {
            name: format!("warp-leaf-{}", pred.target_index),
            digest: BTreeMap::from([("sha256".to_string(), pred.target_leaf.hex())]),
        }],
        predicate_type: REVOCATION_PREDICATE.into(),
        predicate: pred,
    };
    let body = crate::canon::to_vec(&st)?;
    Ok(LogRecord::Revocation {
        envelope: Envelope::sign(DSSE_PAYLOAD_TYPE, &body, key),
    })
}

/// Verify a rebuild record against a specific rebuilder key and check that
/// the subject matches the predicate.
pub fn verify_rebuild(rec: &LogRecord, key: &PublicKey) -> anyhow::Result<RebuildStatement> {
    let LogRecord::Attestation { envelope } = rec else {
        anyhow::bail!("not an attestation");
    };
    envelope.verify(key)?;
    let st = rec.decode_rebuild_unverified()?;
    match (&st.predicate.outcome, &st.predicate.artifact) {
        (Outcome::Reproducible, Some(d)) => {
            let ok = st
                .subject
                .iter()
                .any(|s| s.digest.get("sha256").map(|h| h == &d.hex()).unwrap_or(false));
            if !ok {
                anyhow::bail!("statement subject does not match predicate artifact digest");
            }
        }
        (Outcome::Reproducible, None) => anyhow::bail!("reproducible outcome without digest"),
        (_, Some(_)) => anyhow::bail!("non-reproducible outcome must not claim a digest"),
        _ => {}
    }
    Ok(st)
}

pub fn verify_revocation(rec: &LogRecord, key: &PublicKey) -> anyhow::Result<RevocationStatement> {
    rec.envelope().verify(key)?;
    rec.decode_revocation_unverified()
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn sample(key_id: &str) -> RebuildPredicate {
        let d = Digest::of(b"artifact");
        RebuildPredicate {
            ecosystem: "aur".into(),
            package: "hello".into(),
            version: "1.0-1".into(),
            source: SourceRef {
                repo: "https://aur.archlinux.org/hello.git".into(),
                commit: "abc".into(),
                digest: Digest::of(b"src"),
            },
            outcome: Outcome::Reproducible,
            artifact: Some(d),
            variant_digests: vec![d, d],
            rebuilder: RebuilderRef {
                id: key_id.into(),
                org: "org".into(),
            },
            toolchain: Toolchain::new("arch", BTreeMap::new(), "full"),
            observed: Observed {
                maintainer: Some("alice".into()),
                last_modified: 1,
            },
            timestamp: 2,
            disputes: vec![],
        }
    }

    #[test]
    fn rebuild_roundtrip() {
        let k = SecretKey::generate();
        let rec = sign_rebuild(sample("a"), &k).unwrap();
        let bytes = rec.canonical_bytes().unwrap();
        let back: LogRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, rec);
        let st = verify_rebuild(&back, &k.public()).unwrap();
        assert_eq!(st.predicate.package, "hello");
        assert!(verify_rebuild(&back, &SecretKey::generate().public()).is_err());
    }

    #[test]
    fn inconsistent_claims_rejected() {
        let k = SecretKey::generate();
        let mut p = sample("a");
        p.outcome = Outcome::Unreproducible;
        let rec = sign_rebuild(p, &k).unwrap();
        assert!(verify_rebuild(&rec, &k.public()).is_err());
    }

    #[test]
    fn toolchain_id_stable() {
        let c = BTreeMap::from([("gcc".to_string(), "14.2".to_string())]);
        let a = Toolchain::new("arch", c.clone(), "full");
        let b = Toolchain::new("arch", c, "reduced");
        assert_eq!(a.id, b.id, "sandbox tier does not change toolchain identity");
    }
}
