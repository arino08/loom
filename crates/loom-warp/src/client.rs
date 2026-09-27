//! Client-side log verification.
//!
//! [`LogClient::update`] performs, in order:
//!
//! 1. fetch the latest checkpoint (log first, then peers — FR-2.5, NFR-REL-2);
//! 2. verify the log's signature on it;
//! 3. verify cosignatures from at least `threshold` configured witnesses (FR-5.6);
//! 4. verify consistency with the last checkpoint this client accepted,
//!    refusing on any inconsistency or rollback (FR-5.7);
//! 5. cross-check against each witness's own latest cosigned checkpoint and
//!    record *proof of misbehaviour* (two log-signed, mutually inconsistent
//!    checkpoints) if the log is presenting a split view (NFR-SEC-5);
//! 6. mirror every log record and recompute the Merkle root locally, so the
//!    log cannot hide records — in particular revocations — from this client;
//! 7. persist the new checkpoint (skipped in read-only audit mode, FR-10.2).
//!
//! Inclusion proofs for the records a decision relies on are verified
//! separately via [`LogView::verify_inclusion`] (FR-5.5).

use crate::notes::{self, Cosig, SignedCheckpoint};
use crate::proof;
use crate::server::EntriesResponse;
use crate::tree::{verify_consistency, verify_inclusion, Tree};
use loom_core::attest::LogRecord;
use loom_core::http::{Client, HttpError};
use loom_core::keys::PublicKey;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

/// Where a client keeps its verified mirror and checkpoint for `origin`.
pub fn mirror_dir(state_dir: &std::path::Path, origin: &str) -> PathBuf {
    let tag = loom_core::Digest::of(origin.as_bytes()).short();
    state_dir.join("warp").join(tag)
}

#[derive(Clone, Debug)]
pub struct TrustedLog {
    pub origin: String,
    pub key: PublicKey,
    pub url: String,
}

#[derive(Clone, Debug)]
pub struct TrustedWitness {
    pub name: String,
    pub key: PublicKey,
    pub url: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub log: TrustedLog,
    pub witnesses: Vec<TrustedWitness>,
    pub threshold: usize,
    pub state_dir: PathBuf,
    /// Peers that gossip checkpoints and log entries (untrusted transport).
    pub peers: Vec<String>,
    /// Sent as `X-Loom-Client` (only meaningful against the E6 test log).
    pub client_id: Option<String>,
    pub read_only: bool,
}

#[derive(Clone, Debug)]
pub struct SplitViewEvidence {
    pub detail: String,
    pub ours: String,
    pub theirs: String,
    pub via: String,
    pub saved_to: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    /// The log (and every gossip peer) is unreachable. Policy decides what
    /// to do (NFR-REL-2).
    #[error("transparency log unavailable: {0}")]
    Unavailable(String),
    /// Something failed verification. Always fail closed (NFR-SEC-1).
    #[error("transparency log verification failed: {0}")]
    Invalid(String),
    #[error("SPLIT VIEW DETECTED: {}", .0.detail)]
    SplitView(Box<SplitViewEvidence>),
}

pub struct LogView {
    pub checkpoint: SignedCheckpoint,
    pub cosigs: Vec<Cosig>,
    pub witness_problems: Vec<String>,
    pub previous_size: Option<u64>,
    /// Witnesses whose own view was cross-checked and found consistent.
    pub cross_checked: Vec<String>,
    pub fetched_from: String,
    pub records: Vec<(u64, LogRecord)>,
    pub notes: Vec<String>,
    tree: Tree,
    client: LogClient,
}

#[derive(Clone)]
pub struct LogClient {
    pub cfg: ClientConfig,
    http: Client,
}

impl LogClient {
    pub fn new(cfg: ClientConfig) -> Self {
        let mut http = Client::new(Duration::from_secs(5));
        if let Some(id) = &cfg.client_id {
            http = http.with_header("X-Loom-Client", id);
        }
        LogClient { cfg, http }
    }

    fn dir(&self) -> PathBuf {
        mirror_dir(&self.cfg.state_dir, &self.cfg.log.origin)
    }

    fn witness_keys(&self) -> Vec<(String, PublicKey)> {
        self.cfg
            .witnesses
            .iter()
            .map(|w| (w.name.clone(), w.key.clone()))
            .collect()
    }

    fn get(&self, url: &str) -> Result<Vec<u8>, HttpError> {
        self.http.get(url)
    }

    /// Fetch a checkpoint from the log, falling back to gossip peers.
    fn fetch_checkpoint(&self) -> Result<(Vec<u8>, String), LogError> {
        let mut errs = vec![];
        match self.get(&format!("{}/checkpoint", self.cfg.log.url)) {
            Ok(b) => return Ok((b, self.cfg.log.url.clone())),
            Err(e) => errs.push(format!("{}: {e}", self.cfg.log.url)),
        }
        for p in &self.cfg.peers {
            let url = format!("{p}/gossip/checkpoint?origin={}", self.cfg.log.origin);
            match self.get(&url) {
                Ok(b) => return Ok((b, p.clone())),
                Err(e) => errs.push(format!("{p}: {e}")),
            }
        }
        Err(LogError::Unavailable(errs.join("; ")))
    }

    fn fetch_entries(&self, source: &str, start: u64, end: u64) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut out = vec![];
        let mut cur = start;
        let bases: Vec<String> = std::iter::once(source.to_string())
            .chain(std::iter::once(self.cfg.log.url.clone()))
            .chain(self.cfg.peers.iter().cloned())
            .collect();
        'outer: while cur < end {
            for b in &bases {
                let url = if b == &self.cfg.log.url {
                    format!("{b}/entries?start={cur}&end={end}")
                } else {
                    format!(
                        "{b}/gossip/entries?origin={}&start={cur}&end={end}",
                        self.cfg.log.origin
                    )
                };
                if let Ok(body) = self.get(&url) {
                    if let Ok(er) = serde_json::from_slice::<EntriesResponse>(&body) {
                        if er.start == cur && !er.entries.is_empty() {
                            for e in er.entries {
                                if cur >= end {
                                    break;
                                }
                                out.push(e.into_bytes());
                                cur += 1;
                            }
                            continue 'outer;
                        }
                    }
                }
            }
            anyhow::bail!("could not fetch log entries from index {cur}");
        }
        Ok(out)
    }

    fn consistency_proof(&self, old: u64, new: u64) -> Result<Vec<crate::Hash>, HttpError> {
        let b = self.get(&format!(
            "{}/proof/consistency?old={old}&new={new}",
            self.cfg.log.url
        ))?;
        proof::decode(&String::from_utf8_lossy(&b)).map_err(|e| HttpError::Status {
            status: 0,
            body: e.to_string(),
        })
    }

    fn save_evidence(&self, ev: &mut SplitViewEvidence) {
        if self.cfg.read_only {
            return;
        }
        let dir = self.dir().join("evidence");
        if std::fs::create_dir_all(&dir).is_ok() {
            let p = dir.join(format!("split-view-{}.txt", loom_core::time::now()));
            let body = format!(
                "# Loom split-view evidence\n# {}\n# via {}\n\n## checkpoint A (ours)\n{}\n## checkpoint B\n{}",
                ev.detail, ev.via, ev.ours, ev.theirs
            );
            if std::fs::write(&p, body).is_ok() {
                ev.saved_to = Some(p);
            }
        }
    }

    fn split(&self, detail: String, ours: &[u8], theirs: &[u8], via: &str) -> LogError {
        let mut ev = SplitViewEvidence {
            detail,
            ours: String::from_utf8_lossy(ours).into_owned(),
            theirs: String::from_utf8_lossy(theirs).into_owned(),
            via: via.to_string(),
            saved_to: None,
        };
        self.save_evidence(&mut ev);
        LogError::SplitView(Box::new(ev))
    }

    /// Check two log-signed checkpoints for mutual consistency.
    fn check_pair(
        &self,
        a: &SignedCheckpoint,
        b: &SignedCheckpoint,
        via: &str,
    ) -> Result<bool, LogError> {
        if a.size == b.size {
            if a.root != b.root {
                return Err(self.split(
                    format!("two signed checkpoints for size {} with different roots", a.size),
                    &a.note,
                    &b.note,
                    via,
                ));
            }
            return Ok(true);
        }
        let (small, big) = if a.size < b.size { (a, b) } else { (b, a) };
        match self.consistency_proof(small.size, big.size) {
            Ok(p) => match verify_consistency(&p, small.size, small.root, big.size, big.root) {
                Ok(()) => Ok(true),
                Err(e) => Err(self.split(
                    format!(
                        "log cannot prove size {} is a prefix of size {} ({e})",
                        small.size, big.size
                    ),
                    &a.note,
                    &b.note,
                    via,
                )),
            },
            Err(HttpError::Unavailable(_)) => Ok(false),
            Err(e) => Err(self.split(
                format!("log refused a consistency proof {}→{}: {e}", small.size, big.size),
                &a.note,
                &b.note,
                via,
            )),
        }
    }

    pub fn update(&self) -> Result<LogView, LogError> {
        let log = &self.cfg.log;
        let (note, fetched_from) = self.fetch_checkpoint()?;
        let cp = notes::open_checkpoint(&note, &log.origin, &log.key)
            .map_err(|e| LogError::Invalid(format!("checkpoint from {fetched_from}: {e}")))?;

        // FR-5.6: witness threshold.
        let (cosigs, witness_problems) = notes::verify_cosignatures(&note, &self.witness_keys());
        if cosigs.len() < self.cfg.threshold {
            return Err(LogError::Invalid(format!(
                "checkpoint (size {}) carries {} valid witness cosignature(s) [{}]; policy requires {} of {} configured witnesses. \
                 Honest witnesses refuse to cosign histories inconsistent with what they have seen, so this may indicate a split view.",
                cp.size,
                cosigs.len(),
                cosigs.iter().map(|c| c.witness.as_str()).collect::<Vec<_>>().join(", "),
                self.cfg.threshold,
                self.cfg.witnesses.len()
            )));
        }

        let dir = self.dir();
        let mut notes_out = vec![];
        let mut cp = cp;

        // FR-5.7: consistency with the persisted checkpoint.
        let persisted_path = dir.join("checkpoint");
        let previous = match std::fs::read(&persisted_path) {
            Ok(b) => Some(
                notes::open_checkpoint(&b, &log.origin, &log.key)
                    .map_err(|e| LogError::Invalid(format!("persisted checkpoint unreadable: {e}")))?,
            ),
            Err(_) => None,
        };
        if let Some(prev) = &previous {
            if cp.size < prev.size {
                // Served an older head: must still be consistent; keep ours.
                if !self.check_pair(prev, &cp, &fetched_from)? {
                    notes_out.push("stale checkpoint could not be cross-checked (log offline)".into());
                }
                notes_out.push(format!(
                    "{fetched_from} served an older checkpoint (size {} < {}); using persisted head",
                    cp.size, prev.size
                ));
                cp = prev.clone();
            } else if !self.check_pair(prev, &cp, &fetched_from)? {
                notes_out.push("consistency proof unavailable; relying on local mirror recomputation".into());
            }
        }

        // NFR-SEC-5: cross-check each witness's own view.
        let mut cross_checked = vec![];
        for w in &self.cfg.witnesses {
            let Some(url) = &w.url else { continue };
            let Ok(body) = self.get(&format!("{url}/latest?origin={}", log.origin)) else {
                continue;
            };
            let Ok(theirs) = notes::open_checkpoint(&body, &log.origin, &log.key) else {
                continue;
            };
            let (ok, _) = notes::verify_cosignatures(&body, &[(w.name.clone(), w.key.clone())]);
            if ok.is_empty() {
                continue;
            }
            if self.check_pair(&cp, &theirs, &format!("witness {}", w.name))? {
                cross_checked.push(w.name.clone());
            }
        }

        // Mirror all entries and recompute the root.
        let mirror_path = dir.join("entries.jsonl");
        let mut tree = Tree::new();
        if let Ok(f) = std::fs::read(&mirror_path) {
            for line in f.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
                tree.append(line.to_vec())
                    .map_err(|e| LogError::Invalid(format!("local mirror corrupt: {e}")))?;
            }
        }
        if tree.size() > cp.size {
            return Err(LogError::Invalid(format!(
                "local mirror has {} records but checkpoint only {}",
                tree.size(),
                cp.size
            )));
        }
        let have = tree.size();
        if cp.size > have {
            let new = self
                .fetch_entries(&fetched_from, have, cp.size)
                .map_err(|e| LogError::Unavailable(e.to_string()))?;
            for leaf in &new {
                tree.append(leaf.clone())
                    .map_err(|e| LogError::Invalid(e.to_string()))?;
            }
            if tree.root() != cp.root {
                return Err(LogError::Invalid(format!(
                    "records served for size {} do not hash to the cosigned root — the log is serving inconsistent data",
                    cp.size
                )));
            }
            if !self.cfg.read_only {
                std::fs::create_dir_all(&dir).map_err(|e| LogError::Invalid(e.to_string()))?;
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&mirror_path)
                    .map_err(|e| LogError::Invalid(e.to_string()))?;
                for leaf in &new {
                    f.write_all(leaf).and_then(|_| f.write_all(b"\n"))
                        .map_err(|e| LogError::Invalid(e.to_string()))?;
                }
            }
        } else if tree.root() != cp.root {
            return Err(LogError::Invalid("local mirror does not match checkpoint root".into()));
        }
        if let Some(prev) = &previous {
            if tree.root_at(prev.size).ok() != Some(prev.root) {
                return Err(self.split(
                    "log history no longer contains the previously accepted tree".into(),
                    &prev.note,
                    &cp.note,
                    &fetched_from,
                ));
            }
        }

        let mut records = vec![];
        for i in 0..tree.size() {
            match serde_json::from_slice::<LogRecord>(tree.leaf(i).unwrap()) {
                Ok(r) => records.push((i, r)),
                Err(e) => notes_out.push(format!("record {i} unparseable: {e}")),
            }
        }

        if !self.cfg.read_only {
            let _ = std::fs::create_dir_all(&dir);
            let tmp = dir.join("checkpoint.tmp");
            if std::fs::write(&tmp, &cp.note).is_ok() {
                let _ = std::fs::rename(&tmp, &persisted_path);
            }
        }

        Ok(LogView {
            previous_size: previous.map(|p| p.size),
            checkpoint: cp,
            cosigs,
            witness_problems,
            cross_checked,
            fetched_from,
            records,
            notes: notes_out,
            tree,
            client: self.clone(),
        })
    }
}

/// How an inclusion proof was obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InclusionSource {
    Log,
    LocalMirror,
}

impl LogView {
    pub fn leaf(&self, index: u64) -> Option<&[u8]> {
        self.tree.leaf(index)
    }

    /// Verify that record `index` is included under the cosigned root (FR-5.5).
    /// Uses a proof served by the log when reachable, else one computed from
    /// the locally verified mirror; both are checked against the same root.
    pub fn verify_inclusion(&self, index: u64) -> anyhow::Result<InclusionSource> {
        let leaf = self
            .tree
            .leaf(index)
            .ok_or_else(|| anyhow::anyhow!("record {index} not in mirror"))?;
        let size = self.checkpoint.size;
        let url = format!(
            "{}/proof/inclusion?index={index}&size={size}",
            self.client.cfg.log.url
        );
        match self.client.get(&url) {
            Ok(b) => {
                let p = proof::decode(&String::from_utf8_lossy(&b))?;
                verify_inclusion(&p, size, self.checkpoint.root, index, leaf)?;
                Ok(InclusionSource::Log)
            }
            Err(HttpError::Unavailable(_)) => {
                let p = self.tree.prove_inclusion(index, size)?;
                verify_inclusion(&p, size, self.checkpoint.root, index, leaf)?;
                Ok(InclusionSource::LocalMirror)
            }
            Err(e) => anyhow::bail!("log refused inclusion proof for {index}: {e}"),
        }
    }

    /// Serve-able gossip: raw entries in a range.
    pub fn entries(&self, start: u64, end: u64) -> Vec<String> {
        self.tree
            .leaves(start, end)
            .iter()
            .map(|l| String::from_utf8_lossy(l).into_owned())
            .collect()
    }
}
