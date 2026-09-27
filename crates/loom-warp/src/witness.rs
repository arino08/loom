//! A transparency-log witness (c2sp.org/tlog-witness).
//!
//! The witness remembers, per log origin, the last checkpoint it cosigned.
//! It cosigns a new checkpoint only if the log proves the new tree extends
//! the old one. An honest witness therefore cosigns at most one linear
//! history: to obtain two diverging cosigned views, a log operator must
//! corrupt witnesses (ADV-9, NFR-SEC-5).

use crate::notes;
use crate::proof;
use crate::tree::verify_consistency;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use loom_core::http::{Handler, Request, Response};
use loom_core::keys::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LogState {
    size: u64,
    root: String,
    /// Latest checkpoint note we cosigned, including our cosignature.
    note: String,
}

pub struct Witness {
    pub name: String,
    key: SecretKey,
    logs: BTreeMap<String, PublicKey>,
    state_path: Option<PathBuf>,
    state: Mutex<BTreeMap<String, LogState>>,
    /// Test/evaluation only: a corrupt witness that cosigns anything with a
    /// valid log signature (models ADV-8/ADV-9 collusion).
    evil: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    #[error("unknown log")]
    UnknownLog,
    #[error("log signature invalid: {0}")]
    BadSignature(String),
    #[error("old size mismatch: witness is at {0}")]
    Conflict(u64),
    #[error("consistency proof invalid: {0}")]
    BadProof(String),
    #[error("bad request: {0}")]
    Bad(String),
}

impl Witness {
    pub fn new(
        name: &str,
        key: SecretKey,
        logs: BTreeMap<String, PublicKey>,
        state_path: Option<PathBuf>,
        evil: bool,
    ) -> anyhow::Result<Self> {
        let state = match &state_path {
            Some(p) if p.exists() => serde_json::from_slice(&std::fs::read(p)?)?,
            _ => BTreeMap::new(),
        };
        Ok(Witness {
            name: name.to_string(),
            key,
            logs,
            state_path,
            state: Mutex::new(state),
            evil,
        })
    }

    pub fn public(&self) -> PublicKey {
        self.key.public()
    }

    fn persist(&self, st: &BTreeMap<String, LogState>) -> anyhow::Result<()> {
        if let Some(p) = &self.state_path {
            if let Some(d) = p.parent() {
                std::fs::create_dir_all(d)?;
            }
            let tmp = p.with_extension("tmp");
            std::fs::write(&tmp, serde_json::to_vec_pretty(st)?)?;
            std::fs::rename(tmp, p)?;
        }
        Ok(())
    }

    /// Process an add-checkpoint request. Returns the cosignature line.
    pub fn add_checkpoint(
        &self,
        old_size: u64,
        consistency: &[crate::Hash],
        note: &[u8],
    ) -> Result<Vec<u8>, WitnessError> {
        let text = notes::note_text(note).map_err(|e| WitnessError::Bad(e.to_string()))?;
        let origin = String::from_utf8_lossy(&text)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string();
        let log_key = self.logs.get(&origin).ok_or(WitnessError::UnknownLog)?;
        let cp = notes::open_checkpoint(note, &origin, log_key)
            .map_err(|e| WitnessError::BadSignature(e.to_string()))?;

        let mut st = self.state.lock().unwrap();
        if !self.evil {
            let (cur_size, cur_root) = match st.get(&origin) {
                Some(s) => (s.size, proof::hash_from_b64(&s.root).map_err(|e| WitnessError::Bad(e.to_string()))?),
                None => (0, tlog_tiles::tlog::EMPTY_HASH),
            };
            if old_size != cur_size {
                return Err(WitnessError::Conflict(cur_size));
            }
            if cp.size < old_size {
                return Err(WitnessError::Bad("checkpoint smaller than old size".into()));
            }
            verify_consistency(consistency, old_size, cur_root, cp.size, cp.root)
                .map_err(|e| WitnessError::BadProof(e.to_string()))?;
        }

        let ts = loom_core::time::now().max(0) as u64;
        let line = notes::cosign(note, &self.name, &self.key, ts)
            .map_err(|e| WitnessError::Bad(e.to_string()))?;
        // Remember the log-signed note together with our cosignature.
        let base = strip_to_log_signature(note, &origin);
        let with_ours = notes::add_signature_lines(&base, &line).unwrap_or(base);
        let advance = st.get(&origin).map(|s| cp.size >= s.size).unwrap_or(true);
        if advance {
            st.insert(
                origin,
                LogState {
                    size: cp.size,
                    root: cp.root_b64(),
                    note: B64.encode(&with_ours),
                },
            );
            self.persist(&st).map_err(|e| WitnessError::Bad(e.to_string()))?;
        }
        Ok(line)
    }

    /// The latest checkpoint this witness cosigned for `origin`.
    pub fn latest(&self, origin: &str) -> Option<Vec<u8>> {
        let st = self.state.lock().unwrap();
        st.get(origin).and_then(|s| B64.decode(&s.note).ok())
    }

    pub fn handler(self: Arc<Self>) -> Handler {
        Arc::new(move |r: &Request| self.handle(r))
    }

    fn handle(&self, r: &Request) -> Response {
        match (r.method.as_str(), r.path.as_str()) {
            ("POST", "/add-checkpoint") => {
                let (old, prf, note) = match parse_add_checkpoint(&r.body) {
                    Ok(x) => x,
                    Err(e) => return Response::text(400, e.to_string()),
                };
                match self.add_checkpoint(old, &prf, &note) {
                    Ok(line) => Response::bytes(200, "text/plain; charset=utf-8", line),
                    Err(WitnessError::Conflict(sz)) => {
                        Response::bytes(409, "text/x.tlog.size", format!("{sz}\n").into_bytes())
                    }
                    Err(e @ WitnessError::UnknownLog) => Response::text(404, e.to_string()),
                    Err(e @ WitnessError::BadSignature(_)) => Response::text(403, e.to_string()),
                    Err(e @ WitnessError::BadProof(_)) => Response::text(422, e.to_string()),
                    Err(e) => Response::text(400, e.to_string()),
                }
            }
            ("GET", "/latest") => match r.q("origin").and_then(|o| self.latest(o)) {
                Some(n) => Response::bytes(200, "text/plain; charset=utf-8", n),
                None => Response::not_found(),
            },
            ("GET", "/info") => Response::json(&serde_json::json!({
                "name": self.name,
                "key": self.key.public().to_b64(),
                "logs": self.logs.keys().collect::<Vec<_>>(),
            })),
            _ => Response::not_found(),
        }
    }
}

/// Keep only the log's own signature line(s) on a note, dropping other
/// cosignatures (a witness vouches only for itself).
fn strip_to_log_signature(note: &[u8], origin: &str) -> Vec<u8> {
    let s = String::from_utf8_lossy(note);
    let mut out = String::new();
    let mut in_sigs = false;
    for line in s.split_inclusive('\n') {
        if !in_sigs {
            out.push_str(line);
            if line == "\n" {
                in_sigs = true;
            }
            continue;
        }
        if line.starts_with(&format!("— {origin} ")) {
            out.push_str(line);
        }
    }
    out.into_bytes()
}

/// Request body: `old <size>\n<proof lines>\n\n<note>`.
pub fn encode_add_checkpoint(old: u64, consistency: &[crate::Hash], note: &[u8]) -> Vec<u8> {
    let mut b = format!("old {old}\n").into_bytes();
    b.extend(proof::encode(consistency).into_bytes());
    b.push(b'\n');
    b.extend_from_slice(note);
    b
}

pub fn parse_add_checkpoint(body: &[u8]) -> anyhow::Result<(u64, Vec<crate::Hash>, Vec<u8>)> {
    let s = std::str::from_utf8(body)?;
    let (head, note) = s
        .split_once("\n\n")
        .ok_or_else(|| anyhow::anyhow!("missing blank line"))?;
    let mut lines = head.lines();
    let old: u64 = lines
        .next()
        .and_then(|l| l.strip_prefix("old "))
        .ok_or_else(|| anyhow::anyhow!("missing old line"))?
        .parse()?;
    let rest: Vec<&str> = lines.collect();
    let prf = proof::decode(&rest.join("\n"))?;
    Ok((old, prf, note.as_bytes().to_vec()))
}
