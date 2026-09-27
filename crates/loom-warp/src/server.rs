//! The Warp log service.
//!
//! Admission is permissioned (SRS App. C defers permissionless rebuilder
//! admission): a record is accepted only if it is signed by a configured
//! rebuilder or revocation-authority key. Every accepted record triggers a new
//! checkpoint, which is sent to each configured witness together with a
//! consistency proof from the last size that witness cosigned.
//!
//! For evaluation E6 the server can be started in *split-view* mode, in which
//! it maintains a forked history served only to a designated victim client.
//! That mode exists solely to demonstrate that clients detect it.

use crate::notes;
use crate::proof;
use crate::tree::Tree;
use crate::witness::encode_add_checkpoint;
use loom_core::attest::{self, LogRecord};
use loom_core::digest::Digest;
use loom_core::http::{Client, Handler, HttpError, Request, Response};
use loom_core::keys::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Debug, Default)]
pub struct Admission {
    /// Rebuilder id -> key.
    pub rebuilders: BTreeMap<String, PublicKey>,
    /// Revocation authority name -> key.
    pub revokers: BTreeMap<String, PublicKey>,
}

struct View {
    tree: Tree,
    checkpoint: Vec<u8>,
    witness_sizes: BTreeMap<String, u64>,
}

struct Inner {
    main: View,
    fork: Option<(String, View)>,
}

pub struct LogServer {
    pub origin: String,
    key: SecretKey,
    witnesses: Vec<String>,
    admission: Admission,
    data_dir: Option<PathBuf>,
    inner: Mutex<Inner>,
    http: Client,
    split_view_enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddResponse {
    pub index: u64,
    pub size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EntriesResponse {
    pub start: u64,
    pub entries: Vec<String>,
}

impl LogServer {
    pub fn new(
        origin: &str,
        key: SecretKey,
        witnesses: Vec<String>,
        admission: Admission,
        data_dir: Option<PathBuf>,
        split_view_enabled: bool,
    ) -> anyhow::Result<Arc<Self>> {
        let tree = match &data_dir {
            Some(d) => Tree::open(&d.join("entries.jsonl"))?,
            None => Tree::new(),
        };
        let checkpoint = notes::sign_checkpoint(origin, tree.size(), tree.root(), &key)?;
        let s = Arc::new(LogServer {
            origin: origin.to_string(),
            key,
            witnesses,
            admission,
            data_dir,
            inner: Mutex::new(Inner {
                main: View {
                    tree,
                    checkpoint,
                    witness_sizes: BTreeMap::new(),
                },
                fork: None,
            }),
            http: Client::new(Duration::from_secs(5)),
            split_view_enabled,
        });
        // Publish the current state to witnesses (restart / first boot).
        {
            let mut g = s.inner.lock().unwrap();
            s.publish(&mut g.main);
        }
        Ok(s)
    }

    pub fn public(&self) -> PublicKey {
        self.key.public()
    }

    pub fn vkey(&self) -> String {
        notes::vkey(&self.origin, &self.key.public())
    }

    /// Validate a submission against the admission policy.
    fn validate(&self, rec: &LogRecord, tree: &Tree) -> anyhow::Result<()> {
        match rec {
            LogRecord::Attestation { envelope } => {
                let claimed = envelope.claimed_keyids();
                let (id, key) = self
                    .admission
                    .rebuilders
                    .iter()
                    .find(|(_, k)| claimed.contains(&k.key_id()))
                    .ok_or_else(|| anyhow::anyhow!("attestation not signed by an admitted rebuilder"))?;
                let st = attest::verify_rebuild(rec, key)?;
                if &st.predicate.rebuilder.id != id {
                    anyhow::bail!(
                        "attestation claims rebuilder {:?} but is signed by {:?}",
                        st.predicate.rebuilder.id,
                        id
                    );
                }
            }
            LogRecord::Revocation { envelope } => {
                let claimed = envelope.claimed_keyids();
                let rev = self
                    .admission
                    .revokers
                    .values()
                    .chain(self.admission.rebuilders.values())
                    .find(|k| claimed.contains(&k.key_id()))
                    .ok_or_else(|| anyhow::anyhow!("revocation not signed by an admitted key"))?;
                let st = attest::verify_revocation(rec, rev)?;
                let p = &st.predicate;
                let target = tree
                    .leaf(p.target_index)
                    .ok_or_else(|| anyhow::anyhow!("revocation target {} not in log", p.target_index))?;
                if Digest::of(target) != p.target_leaf {
                    anyhow::bail!("revocation target digest does not match leaf {}", p.target_index);
                }
                let is_authority = self.admission.revokers.values().any(|k| k == rev);
                if !is_authority {
                    // A rebuilder may only revoke its own attestations.
                    let trec: LogRecord = serde_json::from_slice(target)?;
                    if trec.envelope().verify(rev).is_err() {
                        anyhow::bail!("rebuilders may only revoke their own attestations");
                    }
                }
            }
        }
        Ok(())
    }

    pub fn add(&self, rec: &LogRecord, to_fork: bool) -> anyhow::Result<AddResponse> {
        let leaf = rec.canonical_bytes()?;
        let mut g = self.inner.lock().unwrap();
        let view = if to_fork {
            &mut g
                .fork
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("no fork"))?
                .1
        } else {
            &mut g.main
        };
        self.validate(rec, &view.tree)?;
        let index = view.tree.append(leaf)?;
        self.publish(view);
        Ok(AddResponse {
            index,
            size: view.tree.size(),
        })
    }

    /// Sign a new checkpoint and gather witness cosignatures.
    fn publish(&self, view: &mut View) {
        let size = view.tree.size();
        let root = view.tree.root();
        let note = match notes::sign_checkpoint(&self.origin, size, root, &self.key) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("warp: signing checkpoint failed: {e}");
                return;
            }
        };
        let mut full = note.clone();
        for url in &self.witnesses {
            let mut old = *view.witness_sizes.get(url).unwrap_or(&0);
            for _attempt in 0..2 {
                let prf = match view.tree.prove_consistency(old.min(size), size) {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let body = encode_add_checkpoint(old, &prf, &note);
                match self
                    .http
                    .post(&format!("{url}/add-checkpoint"), "text/plain", &body)
                {
                    Ok(line) => {
                        if let Ok(n) = notes::add_signature_lines(&full, &line) {
                            full = n;
                        }
                        view.witness_sizes.insert(url.clone(), size);
                        break;
                    }
                    Err(HttpError::Status { status: 409, body }) => {
                        old = body.trim().parse().unwrap_or(0);
                        if old > size {
                            eprintln!("warp: witness {url} is ahead of this log ({old} > {size})");
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("warp: witness {url} refused/unreachable: {e}");
                        break;
                    }
                }
            }
        }
        view.checkpoint = full;
        if let Some(d) = &self.data_dir {
            let _ = std::fs::write(d.join("checkpoint"), &view.checkpoint);
        }
    }

    fn view_for<'a>(&self, g: &'a Inner, r: &Request) -> &'a View {
        if let (Some((victim, fork)), Some(client)) = (&g.fork, r.header("x-loom-client")) {
            if client == victim {
                return fork;
            }
        }
        &g.main
    }

    pub fn checkpoint(&self) -> Vec<u8> {
        self.inner.lock().unwrap().main.checkpoint.clone()
    }

    pub fn size(&self) -> u64 {
        self.inner.lock().unwrap().main.tree.size()
    }

    /// Split-view attack (evaluation only): snapshot the current history as a
    /// fork that will be served to `victim`.
    pub fn start_fork(&self, victim: &str) -> anyhow::Result<()> {
        if !self.split_view_enabled {
            anyhow::bail!("split-view mode not enabled");
        }
        let mut g = self.inner.lock().unwrap();
        let fork = View {
            tree: {
                let mut t = Tree::new();
                for l in g.main.tree.leaves(0, g.main.tree.size()) {
                    t.append(l.clone())?;
                }
                t
            },
            checkpoint: g.main.checkpoint.clone(),
            witness_sizes: g.main.witness_sizes.clone(),
        };
        g.fork = Some((victim.to_string(), fork));
        Ok(())
    }

    pub fn handler(self: Arc<Self>) -> Handler {
        Arc::new(move |r: &Request| self.handle(r))
    }

    fn handle(&self, r: &Request) -> Response {
        match (r.method.as_str(), r.path.as_str()) {
            ("GET", "/checkpoint") => {
                let g = self.inner.lock().unwrap();
                Response::bytes(200, "text/plain; charset=utf-8", self.view_for(&g, r).checkpoint.clone())
            }
            ("POST", "/add") => {
                let rec: LogRecord = match serde_json::from_slice(&r.body) {
                    Ok(x) => x,
                    Err(e) => return Response::text(400, format!("bad record: {e}")),
                };
                let to_fork = r.q("fork") == Some("1") && self.split_view_enabled;
                match self.add(&rec, to_fork) {
                    Ok(a) => Response::json(&a),
                    Err(e) => Response::text(403, e.to_string()),
                }
            }
            ("GET", "/entries") => {
                let g = self.inner.lock().unwrap();
                let v = self.view_for(&g, r);
                let start = r.q_u64("start").unwrap_or(0);
                let end = r.q_u64("end").unwrap_or(v.tree.size()).min(start + 1000);
                let entries = v
                    .tree
                    .leaves(start, end)
                    .iter()
                    .map(|l| String::from_utf8_lossy(l).into_owned())
                    .collect();
                Response::json(&EntriesResponse { start, entries })
            }
            ("GET", "/proof/inclusion") => {
                let (index, size) = match (r.q_u64("index"), r.q_u64("size")) {
                    (Ok(i), Ok(s)) => (i, s),
                    (Err(e), _) | (_, Err(e)) => return e,
                };
                let g = self.inner.lock().unwrap();
                match self.view_for(&g, r).tree.prove_inclusion(index, size) {
                    Ok(p) => Response::text(200, proof::encode(&p)),
                    Err(e) => Response::text(400, e.to_string()),
                }
            }
            ("GET", "/proof/consistency") => {
                let (old, new) = match (r.q_u64("old"), r.q_u64("new")) {
                    (Ok(a), Ok(b)) => (a, b),
                    (Err(e), _) | (_, Err(e)) => return e,
                };
                let g = self.inner.lock().unwrap();
                match self.view_for(&g, r).tree.prove_consistency(old, new) {
                    Ok(p) => Response::text(200, proof::encode(&p)),
                    Err(e) => Response::text(400, e.to_string()),
                }
            }
            ("POST", "/admin/fork") => match self.start_fork(r.q("victim").unwrap_or("victim")) {
                Ok(()) => Response::text(200, "forked\n"),
                Err(e) => Response::text(403, e.to_string()),
            },
            ("GET", "/info") => Response::json(&serde_json::json!({
                "origin": self.origin,
                "vkey": self.vkey(),
                "size": self.size(),
            })),
            _ => Response::not_found(),
        }
    }
}
