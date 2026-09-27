//! Live dashboard and snapshot report for the demo deployment.
//!
//! `loom-testbed dashboard` serves a single page that polls `/api/state`,
//! an aggregate of every service in the deployment (Warp, witnesses,
//! Shuttle peers, the mock AUR) plus the event journal written by `loom`,
//! `loomd` and `demo/run.sh` (see `loom_core::journal`).
//! `loom-testbed report` freezes the same page with the state embedded, so
//! a finished run can be viewed and shared without the services.
//!
//! The dashboard decodes log entries WITHOUT verifying them: it is a
//! display for the operator of the demo, not a client. Clients (`loom`)
//! verify every checkpoint, cosignature and inclusion proof themselves.

use crate::mockaur::Scenario;
use loom_core::attest::LogRecord;
use loom_core::http::{Client, Handler, Request, Response};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// The page body (title, styles, markup, script). It is a fragment so it can
/// also be published as-is by hosts that supply their own document shell.
const PAGE: &str = include_str!("dashboard.html");
const SHELL_HEAD: &str = "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1, viewport-fit=cover\">\n</head>\n<body>\n";
const SHELL_TAIL: &str = "\n</body>\n</html>\n";

fn full_page(body: &str) -> String {
    format!("{SHELL_HEAD}{body}{SHELL_TAIL}")
}
/// The split-view victim's client id in demo/run.sh.
const VICTIM: &str = "victim";

pub struct Dashboard {
    home: PathBuf,
    events: PathBuf,
}

/// A parsed signed-note checkpoint: origin, size, root and the names on
/// its signature lines (the log's own and each cosigner's).
fn parse_checkpoint(note: &str) -> Value {
    let (body, sigs) = note.split_once("\n\n").unwrap_or((note, ""));
    let mut lines = body.lines();
    let origin = lines.next().unwrap_or_default();
    let size: u64 = lines.next().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
    let root = lines.next().unwrap_or_default();
    let signers: Vec<String> = sigs
        .lines()
        .filter_map(|l| l.strip_prefix("— "))
        .filter_map(|l| l.split_whitespace().next())
        .filter(|n| *n != origin)
        .map(str::to_string)
        .collect();
    json!({"origin": origin, "size": size, "root": root, "cosigners": signers})
}

fn entry_summary(index: u64, raw: &str) -> Value {
    let Ok(rec) = serde_json::from_str::<LogRecord>(raw) else {
        return json!({"index": index, "kind": "unparsable"});
    };
    match &rec {
        LogRecord::Attestation { .. } => match rec.decode_rebuild_unverified() {
            Ok(st) => {
                let p = st.predicate;
                json!({
                    "index": index,
                    "kind": "attestation",
                    "rebuilder": p.rebuilder.id,
                    "org": p.rebuilder.org,
                    "package": p.package,
                    "version": p.version,
                    "outcome": format!("{:?}", p.outcome).to_lowercase(),
                    "artifact": p.artifact.map(|d| d.short()),
                    "commit": p.source.commit.get(..12).unwrap_or(&p.source.commit),
                    "maintainer": p.observed.maintainer,
                    "tier": p.toolchain.sandbox_tier,
                    "ts": p.timestamp,
                })
            }
            Err(_) => json!({"index": index, "kind": "attestation"}),
        },
        LogRecord::Revocation { .. } => match rec.decode_revocation_unverified() {
            Ok(st) => json!({
                "index": index, "kind": "revocation", "target": st.predicate.target_index,
                "reason": st.predicate.reason, "revoker": st.predicate.revoker, "ts": st.predicate.timestamp,
            }),
            Err(_) => json!({"index": index, "kind": "revocation"}),
        },
    }
}

impl Dashboard {
    pub fn new(home: &Path) -> Arc<Self> {
        let events = std::env::var_os("LOOM_EVENTS")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("events.jsonl"));
        Arc::new(Dashboard { home: home.to_path_buf(), events })
    }

    fn endpoints(&self) -> Value {
        std::fs::read(self.home.join("endpoints.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null)
    }

    fn read_json(&self, rel: &str) -> Value {
        std::fs::read(self.home.join(rel))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null)
    }

    fn entries(&self, http: &Client, log: &str, size: u64) -> Vec<Value> {
        let mut out = vec![];
        let mut start = 0;
        while start < size {
            let Ok(body) = http.get(&format!("{log}/entries?start={start}&end={size}")) else { break };
            let Ok(er) = serde_json::from_slice::<loom_warp::server::EntriesResponse>(&body) else { break };
            if er.entries.is_empty() {
                break;
            }
            for (i, e) in er.entries.iter().enumerate() {
                out.push(entry_summary(er.start + i as u64, e));
            }
            start = er.start + er.entries.len() as u64;
        }
        out
    }

    /// Aggregate the whole deployment. Every probe has a short timeout and
    /// a down service is reported, never fatal.
    pub fn state(&self, live: bool) -> Value {
        let ep = self.endpoints();
        let host = ep["host"].as_str().unwrap_or("127.0.0.1").to_string();
        let url = |p: &Value| format!("http://{host}:{}", p.as_u64().unwrap_or(0));
        let http = Client::new(Duration::from_millis(800));
        let origin = ep["origin"].as_str().unwrap_or("demo.loom/warp").to_string();
        let mut services = vec![];

        // ---- AUR
        let aur_url = url(&ep["aur"]);
        services.push(json!({"id": "aur", "kind": "aur", "label": "mock AUR", "url": aur_url, "up": http.get(&format!("{aur_url}/packages.gz")).is_ok()}));

        // ---- Warp: the public view, and the victim's view if it differs
        let warp = url(&ep["warp"]);
        let (log, fork) = match http.get(&format!("{warp}/checkpoint")) {
            Ok(b) => {
                let mut cp = parse_checkpoint(&String::from_utf8_lossy(&b));
                let size = cp["size"].as_u64().unwrap_or(0);
                cp["entries"] = Value::Array(self.entries(&http, &warp, size));
                cp["up"] = true.into();
                let victim_http = Client::new(Duration::from_millis(800)).with_header("x-loom-client", VICTIM);
                let fork = match victim_http.get(&format!("{warp}/checkpoint")) {
                    Ok(vb) => {
                        let mut v = parse_checkpoint(&String::from_utf8_lossy(&vb));
                        if v["root"] != cp["root"] {
                            let vsize = v["size"].as_u64().unwrap_or(0);
                            v["entries"] = Value::Array(self.entries(&victim_http, &warp, vsize));
                            v["victim"] = VICTIM.into();
                            v
                        } else {
                            Value::Null
                        }
                    }
                    Err(_) => Value::Null,
                };
                (cp, fork)
            }
            Err(e) => (json!({"up": false, "error": e.to_string(), "entries": []}), Value::Null),
        };
        services.push(json!({"id": "warp", "kind": "warp", "label": "Warp log", "url": warp, "up": log["up"]}));

        // ---- witnesses: what each has most recently cosigned
        let mut witnesses = vec![];
        for (i, p) in ep["witnesses"].as_array().cloned().unwrap_or_default().iter().enumerate() {
            let wurl = url(p);
            let name = format!("witness-{}", i + 1);
            let up = http.get(&format!("{wurl}/info")).is_ok();
            let latest = http
                .get(&format!("{wurl}/latest?origin={origin}"))
                .ok()
                .map(|b| parse_checkpoint(&String::from_utf8_lossy(&b)));
            services.push(json!({"id": name, "kind": "witness", "label": name, "url": wurl, "up": up}));
            witnesses.push(json!({"name": name, "url": wurl, "up": up, "latest": latest}));
        }

        // ---- Shuttle peers (one per rebuilder CAS)
        for (i, p) in ep["threads"].as_array().cloned().unwrap_or_default().iter().enumerate() {
            let purl = url(p);
            let id = ["thread-a", "thread-b", "thread-c"].get(i).copied().unwrap_or("peer");
            // Any HTTP answer (even 404) means the peer is listening.
            let up = match http.get(&format!("{purl}/")) {
                Ok(_) => true,
                Err(loom_core::http::HttpError::Status { .. }) => true,
                Err(_) => false,
            };
            services.push(json!({"id": format!("peer-{id}"), "kind": "peer", "label": id, "url": purl, "up": up}));
        }

        // ---- mock AUR scenario state (read from disk, like the server)
        let scenario = std::fs::read(self.home.join("aur/scenario.json"))
            .map_err(anyhow::Error::from)
            .and_then(|b| Ok(serde_json::from_slice::<Scenario>(&b)?));
        let aur = match scenario {
            Ok(sc) => {
                let now = loom_core::time::now();
                json!({
                    "packages": sc.packages.iter().map(|(n, p)| json!({
                        "name": n, "version": p.version, "maintainer": p.maintainer,
                        "age_hours": (now - p.last_modified) / 3600, "commit": p.commit.get(..12).unwrap_or(&p.commit),
                    })).collect::<Vec<_>>(),
                    "advisories": sc.advisories,
                    "sink_hits": sc.sink_hits,
                })
            }
            Err(e) => json!({"error": e.to_string()}),
        };

        let events: Vec<Value> = std::fs::read_to_string(&self.events)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();

        json!({
            "generated_at": loom_core::time::now(),
            "live": live,
            "home": self.home.display().to_string(),
            "origin": origin,
            "services": services,
            "log": log,
            "fork": fork,
            "witnesses": witnesses,
            "aur": aur,
            "installed": self.read_json("state/installed.json"),
            "eval": self.read_json("eval.json"),
            "events": events,
        })
    }

    /// The page with a frozen state embedded (no services needed to view it).
    /// `fragment` omits the doctype/head shell.
    pub fn snapshot_html(&self, fragment: bool) -> String {
        let state = serde_json::to_string(&self.state(false)).unwrap_or_else(|_| "null".into());
        // Keep the JSON inert inside <script>: no "</" or "<!--" sequences.
        let state = state.replace("</", "<\\/").replace("<!--", "<\\!--");
        let body = PAGE.replace("/*__LOOM_SNAPSHOT__*/null", &state);
        if fragment {
            body
        } else {
            full_page(&body)
        }
    }

    pub fn handler(self: Arc<Self>) -> Handler {
        Arc::new(move |r: &Request| match (r.method.as_str(), r.path.as_str()) {
            ("GET", "/") | ("GET", "/index.html") => Response::bytes(200, "text/html; charset=utf-8", full_page(PAGE).into_bytes()),
            ("GET", "/api/state") => Response::json(&self.state(true)),
            _ => Response::not_found(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_names_cosigners_but_not_the_log() {
        let note = "demo.loom/warp\n30\nabc=\n\n— demo.loom/warp AAAA\n— witness-1 BBBB\n— witness-3 CCCC\n";
        let v = parse_checkpoint(note);
        assert_eq!(v["size"], 30);
        assert_eq!(v["root"], "abc=");
        assert_eq!(v["cosigners"], json!(["witness-1", "witness-3"]));
    }

    #[test]
    fn page_has_snapshot_slot() {
        assert!(PAGE.contains("/*__LOOM_SNAPSHOT__*/null"));
    }
}
