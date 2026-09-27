//! `loomd` — Loom's network services.
//!
//! * `loomd warp --config warp.toml`       transparency log
//! * `loomd witness --config witness.toml` log witness
//! * `loomd thread --config thread.toml`   rebuilder (+ Shuttle peer)
//! * `loomd peer --cas DIR --listen ADDR`  standalone Shuttle peer
//! * `loomd revoke ...`                    submit a signed revocation
//! * `loomd keygen --out FILE --name N`    create an Ed25519 key (0600)

use clap::{Parser, Subcommand};
use loom_core::attest::{self, LogRecord, RevocationPredicate};
use loom_core::digest::Digest;
use loom_core::http::{Client, Server};
use loom_core::keys::{PublicKey, SecretKey};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "loomd", version, about = "Loom services: Warp log, witnesses, Thread rebuilders, Shuttle peers")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Warp {
        #[arg(long)]
        config: PathBuf,
    },
    Witness {
        #[arg(long)]
        config: PathBuf,
    },
    Thread {
        #[arg(long)]
        config: PathBuf,
        /// Rebuild once and exit (otherwise loop every --interval seconds).
        #[arg(long)]
        once: bool,
        #[arg(long, default_value_t = 60)]
        interval: u64,
        /// Only these packages.
        #[arg(long)]
        package: Vec<String>,
        /// Serve the CAS to peers while running.
        #[arg(long)]
        serve: bool,
        /// Evaluation only (E6): submit into a split-view log's victim fork.
        #[arg(long)]
        into_fork: bool,
    },
    Peer {
        #[arg(long)]
        cas: PathBuf,
        #[arg(long)]
        listen: String,
        /// Evaluation only: serve corrupted artifacts (ADV-7).
        #[arg(long)]
        poisoned: bool,
    },
    Revoke {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        log: String,
        /// Leaf index of the attestation to revoke.
        #[arg(long)]
        index: u64,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        revoker: String,
    },
    Keygen {
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        name: String,
    },
    /// Split-view attack on a log started with `split_view = true` (E6 demo).
    Fork {
        #[arg(long)]
        log: String,
        #[arg(long, default_value = "victim")]
        victim: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRef {
    id: String,
    key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WarpConfig {
    origin: String,
    key: PathBuf,
    data: PathBuf,
    listen: String,
    #[serde(default)]
    witnesses: Vec<String>,
    #[serde(default)]
    split_view: bool,
    #[serde(default)]
    rebuilder: Vec<KeyRef>,
    #[serde(default)]
    revoker: Vec<KeyRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogRef {
    origin: String,
    vkey: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WitnessConfig {
    name: String,
    key: PathBuf,
    state: PathBuf,
    listen: String,
    #[serde(default)]
    evil: bool,
    log: Vec<LogRef>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AurRef {
    rpc: String,
    git: String,
    packages: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ThreadConfig {
    id: String,
    org: String,
    key: PathBuf,
    image: String,
    log: String,
    cache: PathBuf,
    listen: Option<String>,
    #[serde(default)]
    tamper: bool,
    #[serde(default)]
    packages: Vec<String>,
    /// kernel | unconfined-demo
    #[serde(default)]
    sandbox: Option<String>,
    #[serde(default = "d_tier")]
    min_tier: String,
    aur: AurRef,
}

fn d_tier() -> String {
    "reduced".into()
}

fn load<T: for<'de> Deserialize<'de>>(p: &PathBuf) -> anyhow::Result<T> {
    let t = std::fs::read_to_string(p).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?;
    toml::from_str(&t).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))
}

fn main() {
    loom_heddle::maybe_init();
    if let Err(e) = run(Cli::parse()) {
        eprintln!("loomd: error: {e:#}");
        std::process::exit(2);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.cmd {
        Cmd::Keygen { out, name } => {
            let k = SecretKey::generate_named(&name);
            k.save(&out)?;
            println!("{}", k.public().to_b64());
        }
        Cmd::Warp { config } => {
            let c: WarpConfig = load(&config)?;
            let key = SecretKey::load(&c.key)?;
            let mut adm = loom_warp::server::Admission::default();
            for r in c.rebuilder {
                adm.rebuilders.insert(r.id, PublicKey::from_b64(&r.key)?);
            }
            for r in c.revoker {
                adm.revokers.insert(r.id, PublicKey::from_b64(&r.key)?);
            }
            std::fs::create_dir_all(&c.data)?;
            let log = loom_warp::server::LogServer::new(&c.origin, key, c.witnesses, adm, Some(c.data), c.split_view)?;
            let srv = Server::start(&c.listen, 8, log.clone().handler())?;
            eprintln!("warp: {} serving on {} (size {}){}", c.origin, srv.url(), log.size(), if c.split_view { " [SPLIT-VIEW ATTACK MODE]" } else { "" });
            eprintln!("warp: vkey {}", log.vkey());
            srv.wait();
        }
        Cmd::Witness { config } => {
            let c: WitnessConfig = load(&config)?;
            let key = SecretKey::load(&c.key)?;
            let mut logs = BTreeMap::new();
            for l in c.log {
                let (_, pk) = loom_warp::notes::parse_vkey(&l.vkey)?;
                logs.insert(l.origin, pk);
            }
            let w = Arc::new(loom_warp::witness::Witness::new(&c.name, key, logs, Some(c.state), c.evil)?);
            let srv = Server::start(&c.listen, 4, w.clone().handler())?;
            eprintln!("witness: {} on {}{}", c.name, srv.url(), if c.evil { " [CORRUPT — cosigns anything]" } else { "" });
            srv.wait();
        }
        Cmd::Thread { config, once, interval, package, serve, into_fork } => {
            let c: ThreadConfig = load(&config)?;
            let key = SecretKey::load(&c.key)?;
            let sandbox = match c.sandbox.as_deref() {
                Some("unconfined-demo") => loom_heddle::Backend::UnconfinedDemo { victim_home: None },
                _ => loom_heddle::Backend::Kernel,
            };
            let opts = loom_thread::build::BuildOptions {
                sandbox,
                min_tier: loom_heddle::Tier::parse(&c.min_tier)?,
                allow_network: false,
                timeout: Duration::from_secs(3600),
            };
            let mut reb = loom_thread::Rebuilder::new(&c.id, &c.org, key, &c.image, &c.log, c.cache.clone(), opts, c.tamper);
            reb.into_fork = into_fork;
            let mut aur = loom_aur::AurConfig::official(&c.cache);
            aur.rpc = c.aur.rpc;
            aur.git_template = c.aur.git;
            aur.packages_list = c.aur.packages;
            let backend = loom_aur::AurBackend::new(aur);
            let srv = match (&c.listen, serve) {
                (Some(l), true) => Some(Server::start(
                    l,
                    4,
                    loom_shuttle::PeerServer::new(Some(reb.cas.clone()), None, loom_shuttle::PeerMode::Honest).handler(),
                )?),
                _ => None,
            };
            if let Some(s) = &srv {
                eprintln!("thread {}: serving artifacts on {}", c.id, s.url());
            }
            let only: Vec<String> = if package.is_empty() { c.packages.clone() } else { package };
            loop {
                let results = reb.run_once(&backend, &only)?;
                for r in &results {
                    if r.note == "already attested" {
                        continue;
                    }
                    println!(
                        "thread {}: {:<14} {:<10} {:<15} {}{}",
                        c.id,
                        r.package,
                        r.version,
                        format!("{:?}", r.outcome).to_lowercase(),
                        r.artifact.map(|d| d.short()).unwrap_or_else(|| "-".into()),
                        match (r.log_index, r.note.as_str()) {
                            (Some(i), "") => format!("  (log #{i})"),
                            (Some(i), n) => format!("  (log #{i}; {n})"),
                            (None, n) => format!("  ({n})"),
                        }
                    );
                }
                if once {
                    break;
                }
                std::thread::sleep(Duration::from_secs(interval));
            }
            if let Some(s) = srv {
                if !once {
                    s.wait();
                }
            }
        }
        Cmd::Peer { cas, listen, poisoned } => {
            let mode = if poisoned { loom_shuttle::PeerMode::Poisoned } else { loom_shuttle::PeerMode::Honest };
            let srv = Server::start(&listen, 4, loom_shuttle::PeerServer::new(Some(loom_shuttle::Cas::new(&cas)), None, mode).handler())?;
            eprintln!("peer: {} on {}", if poisoned { "POISONED" } else { "honest" }, srv.url());
            srv.wait();
        }
        Cmd::Revoke { key, log, index, reason, revoker } => {
            let k = SecretKey::load(&key)?;
            let http = Client::new(Duration::from_secs(10));
            let body = http.get(&format!("{log}/entries?start={index}&end={}", index + 1))?;
            let er: loom_warp::server::EntriesResponse = serde_json::from_slice(&body)?;
            let leaf = er.entries.first().ok_or_else(|| anyhow::anyhow!("no leaf {index}"))?;
            let pred = RevocationPredicate {
                target_index: index,
                target_leaf: Digest::of(leaf.as_bytes()),
                reason,
                revoker,
                timestamp: loom_core::time::now(),
            };
            let rec: LogRecord = attest::sign_revocation(pred, &k)?;
            let resp = http.post(&format!("{log}/add"), "application/json", &serde_json::to_vec(&rec)?)?;
            println!("{}", String::from_utf8_lossy(&resp));
        }
        Cmd::Fork { log, victim } => {
            let http = Client::new(Duration::from_secs(10));
            let r = http.post(&format!("{log}/admin/fork?victim={victim}"), "text/plain", b"")?;
            println!("{}", String::from_utf8_lossy(&r).trim());
        }
    }
    Ok(())
}
