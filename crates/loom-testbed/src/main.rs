//! `loom-testbed` — mock AUR + provisioning for the demo and evaluation.

mod dashboard;
mod mockaur;
mod provision;

use clap::{Parser, Subcommand};
use mockaur::MockAur;
use provision::{home_from_env, Endpoints};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "loom-testbed", about = "Loom demo/evaluation testbed: mock AUR and provisioning")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate all keys, configs and the initial mock AUR state.
    Provision {
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// kernel | unconfined-demo (default: leave unset → kernel).
        #[arg(long)]
        sandbox: Option<String>,
    },
    /// Serve the mock AUR (RPC, git, upstream, advisories, sink).
    Serve {
        #[arg(long, default_value_t = 7700)]
        port: u16,
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
    },
    /// Publish a fixture version (advance the scenario).
    Publish {
        pkg: String,
        dir: String,
        #[arg(long, default_value = "orphan")]
        maintainer: String,
        /// Rewrite history (force-push) instead of appending a commit.
        #[arg(long)]
        rewrite: bool,
    },
    /// Set a package's publication time to N hours ago.
    SetAge { pkg: String, hours: i64 },
    /// Load the advisory feed from a JSON file.
    Advisories { file: PathBuf },
    /// Print / clear the demo sink hit log.
    Sink {
        #[arg(long)]
        clear: bool,
    },
    /// Print the resolved endpoints JSON.
    Endpoints,
    /// Serve the live deployment dashboard (web UI over every service).
    Dashboard {
        #[arg(long, default_value = "127.0.0.1:7790")]
        listen: String,
    },
    /// Write a self-contained HTML snapshot of the dashboard.
    Report {
        #[arg(long)]
        out: PathBuf,
        /// Omit the doctype/head shell (for hosts that supply their own).
        #[arg(long)]
        fragment: bool,
    },
    /// Append a note to the event journal ($LOOM_EVENTS), e.g. a scenario
    /// step or its conclusion. `--set k=v` adds fields (numbers parsed).
    Note {
        kind: String,
        text: String,
        #[arg(long = "set")]
        set: Vec<String>,
    },
}

fn fixtures() -> PathBuf {
    std::env::var_os("LOOM_FIXTURES")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("demo/fixtures"))
}

fn aur_root(home: &std::path::Path) -> PathBuf {
    home.join("aur")
}

fn main() {
    if let Err(e) = run() {
        eprintln!("loom-testbed: error: {e:#}");
        std::process::exit(2);
    }
}

fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let home = home_from_env();
    match cli.cmd {
        Cmd::Provision { host, sandbox } => {
            let ep = Endpoints::default_on(&host);
            provision::provision(&home, &fixtures(), &ep, sandbox.as_deref())?;
            println!("provisioned Loom demo under {}", home.display());
            println!("  client config: {}/etc/loom.toml", home.display());
            println!("  services:      {}/svc/*.toml", home.display());
        }
        Cmd::Serve { port, host } => {
            let aur = MockAur::open(&aur_root(&home), &fixtures())?;
            aur.set_base_url(&format!("http://{host}:{port}"));
            let srv = loom_core::http::Server::start(&format!("{host}:{port}"), 6, aur.handler())?;
            eprintln!("mock AUR serving on {}", srv.url());
            srv.wait();
        }
        Cmd::Publish { pkg, dir, maintainer, rewrite } => {
            let aur = MockAur::open(&aur_root(&home), &fixtures())?;
            // base_url only matters for placeholder rewriting; read it back.
            if let Ok(b) = std::fs::read(home.join("endpoints.json")) {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&b) {
                    let host = v["host"].as_str().unwrap_or("127.0.0.1");
                    let port = v["aur"].as_u64().unwrap_or(7700);
                    aur.set_base_url(&format!("http://{host}:{port}"));
                }
            }
            let commit = aur.publish(&pkg, &dir, &maintainer, rewrite)?;
            loom_core::journal::record(
                "publish",
                serde_json::json!({"package": pkg, "version": dir, "maintainer": maintainer, "rewrite": rewrite, "commit": &commit[..12]}),
            );
            println!("published {pkg} {dir} by {maintainer}{} → {}", if rewrite { " (history rewritten)" } else { "" }, &commit[..12]);
        }
        Cmd::SetAge { pkg, hours } => {
            let aur = MockAur::open(&aur_root(&home), &fixtures())?;
            aur.set_published(&pkg, loom_core::time::now() - hours * 3600)?;
            loom_core::journal::record("set-age", serde_json::json!({"package": pkg, "hours": hours}));
            println!("{pkg} published {hours}h ago");
        }
        Cmd::Advisories { file } => {
            let aur = MockAur::open(&aur_root(&home), &fixtures())?;
            let adv: Vec<serde_json::Value> = serde_json::from_slice(&std::fs::read(&file)?)?;
            loom_core::journal::record("advisories", serde_json::json!({"advisories": adv}));
            aur.set_advisories(adv)?;
            println!("advisory feed loaded from {}", file.display());
        }
        Cmd::Sink { clear } => {
            let aur = MockAur::open(&aur_root(&home), &fixtures())?;
            if clear {
                aur.clear_sink()?;
                println!("sink cleared");
            } else {
                let hits = aur.sink_hits();
                if hits.is_empty() {
                    println!("(sink empty — no build reached the network)");
                }
                for h in hits {
                    println!("HIT {h}");
                }
            }
        }
        Cmd::Dashboard { listen } => {
            let d = dashboard::Dashboard::new(&home);
            let srv = loom_core::http::Server::start(&listen, 4, d.handler())?;
            eprintln!("dashboard on {}", srv.url());
            srv.wait();
        }
        Cmd::Report { out, fragment } => {
            std::fs::write(&out, dashboard::Dashboard::new(&home).snapshot_html(fragment))?;
            println!("report written to {}", out.display());
        }
        Cmd::Note { kind, text, set } => {
            let mut m = serde_json::Map::new();
            m.insert("text".into(), text.into());
            for kv in set {
                let (k, v) = kv.split_once('=').ok_or_else(|| anyhow::anyhow!("--set expects k=v, got {kv:?}"))?;
                let v = v.parse::<i64>().map(serde_json::Value::from).unwrap_or_else(|_| v.into());
                m.insert(k.into(), v);
            }
            loom_core::journal::record(&kind, serde_json::Value::Object(m));
        }
        Cmd::Endpoints => {
            print!("{}", std::fs::read_to_string(home.join("endpoints.json"))?);
        }
    }
    Ok(())
}
