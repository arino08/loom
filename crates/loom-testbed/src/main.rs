//! `loom-testbed` — mock AUR + provisioning for the demo and evaluation.

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
            println!("published {pkg} {dir} by {maintainer}{} → {}", if rewrite { " (history rewritten)" } else { "" }, &commit[..12]);
        }
        Cmd::SetAge { pkg, hours } => {
            let aur = MockAur::open(&aur_root(&home), &fixtures())?;
            aur.set_published(&pkg, loom_core::time::now() - hours * 3600)?;
            println!("{pkg} published {hours}h ago");
        }
        Cmd::Advisories { file } => {
            let aur = MockAur::open(&aur_root(&home), &fixtures())?;
            let adv: Vec<serde_json::Value> = serde_json::from_slice(&std::fs::read(&file)?)?;
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
        Cmd::Endpoints => {
            print!("{}", std::fs::read_to_string(home.join("endpoints.json"))?);
        }
    }
    Ok(())
}
