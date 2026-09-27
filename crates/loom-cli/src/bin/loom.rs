//! `loom` — the Loom client (SRS §7.1).
//!
//! Exit status: 0 = success/allowed, 1 = blocked by policy, 2 = error.

use clap::{Parser, Subcommand};
use loom_client::audit;
use loom_client::pipeline::{Loom, Mode};
use loom_client::Paths;
use loom_core::ecosystem::Backend as _;
use loom_weave::eval::{render, OverrideKind};
use loom_weave::policy::DEFAULT_POLICY;

#[derive(Parser)]
#[command(name = "loom", version, about = "Loom — a decentralised, verifying package manager for the AUR")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Resolve, verify, obtain (attested artifact or sandboxed build) and install.
    Install {
        packages: Vec<String>,
        /// Evaluate and obtain, but do not install.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        json: bool,
        /// Show per-phase timings (evaluation E5).
        #[arg(long)]
        timings: bool,
    },
    /// Verification only, no installation.
    Verify {
        package: String,
        version: Option<String>,
        /// Build locally under Heddle if no attested artifact is available.
        #[arg(long)]
        build: bool,
        #[arg(long)]
        json: bool,
    },
    /// Full trust derivation for a package.
    Explain {
        package: String,
        #[arg(long)]
        json: bool,
    },
    /// Read-only provenance report for this system.
    Audit {
        #[arg(long)]
        json: bool,
    },
    /// Inspect or check the active policy.
    Policy {
        #[arg(default_value = "show")]
        action: String,
    },
    /// Manage persistent, user-authorised exceptions.
    Override {
        #[command(subcommand)]
        action: OverrideCmd,
    },
    /// Serve the local artifact cache and log mirror to peers (FR-2.4).
    Serve {
        #[arg(long)]
        listen: Option<String>,
    },
    /// Show the verified transparency-log state.
    Log,
    /// Check which sandbox tier this host provides (runs a trivial build).
    SandboxCheck,
}

#[derive(Subcommand)]
enum OverrideCmd {
    /// kind: quarantine | continuity | attestations | sandbox-network | placement
    Add {
        kind: String,
        package: String,
        version: Option<String>,
        #[arg(long)]
        reason: String,
    },
    List,
    Rm { id: u64 },
}

fn main() {
    loom_heddle::maybe_init();
    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("loom: error: {e:#}");
            2
        }
    };
    std::process::exit(code);
}

fn print_run(run: &loom_client::PackageRun, verbose: bool) {
    print!("{}", render(&run.decision, verbose));
    if let Some(o) = &run.origin {
        println!("  artifact: {} from {}", run.decision.target.map(|d| d.short()).unwrap_or_default(), o);
    }
    for n in &run.fetch_notes {
        println!("  shuttle: {n}");
    }
    if let Some(b) = &run.build {
        if !b.denials.is_empty() {
            println!("  sandbox denials:");
            for d in &b.denials {
                println!("    - {} {} [{} {}]", d.syscall, d.resource, d.rule, d.requirement);
            }
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<i32> {
    let paths = Paths::from_env();
    match cli.cmd {
        Cmd::Policy { action } => {
            match action.as_str() {
                "default" => print!("{DEFAULT_POLICY}"),
                "show" | "validate" => {
                    let (p, path) = paths.load_policy()?;
                    let witnesses = paths.load_config().map(|c| c.witness.len()).unwrap_or(0);
                    match &path {
                        Some(p) => println!("# policy: {} (valid)", p.display()),
                        None => println!("# policy: built-in secure default (no policy.toml) (valid)"),
                    }
                    for w in p.warnings(witnesses) {
                        println!("# note: {}", w.0);
                    }
                    if action == "show" {
                        print!("{}", toml::to_string_pretty(&p)?);
                    }
                }
                other => anyhow::bail!("unknown policy action {other:?} (show, validate, default)"),
            }
            Ok(0)
        }
        Cmd::Override { action } => {
            let st = loom_client::state::State::new(&paths.state, false);
            match action {
                OverrideCmd::Add { kind, package, version, reason } => {
                    let k = OverrideKind::parse(&kind)?;
                    let o = st.add_override(k, &package, version.as_deref(), &reason)?;
                    println!(
                        "override #{} recorded: {} for {}{} — \"{}\" (listed by `loom audit`)",
                        o.id,
                        k.as_str(),
                        package,
                        o.version.as_ref().map(|v| format!(" {v}")).unwrap_or_default(),
                        reason
                    );
                }
                OverrideCmd::List => {
                    for o in st.overrides()? {
                        println!(
                            "#{:<3} {:<16} {:<20} {:<10} {} ({} by {})",
                            o.id,
                            o.kind.as_str(),
                            o.package,
                            o.version.clone().unwrap_or_else(|| "*".into()),
                            o.reason,
                            loom_core::time::rfc3339(o.created_at),
                            o.user
                        );
                    }
                }
                OverrideCmd::Rm { id } => {
                    if !st.remove_override(id)? {
                        anyhow::bail!("no override #{id}");
                    }
                    println!("override #{id} removed");
                }
            }
            Ok(0)
        }
        Cmd::Install { packages, dry_run, json, timings } => {
            if packages.is_empty() {
                anyhow::bail!("nothing to install");
            }
            let loom = Loom::open(paths, false)?;
            let ctx = loom.context();
            let (order, system) = loom.resolve_order(&packages)?;
            if !system.is_empty() {
                eprintln!(":: dependencies delegated to pacman (FR-1.4): {}", system.join(", "));
            }
            let installer = loom.installer();
            let mut results = vec![];
            let mut blocked = false;
            for meta in &order {
                let as_dep = !packages.contains(&meta.name);
                let run = loom.run_package(&ctx, meta, Mode::Install, None)?;
                if !json {
                    print_run(&run, false);
                }
                if run.decision.blocked() {
                    blocked = true;
                    if !json {
                        println!("  => NOT installed{}", if as_dep { " (dependency)" } else { "" });
                    }
                    results.push(serde_json::json!({"package": meta.name, "installed": false, "decision": run.decision}));
                    break; // dependents cannot be installed either
                }
                if dry_run {
                    results.push(serde_json::json!({"package": meta.name, "installed": false, "dry_run": true, "decision": run.decision}));
                    continue;
                }
                let out = loom.commit_install(&run, &installer, as_dep)?;
                if !json {
                    if out.installed {
                        println!("  => installed {} {} via {}", out.package, out.version, installer.describe());
                    } else {
                        println!("  => NOT installed (no verified artifact)");
                        blocked = true;
                    }
                    if let Some(h) = &out.hook {
                        if h != "none" {
                            println!("  install script: {h}");
                        }
                    }
                }
                if timings {
                    let mut t = ctx.timings.clone();
                    t.extend(run.timings.clone());
                    eprintln!(":: timings {}: {}", meta.name, serde_json::to_string(&t)?);
                }
                results.push(serde_json::json!({"package": meta.name, "result": out, "decision": run.decision, "timings": run.timings}));
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&results)?);
            }
            Ok(if blocked { 1 } else { 0 })
        }
        Cmd::Verify { package, version, build, json } => {
            let loom = Loom::open(paths, false)?;
            let ctx = loom.context();
            let meta = loom
                .backend
                .resolve(&[package.clone()])?
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("{package} not found in the AUR"))?;
            let run = loom.run_package(&ctx, &meta, Mode::Verify { build }, version.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&run.decision)?);
            } else {
                print_run(&run, false);
            }
            Ok(if run.decision.blocked() { 1 } else { 0 })
        }
        Cmd::Explain { package, json } => {
            let loom = Loom::open(paths, false)?;
            let ctx = loom.context();
            let meta = loom
                .backend
                .resolve(&[package.clone()])?
                .into_iter()
                .next()
                .ok_or_else(|| anyhow::anyhow!("{package} not found in the AUR"))?;
            let run = loom.run_package(&ctx, &meta, Mode::Explain, None)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "decision": run.decision,
                    "attestations": run.views,
                    "maintainer": meta.maintainer,
                    "commit": run.checkout.commit,
                }))?);
                return Ok(if run.decision.blocked() { 1 } else { 0 });
            }
            println!("== {} {} ==", meta.name, run.decision.version);
            println!("maintainer:   {}", meta.maintainer.as_deref().unwrap_or("(orphaned)"));
            println!("published:    {}", loom_core::time::rfc3339(meta.last_modified));
            println!("recipe:       {} @ {}", meta.repo_url, &run.checkout.commit[..12]);
            println!("policy:       k={} min_age={} continuity={:?} insufficient={:?}{}",
                run.decision.effective.required_attestations,
                loom_core::duration::human(run.decision.effective.min_age),
                run.decision.effective.on_continuity_change,
                run.decision.effective.on_insufficient_attestations,
                if run.decision.effective.escalated { " (ESCALATED)" } else { "" });
            println!("sandbox:      {}", loom.sandbox.describe());
            println!("all attestations for this package in the log:");
            for a in &run.views {
                println!(
                    "  #{:<4} {:<12} {:<9} {:<16} {:<14} {}{}",
                    a.index,
                    a.rebuilder,
                    a.version,
                    format!("{:?}", a.outcome).to_lowercase(),
                    a.artifact.map(|d| d.short()).unwrap_or_else(|| "-".into()),
                    a.observed_maintainer.as_deref().map(|m| format!("maint={m}")).unwrap_or_else(|| "maint=(orphaned)".into()),
                    if a.revoked.is_some() { " REVOKED" } else if !a.trusted { " UNTRUSTED" } else { "" }
                );
            }
            println!();
            print_run(&run, true);
            Ok(if run.decision.blocked() { 1 } else { 0 })
        }
        Cmd::Audit { json } => {
            let loom = Loom::open(paths, true)?;
            let r = audit::audit(&loom)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&r)?);
            } else {
                print!("{}", audit::render(&r));
            }
            Ok(0)
        }
        Cmd::Log => {
            let loom = Loom::open(paths, false)?;
            match loom.log_client().update() {
                Ok(v) => {
                    println!("origin:      {}", v.checkpoint.origin);
                    println!("tree size:   {}", v.checkpoint.size);
                    println!("root:        {}", v.checkpoint.root_b64());
                    println!("cosigned by: {}", v.cosigs.iter().map(|c| format!("{} @{}", c.witness, loom_core::time::rfc3339(c.timestamp as i64))).collect::<Vec<_>>().join(", "));
                    println!("cross-checked witness views: {}", if v.cross_checked.is_empty() { "(none reachable)".into() } else { v.cross_checked.join(", ") });
                    if let Some(p) = v.previous_size {
                        println!("consistent with previously accepted size {p}");
                    }
                    for n in &v.notes {
                        println!("note: {n}");
                    }
                    Ok(0)
                }
                Err(e) => {
                    println!("{e}");
                    Ok(1)
                }
            }
        }
        Cmd::Serve { listen } => {
            let cfg = paths.load_config()?;
            let (policy, _) = paths.load_policy()?;
            let addr = listen.or(cfg.peers.listen.clone()).unwrap_or_else(|| "127.0.0.1:7780".into());
            let cas = policy.peer.serve_cache.then(|| loom_shuttle::Cas::new(&paths.cache.join("cas")));
            let srv = loom_core::http::Server::start(
                &addr,
                4,
                loom_shuttle::PeerServer::new(cas, Some(paths.state.clone()), loom_shuttle::PeerMode::Honest).handler(),
            )?;
            eprintln!("loom: serving verified cache and log mirror on {}", srv.url());
            srv.wait();
            Ok(0)
        }
        Cmd::SandboxCheck => {
            let loom = Loom::open(paths, false)?;
            let d = loom.paths.cache.join("sandbox-check");
            std::fs::create_dir_all(&d)?;
            let spec = loom_heddle::SandboxSpec::new(&d, vec!["/bin/sh".into(), "-c".into(), "echo ok".into()]);
            match loom_heddle::run(&spec, &loom.sandbox) {
                Ok(r) => {
                    println!("sandbox tier: {}", r.tier.as_str());
                    for l in &r.layers {
                        println!("  layer: {l}");
                    }
                    for x in &r.reduced {
                        println!("  reduced: {x}");
                    }
                    Ok(0)
                }
                Err(e) => {
                    println!("sandbox unavailable: {e}");
                    Ok(1)
                }
            }
        }
    }
}
