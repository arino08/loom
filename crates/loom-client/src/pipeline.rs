//! The client pipeline: resolve → verify → obtain → re-verify → install.
//!
//! Order matters. Every check that can be made *without executing recipe
//! code* (log integrity, attestations, continuity, quarantine) runs first, so
//! a blocked package is refused before any payload could run (AC-1). Then,
//! by default, the client installs the **attested artifact** fetched by
//! content address (audit item A1: *verify, don't build*): when k
//! independent rebuilders agree, no PKGBUILD code runs on the user's machine
//! at all. Only if no attested artifact can be obtained does the client
//! build locally under Heddle — and the local result must still match.

use crate::config::{Config, Paths};
use crate::install::{run_install_hook, Installer};
use crate::state::{Installed, State};
use loom_aur::{AurBackend, AurConfig};
use loom_core::attest::{self, LogRecord, RebuildStatement};
use loom_core::digest::Digest;
use loom_core::ecosystem::{Backend, Checkout, PackageMeta};
use loom_core::keys::PublicKey;
use loom_heddle::{Backend as Sandbox, Tier};
use loom_shuttle::Cas;
use loom_thread::build::{BuildOptions, Variation};
use loom_warp::client::{ClientConfig, LogClient, LogError, LogView, TrustedLog, TrustedWitness};
use loom_weave::advisory;
use loom_weave::continuity::{self, Baseline};
use loom_weave::eval::{self, AttestationView, BuildView, Candidate, DenialView, Evidence, LogStatus, OverrideKind, Revoked};
use loom_weave::placement;
use loom_weave::policy::{InstallScripts, MinTier};
use loom_weave::{Decision, Policy};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub struct Loom {
    pub paths: Paths,
    pub cfg: Config,
    pub policy: Policy,
    pub policy_path: Option<PathBuf>,
    pub backend: AurBackend,
    pub state: State,
    pub sandbox: Sandbox,
    pub read_only: bool,
    pub progress: Box<dyn Fn(&str) + Send + Sync>,
}

/// A log record parsed into an attestation, with its trust status.
#[derive(Clone)]
pub struct ParsedAttestation {
    pub index: u64,
    pub st: RebuildStatement,
    pub trusted: bool,
    pub org: String,
}

/// Per-invocation evidence shared across packages.
pub struct Context {
    pub log: LogStatus,
    pub view: Option<LogView>,
    pub attestations: Vec<ParsedAttestation>,
    pub revoked: BTreeMap<u64, Revoked>,
    pub advisories: Result<Vec<advisory::Group>, String>,
    pub timings: BTreeMap<String, u128>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Install,
    /// Verification only; builds locally only when `build` is set.
    Verify { build: bool },
    /// Full derivation, never builds.
    Explain,
}

pub struct PackageRun {
    pub meta: PackageMeta,
    pub checkout: Checkout,
    pub decision: Decision,
    pub pre_build: Option<Decision>,
    pub artifact: Option<Vec<u8>>,
    pub origin: Option<String>,
    pub fetch_notes: Vec<String>,
    pub build: Option<BuildView>,
    pub views: Vec<AttestationView>,
    pub timings: BTreeMap<String, u128>,
}

#[derive(Debug, serde::Serialize)]
pub struct InstallOutcome {
    pub package: String,
    pub version: String,
    pub installed: bool,
    pub origin: Option<String>,
    pub decision: String,
    pub hook: Option<String>,
}

fn ms(t: Instant) -> u128 {
    t.elapsed().as_millis()
}

impl Loom {
    pub fn open(paths: Paths, read_only: bool) -> anyhow::Result<Loom> {
        let cfg = paths.load_config()?;
        let (policy, policy_path) = paths.load_policy()?;
        let mut aur = AurConfig::official(&paths.cache);
        aur.rpc = cfg.aur.rpc.clone();
        aur.git_template = cfg.aur.git.clone();
        aur.packages_list = cfg.aur.packages.clone();
        let sandbox = match cfg.sandbox.backend.as_deref() {
            Some("unconfined-demo") => Sandbox::UnconfinedDemo {
                victim_home: std::env::var_os("LOOM_DEMO_VICTIM_HOME").map(PathBuf::from),
            },
            _ => Sandbox::from_env(),
        };
        Ok(Loom {
            state: State::new(&paths.state, read_only),
            backend: AurBackend::new(aur),
            paths,
            cfg,
            policy,
            policy_path,
            sandbox,
            read_only,
            progress: Box::new(|m| eprintln!(":: {m}")),
        })
    }

    fn say(&self, m: &str) {
        (self.progress)(m)
    }

    pub fn log_client(&self) -> LogClient {
        LogClient::new(ClientConfig {
            log: TrustedLog {
                origin: self.cfg.log.origin.clone(),
                key: self.cfg.log_key(),
                url: self.cfg.log.url.trim_end_matches('/').to_string(),
            },
            witnesses: self
                .cfg
                .witness
                .iter()
                .map(|w| TrustedWitness {
                    name: w.name.clone(),
                    key: PublicKey::from_b64(&w.key).expect("validated"),
                    url: w.url.clone(),
                })
                .collect(),
            threshold: self.policy.policy.witness_threshold as usize,
            state_dir: self.paths.state.clone(),
            peers: self.cfg.peers.urls.clone(),
            client_id: std::env::var("LOOM_CLIENT_ID").ok(),
            read_only: self.read_only,
        })
    }

    fn rebuilder_key(&self, id: &str) -> Option<(PublicKey, String)> {
        self.cfg
            .rebuilder
            .iter()
            .find(|r| r.id == id)
            .map(|r| (PublicKey::from_b64(&r.key).expect("validated"), r.org.clone()))
    }

    /// Fetch and verify the log, parse attestations and revocations, fetch
    /// the advisory feed.
    pub fn context(&self) -> Context {
        let mut timings = BTreeMap::new();
        let t = Instant::now();
        let (log, view) = match self.log_client().update() {
            Ok(v) => (
                LogStatus::Verified {
                    size: v.checkpoint.size,
                    witnesses: v.cosigs.iter().map(|c| c.witness.clone()).collect(),
                    cross_checked: v.cross_checked.clone(),
                    notes: v.notes.clone(),
                },
                Some(v),
            ),
            Err(LogError::Unavailable(e)) => (LogStatus::Unavailable(e), None),
            Err(LogError::Invalid(e)) => (LogStatus::Invalid(e), None),
            Err(LogError::SplitView(ev)) => (
                LogStatus::SplitView {
                    detail: ev.detail.clone(),
                    evidence: ev.saved_to.as_ref().map(|p| p.display().to_string()),
                },
                None,
            ),
        };
        timings.insert("log_verify_ms".into(), ms(t));

        let t = Instant::now();
        let mut attestations = vec![];
        let mut revoked = BTreeMap::new();
        if let Some(v) = &view {
            for (i, rec) in &v.records {
                match rec {
                    LogRecord::Attestation { .. } => {
                        let Ok(st) = rec.decode_rebuild_unverified() else { continue };
                        let (trusted, org) = match self.rebuilder_key(&st.predicate.rebuilder.id) {
                            Some((k, org)) => (attest::verify_rebuild(rec, &k).is_ok(), org),
                            None => (false, st.predicate.rebuilder.org.clone()),
                        };
                        attestations.push(ParsedAttestation { index: *i, st, trusted, org });
                    }
                    LogRecord::Revocation { .. } => {
                        let Ok(st) = rec.decode_revocation_unverified() else { continue };
                        let p = &st.predicate;
                        // The target must be the leaf the revocation names.
                        let leaf_ok = v.leaf(p.target_index).map(|l| Digest::of(l) == p.target_leaf).unwrap_or(false);
                        if !leaf_ok {
                            continue;
                        }
                        let by_authority = self.cfg.revoker.iter().find(|r| {
                            PublicKey::from_b64(&r.key).map(|k| attest::verify_revocation(rec, &k).is_ok()).unwrap_or(false)
                        });
                        let by = if let Some(a) = by_authority {
                            Some(format!("revocation authority {}", a.name))
                        } else {
                            // Self-revocation: signed by the rebuilder that made the target.
                            v.records
                                .iter()
                                .find(|(j, _)| *j == p.target_index)
                                .and_then(|(_, t)| t.decode_rebuild_unverified().ok())
                                .and_then(|ts| self.rebuilder_key(&ts.predicate.rebuilder.id).map(|k| (ts, k)))
                                .filter(|(_, (k, _))| attest::verify_revocation(rec, k).is_ok())
                                .map(|(ts, _)| format!("rebuilder {} (self-revocation)", ts.predicate.rebuilder.id))
                        };
                        if let Some(by) = by {
                            revoked.insert(p.target_index, Revoked { index: *i, by, reason: p.reason.clone() });
                        }
                    }
                }
            }
        }
        timings.insert("attestation_parse_ms".into(), ms(t));

        let t = Instant::now();
        let advisories = if self.policy.advisory.fast_path {
            loom_core::http::Client::new(Duration::from_secs(5))
                .get(&self.policy.advisory.feed)
                .map_err(|e| e.to_string())
                .and_then(|b| advisory::parse(&b).map_err(|e| e.to_string()))
        } else {
            Ok(vec![])
        };
        timings.insert("advisory_ms".into(), ms(t));
        Context { log, view, attestations, revoked, advisories, timings }
    }

    fn views_for(&self, ctx: &Context, pkg: &str, version: &str, commit: &str) -> Vec<AttestationView> {
        ctx.attestations
            .iter()
            .filter(|a| a.st.predicate.package == pkg)
            .map(|a| {
                let p = &a.st.predicate;
                let relevant = p.version == version && p.source.commit == commit;
                let inclusion = if relevant {
                    match ctx.view.as_ref().map(|v| v.verify_inclusion(a.index)) {
                        Some(Ok(src)) => Ok(format!("{src:?}").to_lowercase()),
                        Some(Err(e)) => Err(e.to_string()),
                        None => Err("log unavailable".into()),
                    }
                } else {
                    Ok("mirror".into())
                };
                AttestationView {
                    index: a.index,
                    rebuilder: p.rebuilder.id.clone(),
                    org: a.org.clone(),
                    toolchain: p.toolchain.id.clone(),
                    toolchain_image: p.toolchain.image.clone(),
                    sandbox_tier: p.toolchain.sandbox_tier.clone(),
                    outcome: p.outcome,
                    artifact: p.artifact,
                    version: p.version.clone(),
                    commit: p.source.commit.clone(),
                    source_digest: p.source.digest,
                    timestamp: p.timestamp,
                    observed_maintainer: p.observed.maintainer.clone(),
                    trusted: a.trusted,
                    inclusion,
                    revoked: ctx.revoked.get(&a.index).cloned(),
                }
            })
            .collect()
    }

    fn peers(&self) -> Vec<String> {
        let mut p: Vec<String> = self.cfg.peers.urls.clone();
        for r in &self.cfg.rebuilder {
            if let Some(u) = &r.url {
                if !p.contains(u) {
                    p.push(u.clone());
                }
            }
        }
        p
    }

    fn cas(&self) -> Cas {
        Cas::new(&self.paths.cache.join("cas"))
    }

    fn min_tier(&self) -> Tier {
        match self.policy.policy.sandbox_min_tier {
            MinTier::Full => Tier::Full,
            MinTier::Reduced => match self.sandbox {
                Sandbox::UnconfinedDemo { .. } => Tier::UnconfinedDemo,
                Sandbox::Kernel => Tier::Reduced,
            },
        }
    }

    /// Resolve `names` and their AUR dependencies, dependencies first (FR-1.1).
    /// Names not found in the AUR are delegated to pacman (FR-1.4).
    pub fn resolve_order(&self, names: &[String]) -> anyhow::Result<(Vec<PackageMeta>, Vec<String>)> {
        let mut order: Vec<PackageMeta> = vec![];
        let mut system = vec![];
        let mut seen = std::collections::BTreeSet::new();
        fn visit(
            l: &Loom,
            name: &str,
            seen: &mut std::collections::BTreeSet<String>,
            order: &mut Vec<PackageMeta>,
            system: &mut Vec<String>,
            top: bool,
        ) -> anyhow::Result<()> {
            if !seen.insert(name.to_string()) {
                return Ok(());
            }
            let found = l.backend.resolve(&[name.to_string()])?;
            match found.into_iter().next() {
                Some(m) => {
                    for d in m.depends.clone() {
                        visit(l, &d, seen, order, system, false)?;
                    }
                    order.push(m);
                }
                None if top => anyhow::bail!("package {name} not found in the AUR"),
                None => system.push(name.to_string()),
            }
            Ok(())
        }
        for n in names {
            visit(self, n, &mut seen, &mut order, &mut system, true)?;
        }
        Ok((order, system))
    }

    /// Evaluate one package; obtain (and verify) its artifact as the mode allows.
    pub fn run_package(&self, ctx: &Context, meta: &PackageMeta, mode: Mode, version: Option<&str>) -> anyhow::Result<PackageRun> {
        let mut timings = BTreeMap::new();
        let t = Instant::now();
        self.say(&format!("{}: fetching recipe (no code is executed)", meta.name));
        let checkout = self.backend.checkout(meta, &self.paths.cache)?;
        timings.insert("recipe_fetch_ms".into(), ms(t));

        let t = Instant::now();
        let version = version.unwrap_or(&checkout.version).to_string();
        // A historic version is identified by the commit rebuilders attested.
        let commit = if version == checkout.version {
            checkout.commit.clone()
        } else {
            ctx.attestations
                .iter()
                .find(|a| a.st.predicate.package == meta.name && a.st.predicate.version == version)
                .map(|a| a.st.predicate.source.commit.clone())
                .unwrap_or_else(|| checkout.commit.clone())
        };
        let views = self.views_for(ctx, &meta.name, &version, &commit);

        let baselines = self.state.baselines()?;
        let baseline = baselines.get(&meta.name);
        let observations = eval::observations(&views);
        let backend = &self.backend;
        let violations = continuity::check(
            baseline,
            &continuity::Current {
                maintainer: meta.maintainer.as_deref(),
                signing_keys: &checkout.signing_keys,
                commit: &checkout.commit,
                tags: &checkout.tags,
                now: loom_core::time::now(),
            },
            &observations,
            self.policy.effective(&meta.name).continuity_window,
            &|c| backend.is_ancestor(&checkout, c).unwrap_or(false),
        );

        let installed = self.state.installed()?;
        let (advisory, advisory_error) = match &ctx.advisories {
            Ok(g) => (advisory::remediates(g, &meta.name, &version, installed.get(&meta.name).map(|i| i.version.as_str())), None),
            Err(e) => (None, Some(e.clone())),
        };
        let overrides = self.state.overrides()?;
        let eff = self.policy.effective(&meta.name);
        let allow_network = eff.allow_network
            || overrides.iter().any(|o| o.kind == OverrideKind::SandboxNetwork && o.package == meta.name);

        let mut ev = Evidence {
            package: meta.name.clone(),
            version: version.clone(),
            commit: commit.clone(),
            source_digest: None,
            maintainer: meta.maintainer.clone(),
            published: meta.last_modified,
            now: loom_core::time::now(),
            log: ctx.log.clone(),
            attestations: views.clone(),
            continuity: violations,
            had_baseline: baseline.is_some(),
            advisory,
            advisory_error,
            unpinned: vec![],
            candidate: None,
            local_build_required: false,
            build: None,
            placement: None,
            install_script: None,
            overrides,
            sandbox_backend: self.sandbox.describe().into(),
        };
        let pre = eval::evaluate(&self.policy, &ev);
        timings.insert("evaluate_ms".into(), ms(t));
        let _ = self.state.log_decision(&pre);

        let mut run = PackageRun {
            meta: meta.clone(),
            checkout: checkout.clone(),
            decision: pre.clone(),
            pre_build: Some(pre.clone()),
            artifact: None,
            origin: None,
            fetch_notes: vec![],
            build: None,
            views,
            timings,
        };
        if pre.blocked() || mode == Mode::Explain && pre.target.is_none() {
            // Refused before any recipe code could execute (AC-1).
            return Ok(run);
        }

        // ---- obtain the artifact: substitute first (A1), build as fallback.
        let t = Instant::now();
        let mut artifact = None;
        if self.policy.policy.prefer_attested_artifact && pre.independent_support > 0 {
            if let Some(target) = pre.target {
                if let Some(b) = self.cas().get(&target) {
                    artifact = Some(b);
                    run.origin = Some("local verified cache".into());
                } else {
                    let peers = self.peers();
                    self.say(&format!("{}: fetching attested artifact {} from {} peer(s)", meta.name, target.short(), peers.len()));
                    match loom_shuttle::fetch(&peers, &target, self.policy.fallback_timeout()) {
                        Ok(f) => {
                            for a in &f.attempts {
                                run.fetch_notes.push(format!("{}: {}", a.peer, a.outcome));
                            }
                            run.origin = Some(format!("peer {}", f.peer));
                            artifact = Some(f.bytes);
                        }
                        Err(attempts) => {
                            for a in attempts {
                                run.fetch_notes.push(format!("{}: {}", a.peer, a.outcome));
                            }
                            run.fetch_notes.push("no peer delivered the attested artifact; falling back to a local sandboxed build (FR-2.3)".into());
                        }
                    }
                }
            }
        }
        run.timings.insert("fetch_ms".into(), ms(t));

        let may_build = matches!(mode, Mode::Install | Mode::Verify { build: true });
        if artifact.is_none() && may_build {
            let t = Instant::now();
            self.say(&format!("{}: building locally under Heddle ({})", meta.name, self.sandbox.describe()));
            ev.local_build_required = true;
            let wd = self.paths.cache.join("build").join(format!("{}-{}", meta.name, &checkout.commit[..8]));
            let logp = self.paths.cache.join("logs").join(format!("{}-{}.log", meta.name, version));
            let opts = BuildOptions {
                sandbox: self.sandbox.clone(),
                min_tier: self.min_tier(),
                allow_network,
                timeout: Duration::from_secs(3600),
            };
            let b = loom_thread::build::build(&self.backend, meta, &checkout, &wd, &Variation::standard()[0], &opts, &logp)?;
            ev.source_digest = Some(b.plan.source_digest);
            ev.unpinned = b.plan.unpinned.clone();
            let view = BuildView {
                tier: b.report.as_ref().map(|r| r.tier.as_str().to_string()).unwrap_or_else(|| "none".into()),
                layers: b.report.as_ref().map(|r| r.layers.clone()).unwrap_or_default(),
                reduced: b.report.as_ref().map(|r| r.reduced.clone()).unwrap_or_default(),
                denials: b
                    .report
                    .as_ref()
                    .map(|r| {
                        r.denials
                            .iter()
                            .map(|d| DenialView {
                                syscall: d.syscall.clone(),
                                resource: d.resource.clone(),
                                rule: d.rule.clone(),
                                requirement: d.requirement.clone(),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                exit_code: b.report.as_ref().map(|r| r.exit_code).unwrap_or(-1),
                success: b.digest.is_some(),
                setup_error: if b.report.is_none() && b.plan.unpinned.is_empty() { b.error.clone() } else { None },
                duration_ms: b.report.as_ref().map(|r| r.duration_ms).unwrap_or(0),
            };
            if b.plan.unpinned.is_empty() {
                ev.build = Some(view.clone());
                run.build = Some(view);
            }
            if let Some(a) = b.artifact {
                run.origin = Some(format!(
                    "local sandboxed build ({})",
                    b.report.as_ref().map(|r| r.tier.as_str()).unwrap_or("?")
                ));
                artifact = Some(a);
            }
            run.timings.insert("build_ms".into(), ms(t));
        }

        let t = Instant::now();
        if let Some(a) = &artifact {
            let digest = Digest::of(a);
            ev.candidate = Some(Candidate { digest, origin: run.origin.clone().unwrap_or_default() });
            let manifest = self.backend.inspect(a)?;
            ev.placement = Some(placement::analyse(&manifest, &eff.allow_placement));
            ev.install_script = Some(manifest.install_script.is_some());
        }
        let d = eval::evaluate(&self.policy, &ev);
        let _ = self.state.log_decision(&d);
        run.timings.insert("final_evaluate_ms".into(), ms(t));
        run.decision = d;
        run.artifact = artifact;
        Ok(run)
    }

    /// Install one evaluated package.
    pub fn commit_install(&self, run: &PackageRun, installer: &Installer, as_dep: bool) -> anyhow::Result<InstallOutcome> {
        let d = &run.decision;
        let mut out = InstallOutcome {
            package: run.meta.name.clone(),
            version: d.version.clone(),
            installed: false,
            origin: run.origin.clone(),
            decision: format!("{:?}", d.outcome),
            hook: None,
        };
        let Some(artifact) = &run.artifact else { return Ok(out) };
        if d.blocked() || d.stage != "pre-install" {
            return Ok(out);
        }
        let manifest = self.backend.inspect(artifact)?;
        let eff = &d.effective;
        let prev = self.state.installed()?;
        let previous = prev.get(&run.meta.name);
        let listed = self.policy.policy.install_script_allowlist.iter().any(|p| p == &run.meta.name);
        let run_hooks = manifest.install_script.is_some()
            && match eff.install_scripts {
                InstallScripts::Sandbox => true,
                InstallScripts::Deny => false,
                InstallScripts::Allowlist => listed,
            };
        let stripped = loom_aur::package::strip_install(artifact)?;
        let files = installer.install(
            &run.meta.name,
            &d.version,
            &stripped,
            previous.map(|p| p.files.as_slice()).unwrap_or(&[]),
            as_dep,
        )?;
        let mut hook_action = if manifest.install_script.is_some() { "skipped (policy)".to_string() } else { "none".to_string() };
        if run_hooks {
            let script = manifest.install_script.as_deref().unwrap_or_default();
            let func = if previous.is_some() { "post_upgrade" } else { "post_install" };
            let work = self.paths.cache.join("hooks").join(&run.meta.name);
            match run_install_hook(script, func, &d.version, &work, &self.sandbox, self.min_tier()) {
                Ok(Some(r)) => {
                    hook_action = format!(
                        "{func}() ran under Heddle ({}; exit {}; {} denial(s){})",
                        r.tier.as_str(),
                        r.exit_code,
                        r.denials.len(),
                        r.denials
                            .iter()
                            .map(|d| format!("; denied {} {} [{}]", d.syscall, d.resource, d.requirement))
                            .collect::<String>()
                    );
                }
                Ok(None) => hook_action = format!("no {func}() defined"),
                Err(e) => hook_action = format!("{func}() NOT run: sandbox unavailable ({e})"),
            }
        }
        out.hook = Some(hook_action.clone());
        if let Some(a) = &run.artifact {
            if self.policy.peer.serve_cache {
                let _ = self.cas().put(a);
            }
        }
        self.state.set_installed(Installed {
            name: run.meta.name.clone(),
            version: d.version.clone(),
            digest: Digest::of(artifact),
            installed_at: loom_core::time::now(),
            published: run.meta.last_modified,
            files,
            install_script: manifest.install_script.is_some(),
            install_script_action: hook_action,
            origin: run.origin.clone().unwrap_or_default(),
            independent_attestations: d.independent_support,
            outcome: format!("{:?}", d.outcome),
            as_dependency: as_dep,
        })?;
        self.state.set_baseline(Baseline {
            package: run.meta.name.clone(),
            version: d.version.clone(),
            maintainer: run.meta.maintainer.clone(),
            signing_keys: run.checkout.signing_keys.clone(),
            commit: run.checkout.commit.clone(),
            tags: run.checkout.tags.clone(),
            observed_at: loom_core::time::now(),
        })?;
        self.state.consume_continuity_override(&run.meta.name)?;
        out.installed = true;
        Ok(out)
    }

    pub fn installer(&self) -> Installer {
        match self.cfg.install.backend.as_str() {
            "pacman" => Installer::Pacman { pkg_cache: self.paths.cache.join("pkg") },
            _ => Installer::Root { root: PathBuf::from(self.cfg.install.root.clone().unwrap_or_default()) },
        }
    }
}
