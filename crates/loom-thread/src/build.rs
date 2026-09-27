//! Building a package under Heddle. Shared by rebuilders and by the client's
//! local-build fallback, so both run exactly the same pipeline.

use loom_core::digest::Digest;
use loom_core::ecosystem::{Backend, BuildPlan, Checkout, PackageMeta};
use loom_heddle::{Backend as Sandbox, RunReport, SandboxSpec, Tier};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

/// Environment variation for reproducibility checking (reprotest-style).
#[derive(Clone, Debug)]
pub struct Variation {
    pub name: String,
    pub env: BTreeMap<String, String>,
}

impl Variation {
    pub fn standard() -> [Variation; 2] {
        let a = BTreeMap::from([
            ("TZ".to_string(), "UTC".to_string()),
            ("LANG".to_string(), "C.UTF-8".to_string()),
            ("LOOM_UMASK".to_string(), "022".to_string()),
        ]);
        let b = BTreeMap::from([
            ("TZ".to_string(), "Pacific/Chatham".to_string()),
            ("LANG".to_string(), "fr_CH.UTF-8".to_string()),
            ("LC_ALL".to_string(), "fr_CH.UTF-8".to_string()),
            ("LOOM_UMASK".to_string(), "002".to_string()),
            ("LOOM_VARIATION_NOISE".to_string(), "b".to_string()),
        ]);
        [
            Variation { name: "a".into(), env: a },
            Variation { name: "b".into(), env: b },
        ]
    }
}

pub struct Built {
    pub plan: BuildPlan,
    pub report: Option<RunReport>,
    pub artifact: Option<Vec<u8>>,
    pub digest: Option<Digest>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct BuildOptions {
    pub sandbox: Sandbox,
    pub min_tier: Tier,
    pub allow_network: bool,
    pub timeout: Duration,
}

/// Prepare inputs, run the build in Heddle, package the result.
/// Unpinned inputs abort before any recipe code runs.
pub fn build(
    backend: &dyn Backend,
    meta: &PackageMeta,
    checkout: &Checkout,
    workdir: &Path,
    variation: &Variation,
    opts: &BuildOptions,
    log_path: &Path,
) -> anyhow::Result<Built> {
    let plan = backend.prepare_build(checkout, meta, workdir)?;
    if !plan.unpinned.is_empty() {
        return Ok(Built {
            plan,
            report: None,
            artifact: None,
            digest: None,
            error: Some("unpinned inputs".into()),
        });
    }
    let mut spec = SandboxSpec::new(&plan.workdir, plan.argv.clone());
    spec.env = plan.env.clone();
    spec.env.extend(variation.env.clone());
    spec.min_tier = opts.min_tier;
    spec.allow_network = opts.allow_network;
    spec.timeout = opts.timeout;
    spec.log_path = Some(log_path.to_path_buf());
    let report = match loom_heddle::run(&spec, &opts.sandbox) {
        Ok(r) => r,
        Err(e) => {
            return Ok(Built {
                plan,
                report: None,
                artifact: None,
                digest: None,
                error: Some(e.to_string()),
            })
        }
    };
    if !report.success() {
        return Ok(Built {
            plan,
            report: Some(report),
            artifact: None,
            digest: None,
            error: Some("build failed".into()),
        });
    }
    let artifact = backend.package(&plan, meta)?;
    let digest = Digest::of(&artifact);
    Ok(Built {
        plan,
        report: Some(report),
        artifact: Some(artifact),
        digest: Some(digest),
        error: None,
    })
}

/// Versions of the tools that shape build output (FR-4.5).
pub fn detect_components() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for (name, args) in [
        ("bash", vec!["--version"]),
        ("gcc", vec!["-dumpfullversion"]),
        ("ld", vec!["--version"]),
        ("tar", vec!["--version"]),
        ("make", vec!["--version"]),
    ] {
        if let Ok(o) = std::process::Command::new(name).args(&args).output() {
            if o.status.success() {
                let first = String::from_utf8_lossy(&o.stdout).lines().next().unwrap_or("").trim().to_string();
                m.insert(name.to_string(), first);
            }
        }
    }
    m
}
