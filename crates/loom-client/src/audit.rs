//! `loom audit` — read-only provenance report for an installation (SRS §5.10).
//!
//! Opens the client in read-only mode: the log mirror and checkpoint are
//! verified but not persisted, no baselines or install records are written,
//! no git mirrors are fetched (FR-10.2).

use crate::pipeline::Loom;
use loom_core::attest::Outcome as BO;
use loom_core::ecosystem::Backend as _;
use loom_weave::eval::{LogStatus, Override};
use loom_weave::independence::{independent_count, Witnessing};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AuditRow {
    pub name: String,
    pub version: String,
    pub source: String,
    pub digest: Option<String>,
    pub independent_attestations: usize,
    pub covered: bool,
    pub published: Option<i64>,
    pub age_days: Option<i64>,
    pub continuity: String,
    pub install_script: Option<bool>,
    pub install_script_action: Option<String>,
    pub exceptions: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AuditReport {
    pub generated_at: i64,
    pub log: String,
    pub required_attestations: u32,
    pub packages: Vec<AuditRow>,
    pub total: usize,
    pub covered: usize,
    pub coverage_percent: f64,
    pub overrides: Vec<Override>,
    pub notes: Vec<String>,
}

fn pacman_foreign() -> Vec<(String, String)> {
    std::process::Command::new("pacman")
        .arg("-Qm")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter_map(|l| l.split_once(' '))
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

pub fn audit(loom: &Loom) -> anyhow::Result<AuditReport> {
    assert!(loom.read_only, "audit must run read-only");
    let ctx = loom.context();
    let now = loom_core::time::now();
    let installed = loom.state.installed()?;
    let baselines = loom.state.baselines()?;
    let overrides = loom.state.overrides()?;
    let mut notes = vec![];

    let mut rows_src: Vec<(String, String, Option<loom_core::Digest>, &'static str)> = installed
        .values()
        .map(|i| (i.name.clone(), i.version.clone(), Some(i.digest), "loom"))
        .collect();
    for (n, v) in pacman_foreign() {
        if !installed.contains_key(&n) {
            rows_src.push((n, v, None, "pacman (foreign, not installed by loom)"));
        }
    }
    let names: Vec<String> = rows_src.iter().map(|r| r.0.clone()).collect();
    let metas = match loom.backend.resolve(&names) {
        Ok(m) => m,
        Err(e) => {
            notes.push(format!("AUR unreachable, continuity/age not refreshed: {e}"));
            vec![]
        }
    };

    let k = loom.policy.policy.required_attestations as usize;
    let mut rows = vec![];
    for (name, version, digest, source) in rows_src {
        let atts: Vec<_> = ctx
            .attestations
            .iter()
            .filter(|a| a.trusted && a.st.predicate.package == name && a.st.predicate.version == version)
            .filter(|a| !ctx.revoked.contains_key(&a.index))
            .filter(|a| a.st.predicate.outcome == BO::Reproducible)
            .filter(|a| digest.map(|d| a.st.predicate.artifact == Some(d)).unwrap_or(true))
            .collect();
        let w: Vec<Witnessing> = atts
            .iter()
            .map(|a| Witnessing { rebuilder: &a.st.predicate.rebuilder.id, org: &a.org, toolchain: &a.st.predicate.toolchain.id })
            .collect();
        let (n, _) = independent_count(&w);
        let meta = metas.iter().find(|m| m.name == name);
        let continuity = match (baselines.get(&name), meta) {
            (Some(b), Some(m)) if b.maintainer != m.maintainer => format!(
                "CHANGED: maintainer {} → {}",
                b.maintainer.as_deref().unwrap_or("(orphaned)"),
                m.maintainer.as_deref().unwrap_or("(orphaned)")
            ),
            (Some(_), Some(_)) => "unchanged since install".into(),
            (None, Some(_)) => "no baseline (not installed by loom)".into(),
            (_, None) => "unknown (not in AUR or AUR unreachable)".into(),
        };
        let inst = installed.get(&name);
        let mut exceptions: Vec<String> = overrides
            .iter()
            .filter(|o| o.package == name)
            .map(|o| format!("override #{} {} ({})", o.id, o.kind.as_str(), o.reason))
            .collect();
        if let Some(po) = loom.policy.package.get(&name) {
            if po.allow_network == Some(true) {
                exceptions.push("policy: build-time network allowed (FR-3.8)".into());
            }
            if !po.allow_placement.is_empty() {
                exceptions.push(format!("policy: placement allowed for {}", po.allow_placement.join(", ")));
            }
        }
        let published = meta.map(|m| m.last_modified).or(inst.map(|i| i.published));
        rows.push(AuditRow {
            name,
            version,
            source: source.into(),
            digest: digest.map(|d| d.to_string()),
            independent_attestations: n,
            covered: digest.is_some() && n >= k.max(1),
            published,
            age_days: published.map(|p| (now - p) / 86400),
            continuity,
            install_script: inst.map(|i| i.install_script),
            install_script_action: inst.map(|i| i.install_script_action.clone()),
            exceptions,
        });
    }
    let total = rows.len();
    let covered = rows.iter().filter(|r| r.covered).count();
    Ok(AuditReport {
        generated_at: now,
        log: match &ctx.log {
            LogStatus::Verified { size, witnesses, .. } => format!("verified (size {size}, witnesses: {})", witnesses.join(", ")),
            LogStatus::Unavailable(e) => format!("UNAVAILABLE: {e}"),
            LogStatus::Invalid(e) => format!("INVALID: {e}"),
            LogStatus::SplitView { detail, .. } => format!("SPLIT VIEW: {detail}"),
        },
        required_attestations: k as u32,
        packages: rows,
        total,
        covered,
        coverage_percent: if total == 0 { 100.0 } else { 100.0 * covered as f64 / total as f64 },
        overrides,
        notes,
    })
}

pub fn render(r: &AuditReport) -> String {
    let mut s = format!("Loom audit — {}\nlog: {}\n\n", loom_core::time::rfc3339(r.generated_at), r.log);
    s.push_str(&format!("{:<22} {:<14} {:>5} {:>6}  {:<8} {}\n", "PACKAGE", "VERSION", "ATTS", "AGE", "SCRIPTS", "CONTINUITY"));
    for p in &r.packages {
        s.push_str(&format!(
            "{:<22} {:<14} {:>3}{} {:>5}  {:<8} {}\n",
            trunc(&p.name, 22),
            trunc(&p.version, 14),
            p.independent_attestations,
            if p.covered { " ✓" } else { " ✗" },
            p.age_days.map(|d| format!("{d}d")).unwrap_or_else(|| "?".into()),
            match p.install_script {
                Some(true) => "yes",
                Some(false) => "no",
                None => "?",
            },
            trunc(&p.continuity, 30)
        ));
        for e in &p.exceptions {
            s.push_str(&format!("    exception: {e}\n"));
        }
        if let Some(a) = &p.install_script_action {
            if a != "none" {
                s.push_str(&format!("    install script: {}\n", trunc(a, 70)));
            }
        }
    }
    s.push_str(&format!(
        "\nprovenance coverage: {}/{} packages ({:.0}%) have >= {} independent attestation(s) for the installed artifact\n",
        r.covered, r.total, r.coverage_percent, r.required_attestations.max(1)
    ));
    for n in &r.notes {
        s.push_str(&format!("note: {n}\n"));
    }
    s
}

fn trunc(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}
