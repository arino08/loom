//! The trust decision (SRS §5.6, §5.7, §5.8, §5.11).
//!
//! [`evaluate`] is a pure function from (policy, evidence) to a [`Decision`].
//! It evaluates *every* rule and reports every violation (FR-6.5); each
//! failing rule carries its evidence and a remediation (FR-11.2,
//! NFR-USE-2). No rule ever produces an unexplained failure (FR-11.4).

use crate::advisory;
use crate::continuity::{self, Kind, Source, Violation};
use crate::independence::{independent_count, Witnessing};
use crate::placement::{Finding, Severity};
use crate::policy::{Action, Effective, InstallScripts, OnContinuity, PlacementAction, Policy};
use loom_core::attest::Outcome as BuildOutcomeKind;
use loom_core::digest::Digest;
use loom_core::duration::human;
use loom_core::time::rfc3339;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Revoked {
    pub index: u64,
    pub by: String,
    pub reason: String,
}

/// One attestation relevant to the package, after client-side verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationView {
    pub index: u64,
    pub rebuilder: String,
    pub org: String,
    pub toolchain: String,
    pub toolchain_image: String,
    pub sandbox_tier: String,
    pub outcome: BuildOutcomeKind,
    pub artifact: Option<Digest>,
    pub version: String,
    pub commit: String,
    pub source_digest: Digest,
    pub timestamp: i64,
    pub observed_maintainer: Option<String>,
    /// Signature verified against the trust-root key for this rebuilder id.
    pub trusted: bool,
    /// `Ok(how)` if the inclusion proof verified, `Err(why)` otherwise.
    pub inclusion: Result<String, String>,
    pub revoked: Option<Revoked>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LogStatus {
    Verified {
        size: u64,
        witnesses: Vec<String>,
        cross_checked: Vec<String>,
        notes: Vec<String>,
    },
    Unavailable(String),
    Invalid(String),
    SplitView {
        detail: String,
        evidence: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OverrideKind {
    Quarantine,
    Continuity,
    Attestations,
    SandboxNetwork,
    Placement,
}

impl OverrideKind {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        Ok(match s {
            "quarantine" => Self::Quarantine,
            "continuity" => Self::Continuity,
            "attestations" => Self::Attestations,
            "sandbox-network" => Self::SandboxNetwork,
            "placement" => Self::Placement,
            _ => anyhow::bail!("unknown override kind {s:?} (quarantine, continuity, attestations, sandbox-network, placement)"),
        })
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Quarantine => "quarantine",
            Self::Continuity => "continuity",
            Self::Attestations => "attestations",
            Self::SandboxNetwork => "sandbox-network",
            Self::Placement => "placement",
        }
    }
    /// Whether the override must name a specific version (FR-7.2).
    pub fn needs_version(&self) -> bool {
        matches!(self, Self::Quarantine | Self::Attestations)
    }
}

/// A persistent, user-authorised exception (FR-3.8, FR-7.2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Override {
    pub id: u64,
    pub kind: OverrideKind,
    pub package: String,
    pub version: Option<String>,
    pub reason: String,
    pub created_at: i64,
    pub user: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DenialView {
    pub syscall: String,
    pub resource: String,
    pub rule: String,
    pub requirement: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildView {
    pub tier: String,
    pub layers: Vec<String>,
    pub reduced: Vec<String>,
    pub denials: Vec<DenialView>,
    pub exit_code: i32,
    pub success: bool,
    pub setup_error: Option<String>,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Candidate {
    pub digest: Digest,
    /// "peer <url>" or "local sandboxed build".
    pub origin: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub package: String,
    pub version: String,
    pub commit: String,
    pub source_digest: Option<Digest>,
    pub maintainer: Option<String>,
    pub published: i64,
    pub now: i64,
    pub log: LogStatus,
    pub attestations: Vec<AttestationView>,
    pub continuity: Vec<Violation>,
    pub had_baseline: bool,
    pub advisory: Option<advisory::Match>,
    pub advisory_error: Option<String>,
    pub unpinned: Vec<String>,
    pub candidate: Option<Candidate>,
    pub local_build_required: bool,
    pub build: Option<BuildView>,
    pub placement: Option<Vec<Finding>>,
    pub install_script: Option<bool>,
    pub overrides: Vec<Override>,
    pub sandbox_backend: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pass,
    Info,
    Overridden,
    Warn,
    Fail,
}

impl Status {
    pub fn tag(&self) -> &'static str {
        match self {
            Status::Pass => " ok ",
            Status::Info => "info",
            Status::Overridden => "OVRD",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleResult {
    pub id: String,
    pub requirement: String,
    pub title: String,
    pub status: Status,
    pub summary: String,
    pub evidence: Vec<String>,
    pub remediation: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allow,
    AllowWithWarnings,
    Block,
}

#[derive(Clone, Debug, Serialize)]
pub struct Decision {
    pub package: String,
    pub version: String,
    pub stage: String,
    pub outcome: Outcome,
    pub rules: Vec<RuleResult>,
    pub effective: Effective,
    /// The artifact digest the decision is about (candidate or consensus).
    pub target: Option<Digest>,
    pub independent_support: usize,
    pub timestamp: i64,
}

impl Decision {
    pub fn blocked(&self) -> bool {
        self.outcome == Outcome::Block
    }
    pub fn rule(&self, id: &str) -> Option<&RuleResult> {
        self.rules.iter().find(|r| r.id == id)
    }
}

fn find_override<'a>(ev: &'a Evidence, kind: OverrideKind) -> Option<&'a Override> {
    ev.overrides.iter().find(|o| {
        o.kind == kind
            && o.package == ev.package
            && o.version.as_deref().map(|v| v == ev.version).unwrap_or(true)
    })
}

/// Whether a sandbox denial reveals hostile intent: a read of the user's
/// home/credentials (FR-3.2) or network use (FR-3.4) without an exception.
/// Mirrors `loom_heddle::Denial::is_hostile`.
pub fn is_hostile_denial(requirement: &str, network_allowed: bool) -> bool {
    match requirement {
        "FR-3.2" => true,
        "FR-3.4" => !network_allowed,
        _ => false,
    }
}

fn rr(id: &str, req: &str, title: &str, status: Status, summary: String) -> RuleResult {
    RuleResult {
        id: id.into(),
        requirement: req.into(),
        title: title.into(),
        status,
        summary,
        evidence: vec![],
        remediation: None,
    }
}

/// Group usable reproducible attestations by artifact digest and compute
/// independent support for each.
fn support(atts: &[&AttestationView]) -> BTreeMap<Digest, (usize, Vec<String>)> {
    let mut by: BTreeMap<Digest, Vec<&AttestationView>> = BTreeMap::new();
    for a in atts {
        if a.outcome == BuildOutcomeKind::Reproducible {
            if let Some(d) = a.artifact {
                by.entry(d).or_default().push(a);
            }
        }
    }
    by.into_iter()
        .map(|(d, xs)| {
            let w: Vec<Witnessing> = xs
                .iter()
                .map(|a| Witnessing { rebuilder: &a.rebuilder, org: &a.org, toolchain: &a.toolchain })
                .collect();
            let (n, chosen) = independent_count(&w);
            (d, (n, chosen.into_iter().map(|i| xs[i].rebuilder.clone()).collect()))
        })
        .collect()
}

pub fn evaluate(policy: &Policy, ev: &Evidence) -> Decision {
    let mut eff = policy.effective(&ev.package);
    let mut rules = vec![];
    let pkg = &ev.package;
    let ver = &ev.version;

    // ---------------------------------------------------------- continuity
    // Evaluated first: an escalation changes k and min_age for later rules.
    {
        let mut r = rr("continuity", "FR-8.x", "publishing-authority continuity", Status::Pass, String::new());
        if ev.continuity.is_empty() {
            r.summary = if ev.had_baseline {
                "maintainer, signing keys and commit lineage unchanged since last install".into()
            } else {
                "no local baseline; transparency-log history shows no recent change of authority".into()
            };
        } else {
            let ov = find_override(ev, OverrideKind::Continuity);
            for v in &ev.continuity {
                r.evidence.push(format!(
                    "[{}] {}: {} → {}{}{} (source: {})",
                    v.kind.requirement(),
                    v.kind.describe(),
                    v.prior,
                    v.current,
                    v.prior_observed.map(|t| format!("; prior value last seen {}", rfc3339(t))).unwrap_or_default(),
                    v.changed_at.map(|t| format!("; change first observed {}", rfc3339(t))).unwrap_or_default(),
                    match v.source {
                        Source::LocalBaseline => "this machine's install record",
                        Source::TransparencyLog => "rebuilder observations in the transparency log",
                    }
                ));
            }
            let kinds: Vec<&str> = ev.continuity.iter().map(|v| v.kind.describe()).collect();
            if let Some(o) = ov {
                r.status = Status::Overridden;
                r.summary = format!("{} — accepted by override #{} ({})", kinds.join("; "), o.id, o.reason);
            } else {
                match eff.on_continuity_change {
                    OnContinuity::Block => {
                        r.status = Status::Fail;
                        r.summary = format!("{} — policy on_continuity_change = block", kinds.join("; "));
                    }
                    OnContinuity::Escalate => {
                        policy.escalate(&mut eff);
                        r.status = Status::Warn;
                        r.summary = format!(
                            "{} — escalated: now requires {} attestations and {} quarantine",
                            kinds.join("; "),
                            eff.required_attestations,
                            human(eff.min_age)
                        );
                    }
                    OnContinuity::Warn => {
                        r.status = Status::Warn;
                        r.summary = kinds.join("; ");
                    }
                }
                if ev.continuity.iter().any(|v| matches!(v.kind, Kind::MaintainerChanged | Kind::OrphanAdopted)) {
                    r.remediation = Some(format!(
                        "review the new maintainer's changes (loom explain {pkg}), then if you trust them: \
                         loom override add continuity {pkg} --reason \"reviewed new maintainer\""
                    ));
                } else {
                    r.remediation = Some(format!(
                        "inspect the recipe history; if the rewrite is legitimate: loom override add continuity {pkg} --reason \"...\""
                    ));
                }
            }
        }
        rules.push(r);
    }

    // ---------------------------------------------------------- log
    let log_ok = matches!(ev.log, LogStatus::Verified { .. });
    {
        let mut r = rr("log", "FR-5.5–5.7", "transparency log (Warp)", Status::Pass, String::new());
        match &ev.log {
            LogStatus::Verified { size, witnesses, cross_checked, notes } => {
                r.summary = format!(
                    "checkpoint size {size} verified; cosigned by {} witness(es): {}",
                    witnesses.len(),
                    witnesses.join(", ")
                );
                if !cross_checked.is_empty() {
                    r.evidence.push(format!("consistent with the views of: {}", cross_checked.join(", ")));
                }
                r.evidence.extend(notes.iter().cloned());
            }
            LogStatus::Unavailable(e) => {
                r.status = Status::Warn;
                r.summary = "log unreachable (and no gossip peer had a copy): no attestation evidence; \
                             on_insufficient_attestations decides (NFR-REL-2)"
                    .into();
                r.evidence.push(e.clone());
            }
            LogStatus::Invalid(e) => {
                r.status = Status::Fail;
                r.summary = "log failed verification — refusing to trust any evidence from it (NFR-SEC-1)".into();
                r.evidence.push(e.clone());
                r.remediation = Some("do not override: report to the log and witness operators".into());
            }
            LogStatus::SplitView { detail, evidence } => {
                r.status = Status::Fail;
                r.summary = "SPLIT VIEW: the log is presenting inconsistent histories (NFR-SEC-5)".into();
                r.evidence.push(detail.clone());
                if let Some(p) = evidence {
                    r.evidence.push(format!("proof of misbehaviour saved to {p}"));
                }
                r.remediation = Some("do not override: publish the saved evidence to the witness operators".into());
            }
        }
        rules.push(r);
    }

    // ---------------------------------------------------------- attestations
    let relevant: Vec<&AttestationView> = ev
        .attestations
        .iter()
        .filter(|a| a.version == *ver && a.commit == ev.commit)
        .collect();
    let mut notes = vec![];
    let mut usable: Vec<&AttestationView> = vec![];
    for a in &relevant {
        if !a.trusted {
            notes.push(format!("#{} {}: not signed by a trusted rebuilder key — ignored", a.index, a.rebuilder));
        } else if let Err(e) = &a.inclusion {
            notes.push(format!("#{} {}: inclusion proof failed ({e}) — ignored", a.index, a.rebuilder));
        } else if let Some(rv) = &a.revoked {
            notes.push(format!(
                "#{} {}: REVOKED by {} in log record #{} ({}) (FR-5.8/5.9)",
                a.index, a.rebuilder, rv.by, rv.index, rv.reason
            ));
        } else if let (Some(sd), false) = (ev.source_digest, a.source_digest == ev.source_digest.unwrap_or(a.source_digest)) {
            notes.push(format!(
                "#{} {}: built from different inputs ({} ≠ local {}) — ignored",
                a.index,
                a.rebuilder,
                a.source_digest.short(),
                sd.short()
            ));
        } else {
            usable.push(a);
        }
    }
    for a in &usable {
        if a.outcome != BuildOutcomeKind::Reproducible {
            notes.push(format!(
                "#{} {}: {:?} — could not reproduce its own build; counts neither for nor against (ASM-5)",
                a.index, a.rebuilder, a.outcome
            ));
        }
    }
    let sup = support(&usable);
    let target = match &ev.candidate {
        Some(c) => Some(c.digest),
        None => sup.iter().max_by_key(|(_, (n, _))| *n).map(|(d, _)| *d),
    };
    let target_support = target.and_then(|t| sup.get(&t).cloned()).unwrap_or((0, vec![]));
    let describe = |a: &AttestationView| {
        format!(
            "#{} {} (org {}, toolchain {} [{}], sandbox {}): {}{}",
            a.index,
            a.rebuilder,
            a.org,
            a.toolchain,
            a.toolchain_image,
            a.sandbox_tier,
            match (&a.outcome, &a.artifact) {
                (BuildOutcomeKind::Reproducible, Some(d)) => format!("reproduced {}", d.short()),
                (o, _) => format!("{o:?}"),
            },
            a.inclusion.as_ref().map(|h| format!(", inclusion verified via {h}")).unwrap_or_default()
        )
    };
    {
        let k = eff.required_attestations as usize;
        let (n, who) = &target_support;
        let mut r = rr("attestations", "FR-6.1/6.2", "independent reproducible-build attestations", Status::Pass, String::new());
        for a in &usable {
            r.evidence.push(describe(a));
        }
        r.evidence.extend(notes.iter().cloned());
        let raw = usable
            .iter()
            .filter(|a| a.outcome == BuildOutcomeKind::Reproducible && a.artifact == target)
            .count();
        if raw > *n {
            r.evidence.push(format!(
                "{raw} attestations agree but only {n} are independent (shared organisation or identical toolchain count once)"
            ));
        }
        let tgt = target.map(|d| d.short()).unwrap_or_else(|| "(none)".into());
        if *n >= k {
            r.summary = format!("{n} independent attestation(s) for artifact {tgt} (required: {k}) — {}", who.join(", "));
        } else {
            let base = format!(
                "only {n} independent attestation(s) for artifact {tgt}; policy requires {k}{}",
                if eff.escalated { " (escalated)" } else { "" }
            );
            if let Some(o) = find_override(ev, OverrideKind::Attestations) {
                r.status = Status::Overridden;
                r.summary = format!("{base} — accepted by override #{} ({})", o.id, o.reason);
            } else {
                match eff.on_insufficient_attestations {
                    Action::Block => {
                        r.status = Status::Fail;
                        r.summary = format!("{base}; on_insufficient_attestations = block");
                    }
                    Action::Warn => {
                        r.status = Status::Warn;
                        r.summary = format!("{base}; proceeding (on_insufficient_attestations = warn)");
                    }
                    Action::Allow => {
                        r.status = Status::Info;
                        r.summary = format!("{base}; allowed by policy");
                    }
                }
                r.remediation = Some(format!(
                    "wait for rebuilders to attest this version, or: loom override add attestations {pkg} {ver} --reason \"...\""
                ));
            }
        }
        rules.push(r);
    }
    {
        // FR-6.4: any contradicting reproducible attestation blocks.
        let mut r = rr("contradiction", "FR-6.4", "no contradicting attestation", Status::Pass, String::new());
        let contra: Vec<&&AttestationView> = usable
            .iter()
            .filter(|a| a.outcome == BuildOutcomeKind::Reproducible && a.artifact.is_some())
            .filter(|a| match target {
                Some(t) => a.artifact != Some(t),
                None => false,
            })
            .collect();
        let distinct: std::collections::BTreeSet<Digest> = sup.keys().copied().collect();
        if !contra.is_empty() {
            r.status = Status::Fail;
            r.summary = format!(
                "{} rebuilder(s) reproducibly built a DIFFERENT artifact from the same source — \
                 the artifact does not correspond to its published source (ADV-4)",
                contra.len()
            );
            for a in contra {
                r.evidence.push(describe(a));
            }
            if let Some(t) = target {
                r.evidence.push(format!("artifact under evaluation (sha256): {}", t.hex()));
            }
            r.remediation = Some(
                "not overridable. Investigate the divergence; an erroneous attestation must be revoked in the log (CON-3), after which the decision is re-evaluated".into(),
            );
        } else if target.is_none() && distinct.len() > 1 {
            r.status = Status::Fail;
            r.summary = "rebuilders disagree on the artifact built from this source".into();
        } else {
            r.summary = "no rebuilder reported a different artifact for this source".into();
        }
        rules.push(r);
    }

    // ---------------------------------------------------------- quarantine
    {
        let age = Duration::from_secs((ev.now - ev.published).max(0) as u64);
        let mut r = rr("quarantine", "FR-7.x", "temporal quarantine", Status::Pass, String::new());
        r.evidence.push(format!("published {} ({} ago)", rfc3339(ev.published), human(age)));
        if age >= eff.min_age {
            r.summary = format!("published {} ago (min_age {})", human(age), human(eff.min_age));
        } else if let (true, Some(m)) = (policy.advisory.fast_path, &ev.advisory) {
            r.summary = format!(
                "within quarantine but EXEMPT: remediates {} ({} severity; fixed in {}; {}) (FR-7.3)",
                m.group,
                m.severity,
                m.fixed,
                m.issues.join(", ")
            );
        } else if let Some(o) = find_override(ev, OverrideKind::Quarantine) {
            r.status = Status::Overridden;
            r.summary = format!("within quarantine; released by override #{} ({})", o.id, o.reason);
        } else {
            let left = eff.min_age - age;
            r.status = Status::Fail;
            r.summary = format!(
                "version published {} ago; quarantine is {}{} — {} remaining (until {})",
                human(age),
                human(eff.min_age),
                if eff.escalated { " (escalated)" } else { "" },
                human(left),
                rfc3339(ev.published + eff.min_age.as_secs() as i64)
            );
            if let Some(e) = &ev.advisory_error {
                r.evidence.push(format!("advisory feed unavailable: {e}"));
            }
            r.remediation = Some(format!(
                "wait, or after reviewing the change: loom override add quarantine {pkg} {ver} --reason \"...\""
            ));
        }
        rules.push(r);
    }

    // ---------------------------------------------------------- sources
    {
        let mut r = rr("sources", "FR-3.5", "all build inputs pinned by hash", Status::Pass, String::new());
        if ev.unpinned.is_empty() {
            r.summary = "every declared input is pinned and was hash-verified before the build".into();
        } else if !ev.local_build_required {
            r.status = Status::Info;
            r.summary = "recipe has unpinned inputs, but no local build is needed (attested artifact substituted)".into();
            r.evidence = ev.unpinned.clone();
        } else {
            r.status = Status::Fail;
            r.summary = "the recipe declares inputs Loom cannot verify; builds never fetch from the network".into();
            r.evidence = ev.unpinned.clone();
            r.remediation = Some("ask the maintainer to pin checksums (not SKIP) and use release tarballs instead of VCS sources".into());
        }
        rules.push(r);
    }

    // ---------------------------------------------------------- sandbox
    {
        let mut r = rr("sandbox", "FR-3.x", "build confinement (Heddle)", Status::Pass, String::new());
        match &ev.build {
            None if !ev.local_build_required && ev.candidate.is_some() => {
                r.summary = "no recipe code executed on this machine: attested artifact substituted".into();
            }
            None => {
                r.status = Status::Info;
                r.summary = format!("not built yet (sandbox backend: {})", ev.sandbox_backend);
            }
            Some(b) => {
                r.evidence.extend(b.layers.iter().cloned());
                for d in &b.denials {
                    r.evidence.push(format!("denied {} {} — rule {} ({})", d.syscall, d.resource, d.rule, d.requirement));
                }
                r.evidence.extend(b.reduced.iter().map(|x| format!("reduced assurance: {x}")));
                let net_ok = find_override(ev, OverrideKind::SandboxNetwork).is_some() || eff.allow_network;
                let hostile: Vec<&DenialView> = b.denials.iter().filter(|d| is_hostile_denial(&d.requirement, net_ok)).collect();
                if let Some(e) = &b.setup_error {
                    r.status = Status::Fail;
                    r.summary = format!("sandbox could not be established — build refused (NFR-SEC-1): {e}");
                    r.remediation = Some("enable Landlock (Linux >= 5.13) and unprivileged user namespaces; see docs/SANDBOX.md".into());
                } else if !hostile.is_empty() {
                    // Contained, but a build that reached for credentials or
                    // the network is not trusted, even if it exited 0 (a
                    // payload wrapped in `|| true`). Fail closed.
                    let mut what: Vec<&str> = hostile
                        .iter()
                        .map(|d| if d.requirement == "FR-3.4" { "the network" } else { "home/credential files" })
                        .collect();
                    what.dedup();
                    r.status = Status::Fail;
                    r.summary = format!(
                        "build tried to reach {} — contained by Heddle, artifact rejected (exit {}; {} hostile access attempt(s))",
                        what.join(" and "),
                        b.exit_code,
                        hostile.len()
                    );
                    r.remediation = Some(if hostile.iter().all(|d| d.requirement == "FR-3.4") {
                        format!("if this package legitimately needs the network at build time: loom override add sandbox-network {pkg} --reason \"...\" (FR-3.8)")
                    } else {
                        "credential access is never granted to a build; treat this version as malicious and report it".into()
                    });
                } else if !b.success {
                    r.status = Status::Fail;
                    r.summary = format!(
                        "build failed under confinement (exit {}; {} denied access attempt(s))",
                        b.exit_code,
                        b.denials.len()
                    );
                    if b.denials.iter().any(|d| d.requirement == "FR-3.4") {
                        r.remediation = Some(format!(
                            "the build tried to use the network. If that is legitimate: loom override add sandbox-network {pkg} --reason \"...\" (FR-3.8)"
                        ));
                    } else {
                        r.remediation = Some("inspect the build log; access outside the build directory is never granted".into());
                    }
                } else if b.tier == "unconfined-demo" {
                    r.status = Status::Warn;
                    r.summary = "DEMO BACKEND: build ran WITHOUT kernel confinement".into();
                } else if b.tier == "reduced" {
                    r.status = Status::Warn;
                    r.summary = format!("built under reduced confinement (Landlock + seccomp; {} denial(s))", b.denials.len());
                } else {
                    r.summary = format!("built under full confinement ({} denial(s) logged)", b.denials.len());
                }
                if net_ok {
                    r.evidence.push("network exception in effect for this package (FR-3.8; listed by loom audit)".into());
                }
            }
        }
        rules.push(r);
    }

    // ---------------------------------------------------------- placement
    {
        let mut r = rr("placement", "audit A4", "installed files do not create persistence or privilege", Status::Pass, String::new());
        match &ev.placement {
            None => {
                r.status = Status::Info;
                r.summary = "artifact not yet available for inspection".into();
            }
            Some(f) => {
                let crit: Vec<&Finding> = f.iter().filter(|x| x.severity == Severity::Critical).collect();
                for x in f {
                    r.evidence.push(format!("{} — {}", x.path, x.reason));
                }
                if crit.is_empty() {
                    r.summary = "no sensitive install locations".into();
                } else if let Some(o) = find_override(ev, OverrideKind::Placement) {
                    r.status = Status::Overridden;
                    r.summary = format!("{} sensitive path(s) accepted by override #{} ({})", crit.len(), o.id, o.reason);
                } else {
                    r.status = match policy.policy.placement {
                        PlacementAction::Block => Status::Fail,
                        PlacementAction::Warn => Status::Warn,
                    };
                    r.summary = format!("package installs {} file(s) into privileged execution paths", crit.len());
                    r.remediation = Some(format!(
                        "if intended: loom override add placement {pkg} --reason \"...\" or allow specific paths in [package.{pkg}] allow_placement"
                    ));
                }
            }
        }
        rules.push(r);
    }

    // ---------------------------------------------------------- install scripts
    {
        let mut r = rr("install-scripts", "FR-9.2", "install-time scripts", Status::Pass, String::new());
        match ev.install_script {
            None => {
                r.status = Status::Info;
                r.summary = "unknown until the artifact is available".into();
            }
            Some(false) => r.summary = "package ships no install script".into(),
            Some(true) => {
                let listed = policy.policy.install_script_allowlist.iter().any(|p| p == pkg);
                r.status = Status::Info;
                r.summary = match eff.install_scripts {
                    InstallScripts::Sandbox => "install script will run inside Heddle, never as root under pacman".into(),
                    InstallScripts::Deny => "install script will be SKIPPED (install_scripts = deny)".into(),
                    InstallScripts::Allowlist if listed => "install script allow-listed: will run inside Heddle".into(),
                    InstallScripts::Allowlist => "install script not allow-listed: will be SKIPPED".into(),
                };
            }
        }
        rules.push(r);
    }

    let outcome = if rules.iter().any(|r| r.status == Status::Fail) {
        Outcome::Block
    } else if rules.iter().any(|r| r.status == Status::Warn || r.status == Status::Overridden) {
        Outcome::AllowWithWarnings
    } else {
        Outcome::Allow
    };
    let _ = log_ok;
    Decision {
        package: pkg.clone(),
        version: ver.clone(),
        stage: if ev.candidate.is_some() { "pre-install".into() } else { "pre-build".into() },
        outcome,
        rules,
        effective: eff,
        target,
        independent_support: target_support.0,
        timestamp: ev.now,
    }
}

/// Log observations for continuity, from all attestations of a package.
pub fn observations(atts: &[AttestationView]) -> Vec<continuity::LogObservation> {
    atts.iter()
        .filter(|a| a.trusted && a.inclusion.is_ok())
        .map(|a| continuity::LogObservation {
            version: a.version.clone(),
            commit: a.commit.clone(),
            maintainer: a.observed_maintainer.clone(),
            timestamp: a.timestamp,
        })
        .collect()
}

// ------------------------------------------------------------------ render

fn wrap(s: &str, width: usize, indent: &str) -> String {
    let mut out = String::new();
    let mut line = String::new();
    for w in s.split_whitespace() {
        if !line.is_empty() && line.len() + 1 + w.len() > width {
            out.push_str(indent);
            out.push_str(&line);
            out.push('\n');
            line.clear();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(w);
    }
    if !line.is_empty() {
        out.push_str(indent);
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// Plain-text rendering, legible at 80 columns without colour (NFR-USE-4).
pub fn render(d: &Decision, verbose: bool) -> String {
    let verdict = match d.outcome {
        Outcome::Allow => "ALLOWED",
        Outcome::AllowWithWarnings => "ALLOWED WITH WARNINGS",
        Outcome::Block => "BLOCKED",
    };
    let mut s = format!("{} {} — {} ({})\n", d.package, d.version, verdict, d.stage);
    for r in &d.rules {
        let show = verbose || matches!(r.status, Status::Fail | Status::Warn | Status::Overridden);
        if !show {
            continue;
        }
        s.push_str(&format!("  [{}] {} ({})\n", r.status.tag(), r.title, r.requirement));
        s.push_str(&wrap(&r.summary, 70, "         "));
        if verbose || r.status == Status::Fail {
            for e in &r.evidence {
                s.push_str(&wrap(&format!("- {e}"), 68, "           "));
            }
        }
        if let Some(fix) = &r.remediation {
            if r.status == Status::Fail || verbose {
                s.push_str(&wrap(&format!("fix: {fix}"), 70, "         "));
            }
        }
    }
    if !verbose {
        let ok = d.rules.iter().filter(|r| matches!(r.status, Status::Pass | Status::Info)).count();
        s.push_str(&format!("  ({ok} other check(s) passed; `loom explain {}` for the full derivation)\n", d.package));
    }
    s
}
