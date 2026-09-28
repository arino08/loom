//! A labelled corpus of package scenarios, each rendered as a Weave
//! [`Evidence`] so the policy engine can be exercised deterministically and
//! offline. Malicious entries model the 2026 incident classes; benign entries
//! model the kinds of legitimate package that stress each mechanism (a fresh
//! release, a legitimate maintainer handover, a package that ships a system
//! service, ...), to measure false positives.

use loom_core::attest::Outcome as O;
use loom_core::digest::Digest;
use loom_weave::continuity::{Kind, Source, Violation};
use loom_weave::eval::*;
use loom_weave::placement::{Finding, Severity};

pub const H: i64 = 3600;
pub const DAY: i64 = 86400;
pub const NOW: i64 = 1_800_000_000;

/// Which incident class an entry represents (for the traceability report).
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Benign,
    OrphanAdoption,
    ForcePush,
    MaintainerCompromise,
    BuildInjection,
    CredentialHarvest,
    TamperedArtifact,
    PlacementPersistence,
    PthHook,
    Worm,
}

pub struct Entry {
    pub name: &'static str,
    pub malicious: bool,
    #[allow(dead_code)]
    pub class: Class,
    pub incident: &'static str,
    pub evidence: Evidence,
}

fn att(rb: &str, org: &str, tc: &str, d: Option<&[u8]>, i: u64) -> AttestationView {
    AttestationView {
        index: i,
        rebuilder: rb.into(),
        org: org.into(),
        toolchain: tc.into(),
        toolchain_image: "img".into(),
        sandbox_tier: "full".into(),
        outcome: if d.is_some() { O::Reproducible } else { O::Unreproducible },
        artifact: d.map(Digest::of),
        version: "1.0-1".into(),
        commit: "c1".into(),
        source_digest: Digest::of(b"src"),
        timestamp: NOW - 90 * DAY,
        observed_maintainer: Some("alice".into()),
        trusted: true,
        inclusion: Ok("log".into()),
        revoked: None,
    }
}

/// k independent, agreeing attestations for the given artifact.
fn attested(d: &[u8]) -> Vec<AttestationView> {
    vec![
        att("ra", "o1", "t1", Some(d), 1),
        att("rb", "o2", "t2", Some(d), 2),
        att("rc", "o3", "t3", Some(d), 3),
    ]
}

fn base(name: &'static str) -> Evidence {
    let art = Digest::of(name.as_bytes());
    Evidence {
        package: name.into(),
        version: "1.0-1".into(),
        commit: "c1".into(),
        source_digest: Some(Digest::of(b"src")),
        maintainer: Some("alice".into()),
        published: NOW - 30 * DAY,
        now: NOW,
        log: LogStatus::Verified { size: 100, witnesses: vec!["w1".into(), "w2".into()], cross_checked: vec!["w1".into(), "w2".into()], notes: vec![] },
        attestations: attested(name.as_bytes()),
        continuity: vec![],
        had_baseline: true,
        advisory: None,
        advisory_error: None,
        unpinned: vec![],
        candidate: Some(Candidate { digest: art, origin: "peer".into() }),
        local_build_required: false,
        build: None,
        placement: Some(vec![]),
        install_script: Some(false),
        overrides: vec![],
        sandbox_backend: "kernel".into(),
    }
}

fn clean_build() -> BuildView {
    BuildView { tier: "full".into(), layers: vec!["namespaces+landlock+seccomp".into()], reduced: vec![], denials: vec![], exit_code: 0, success: true, setup_error: None, duration_ms: 900 }
}

fn denied_build(denials: Vec<DenialView>) -> BuildView {
    BuildView { tier: "full".into(), layers: vec!["namespaces+landlock+seccomp".into()], reduced: vec![], denials, exit_code: 1, success: false, setup_error: None, duration_ms: 900 }
}

/// The evasive variant: the payload is wrapped in `|| true`, so the build
/// exits 0 and yields an artifact despite the denials. Must still be blocked.
fn tolerant_build(denials: Vec<DenialView>) -> BuildView {
    BuildView { exit_code: 0, success: true, ..denied_build(denials) }
}

fn net_denial() -> DenialView {
    DenialView { syscall: "socket".into(), resource: "AF_INET".into(), rule: "deny-network".into(), requirement: "FR-3.4".into() }
}
fn home_denial() -> DenialView {
    DenialView { syscall: "openat".into(), resource: "/root/.ssh/id_ed25519".into(), rule: "deny-home-and-credentials".into(), requirement: "FR-3.2".into() }
}

fn maint_change(kind: Kind, prior: &str, cur: &str) -> Violation {
    Violation { kind, source: Source::LocalBaseline, prior: prior.into(), current: cur.into(), prior_observed: Some(NOW - 20 * DAY), changed_at: Some(NOW - 2 * DAY) }
}

pub fn corpus() -> Vec<Entry> {
    let mut v: Vec<Entry> = vec![];

    // -------- malicious --------
    // 1. Orphan adoption (Atomic Arch / July–Aug AUR waves).
    let mut e = base("orphan-adopted");
    e.continuity = vec![maint_change(Kind::OrphanAdopted, "(orphaned)", "mallory")];
    e.maintainer = Some("mallory".into());
    v.push(Entry { name: "orphan-adopted", malicious: true, class: Class::OrphanAdoption, incident: "Atomic Arch orphan adoption (Jun–Aug 2026)", evidence: e });

    // 2. Force-push / history rewrite (TeamPCP).
    let mut e = base("history-rewritten");
    e.continuity = vec![maint_change(Kind::HistoryRewritten, "commit c1", "commit evil")];
    v.push(Entry { name: "history-rewritten", malicious: true, class: Class::ForcePush, incident: "TeamPCP 110+ tags force-pushed (Mar 2026)", evidence: e });

    // 3. Maintainer-account compromise → build-time network injection (npm-in-PKGBUILD).
    let mut e = base("npm-injection");
    e.attestations = vec![]; // no rebuilder can reproduce a network build
    e.candidate = None;
    e.local_build_required = true;
    e.build = Some(denied_build(vec![net_denial()]));
    v.push(Entry { name: "npm-injection", malicious: true, class: Class::BuildInjection, incident: "Atomic Arch npm install in PKGBUILD", evidence: e });

    // 4. Credential harvest at build time (Shai-Hulud / ChainDrop). The
    //    payload swallows its own errors, so the build exits 0 and yields
    //    an artifact: the denials alone must block it.
    let mut e = base("cred-harvest");
    e.attestations = vec![];
    e.candidate = Some(Candidate { digest: Digest::of(b"harvested-build"), origin: "local sandboxed build (full)".into() });
    e.local_build_required = true;
    e.build = Some(tolerant_build(vec![home_denial(), net_denial()]));
    v.push(Entry { name: "cred-harvest", malicious: true, class: Class::CredentialHarvest, incident: "Shai-Hulud / ChainDrop credential harvest (Aug 2026)", evidence: e });

    // 5. Self-propagating worm (harvest + publish). Same containment as (4);
    //    the worm cannot use harvested creds because none are reachable.
    let mut e = base("worm");
    e.attestations = vec![];
    e.candidate = None;
    e.local_build_required = true;
    e.build = Some(denied_build(vec![home_denial(), net_denial()]));
    v.push(Entry { name: "worm", malicious: true, class: Class::Worm, incident: "Shai-Hulud self-propagation", evidence: e });

    // 6. Tampered artifact: signed & hash-verifies but not from source (LiteLLM/Axios).
    //    One honest rebuilder reproduces the true artifact; the tampered one
    //    is a reproducible build of a DIFFERENT digest → contradiction (FR-6.4).
    let mut e = base("tampered-artifact");
    let good = b"good-build";
    let evil = b"tampered-build";
    e.candidate = Some(Candidate { digest: Digest::of(evil), origin: "peer".into() });
    e.attestations = vec![
        att("ra", "o1", "t1", Some(good), 1),
        att("rb", "o2", "t2", Some(good), 2),
        att("evilci", "compromised", "t9", Some(evil), 9),
    ];
    v.push(Entry { name: "tampered-artifact", malicious: true, class: Class::TamperedArtifact, incident: "Axios CI bypass / LiteLLM (Mar 2026)", evidence: e });

    // 7. Fresh malicious version, not yet independently rebuilt (Mastra: 140
    //    packages in 19 minutes). Temporal quarantine holds it.
    let mut e = base("fresh-malicious");
    e.published = NOW - 30 * 60; // 30 minutes old
    e.attestations = vec![];
    e.candidate = None;
    e.local_build_required = true;
    e.build = Some(clean_build()); // even a "clean-looking" build is quarantined
    v.push(Entry { name: "fresh-malicious", malicious: true, class: Class::MaintainerCompromise, incident: "Mastra 140 packages in 19 min (2026)", evidence: e });

    // 8. Persistence via a pacman hook (placement).
    let mut e = base("alpm-hook");
    e.placement = Some(vec![Finding { path: "/usr/share/libalpm/hooks/zz.hook".into(), severity: Severity::Critical, reason: "pacman hook runs as root".into() }]);
    v.push(Entry { name: "alpm-hook", malicious: true, class: Class::PlacementPersistence, incident: "post-install persistence", evidence: e });

    // 9. Python .pth startup hook (LiteLLM .pth).
    let mut e = base("pth-hook");
    e.placement = Some(vec![Finding { path: "/usr/lib/python3/site-packages/x.pth".into(), severity: Severity::Critical, reason: ".pth import hook".into() }]);
    v.push(Entry { name: "pth-hook", malicious: true, class: Class::PthHook, incident: "LiteLLM .pth (Mar 2026)", evidence: e });

    // -------- benign (false-positive stress) --------
    // b1. Ordinary well-established package.
    v.push(Entry { name: "hello", malicious: false, class: Class::Benign, incident: "-", evidence: base("hello") });

    // b2. A legitimate maintainer handover that was reviewed: the user has an
    //     override on file (should NOT block).
    let mut e = base("handover-ok");
    e.continuity = vec![maint_change(Kind::MaintainerChanged, "alice", "trusted-bob")];
    e.overrides = vec![Override { id: 1, kind: OverrideKind::Continuity, package: "handover-ok".into(), version: None, reason: "reviewed handover".into(), created_at: NOW, user: "u".into() }];
    v.push(Entry { name: "handover-ok", malicious: false, class: Class::Benign, incident: "legitimate handover (reviewed)", evidence: e });

    // b3. A security update within quarantine but on the advisory fast-path.
    let mut e = base("secfix");
    e.published = NOW - H;
    e.advisory = Some(loom_weave::advisory::Match { group: "AVG-1".into(), severity: "High".into(), fixed: "1.0-1".into(), issues: vec!["CVE-2026-1".into()] });
    v.push(Entry { name: "secfix", malicious: false, class: Class::Benign, incident: "security release (advisory fast-path)", evidence: e });

    // b4. A package that legitimately ships a (not-enabled) systemd service:
    //     a NOTICE, not a block.
    let mut e = base("with-service");
    e.placement = Some(vec![Finding { path: "/usr/lib/systemd/system/foo.service".into(), severity: Severity::Notice, reason: "ships a service".into() }]);
    v.push(Entry { name: "with-service", malicious: false, class: Class::Benign, incident: "ships a system service", evidence: e });

    // b5. A locally-built package with clean confinement and full attestations.
    let mut e = base("built-clean");
    e.local_build_required = true;
    e.build = Some(clean_build());
    e.candidate = Some(Candidate { digest: Digest::of(b"built-clean"), origin: "local".into() });
    e.attestations = attested(b"built-clean");
    v.push(Entry { name: "built-clean", malicious: false, class: Class::Benign, incident: "reproducible local build", evidence: e });

    // b6. A package that ships an install script (runs sandboxed): not a block.
    let mut e = base("with-install-script");
    e.install_script = Some(true);
    v.push(Entry { name: "with-install-script", malicious: false, class: Class::Benign, incident: "benign install script", evidence: e });

    // b7. A package with a setuid helper the user explicitly allowed.
    let mut e = base("setuid-allowed");
    e.placement = Some(vec![Finding { path: "/usr/bin/helper".into(), severity: Severity::Critical, reason: "setuid".into() }]);
    e.overrides = vec![Override { id: 1, kind: OverrideKind::Placement, package: "setuid-allowed".into(), version: None, reason: "known setuid helper".into(), created_at: NOW, user: "u".into() }];
    v.push(Entry { name: "setuid-allowed", malicious: false, class: Class::Benign, incident: "allowed setuid helper", evidence: e });

    v
}
