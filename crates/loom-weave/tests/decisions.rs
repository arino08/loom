//! Decision-engine tests, including property-style sweeps over policy
//! configurations (SRS §8.1, FR-6.x).

use loom_core::attest::Outcome as O;
use loom_core::digest::Digest;
use loom_weave::continuity::{Kind, Source, Violation};
use loom_weave::eval::*;
use loom_weave::policy::{Policy, DEFAULT_POLICY};

const H: i64 = 3600;
const NOW: i64 = 1_800_000_000;

fn att(i: u64, rb: &str, org: &str, tc: &str, d: Option<&[u8]>) -> AttestationView {
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
        timestamp: NOW - 100 * H,
        observed_maintainer: Some("alice".into()),
        trusted: true,
        inclusion: Ok("log".into()),
        revoked: None,
    }
}

fn ev(atts: Vec<AttestationView>) -> Evidence {
    Evidence {
        package: "hello".into(),
        version: "1.0-1".into(),
        commit: "c1".into(),
        source_digest: None,
        maintainer: Some("alice".into()),
        published: NOW - 200 * H,
        now: NOW,
        log: LogStatus::Verified { size: 10, witnesses: vec!["w1".into(), "w2".into()], cross_checked: vec![], notes: vec![] },
        attestations: atts,
        continuity: vec![],
        had_baseline: false,
        advisory: None,
        advisory_error: None,
        unpinned: vec![],
        candidate: None,
        local_build_required: false,
        build: None,
        placement: Some(vec![]),
        install_script: Some(false),
        overrides: vec![],
        sandbox_backend: "kernel".into(),
    }
}

fn good3() -> Vec<AttestationView> {
    vec![
        att(1, "a", "oa", "t1", Some(b"good")),
        att(2, "b", "ob", "t2", Some(b"good")),
        att(3, "c", "oc", "t3", Some(b"good")),
    ]
}

fn pol() -> Policy {
    Policy::default_policy()
}

#[test]
fn healthy_package_allowed() {
    let d = evaluate(&pol(), &ev(good3()));
    assert_eq!(d.outcome, Outcome::Allow, "{}", render(&d, true));
    assert_eq!(d.target, Some(Digest::of(b"good")));
    assert_eq!(d.independent_support, 3);
}

#[test]
fn contradiction_blocks_regardless_of_majority() {
    // FR-6.4: 3 agree, 1 reproducible dissenter.
    let mut a = good3();
    a.push(att(4, "ci", "upstream", "t4", Some(b"evil")));
    let d = evaluate(&pol(), &ev(a));
    assert!(d.blocked());
    assert_eq!(d.rule("contradiction").unwrap().status, Status::Fail);
    assert!(d.rule("contradiction").unwrap().remediation.as_ref().unwrap().contains("not overridable"));
}

#[test]
fn revocation_removes_contradiction() {
    let mut a = good3();
    let mut bad = att(4, "ci", "upstream", "t4", Some(b"evil"));
    bad.revoked = Some(Revoked { index: 9, by: "loom-security".into(), reason: "tampered CI".into() });
    a.push(bad);
    let d = evaluate(&pol(), &ev(a));
    assert_eq!(d.outcome, Outcome::Allow, "{}", render(&d, true));
}

#[test]
fn unreproducible_rebuilders_neither_support_nor_contradict() {
    let a = vec![att(1, "a", "oa", "t1", None), att(2, "b", "ob", "t2", None)];
    let d = evaluate(&pol(), &ev(a));
    assert_eq!(d.rule("contradiction").unwrap().status, Status::Pass);
    assert_eq!(d.rule("attestations").unwrap().status, Status::Warn); // default: warn
}

#[test]
fn correlated_toolchains_counted_once() {
    // FR-6.2: two attestations sharing a toolchain + k=2 → insufficient.
    let a = vec![att(1, "a", "oa", "t1", Some(b"g")), att(2, "b", "ob", "t1", Some(b"g"))];
    let text = DEFAULT_POLICY.replace("on_insufficient_attestations = \"warn\"", "on_insufficient_attestations = \"block\"");
    let d = evaluate(&Policy::parse(&text).unwrap(), &ev(a));
    assert!(d.blocked());
    assert_eq!(d.independent_support, 1);
}

#[test]
fn untrusted_or_unproven_attestations_ignored() {
    let mut a = good3();
    a[0].trusted = false;
    a[1].inclusion = Err("bad proof".into());
    let d = evaluate(&pol(), &ev(a));
    assert_eq!(d.independent_support, 1);
}

#[test]
fn quarantine_and_exemption_and_override() {
    let mut e = ev(good3());
    e.published = NOW - 2 * H;
    let d = evaluate(&pol(), &e);
    assert!(d.blocked());
    let q = d.rule("quarantine").unwrap();
    assert!(q.summary.contains("70h remaining") || q.summary.contains("2d 22h"), "{}", q.summary);

    e.advisory = Some(loom_weave::advisory::Match { group: "AVG-1".into(), severity: "High".into(), fixed: "1.0-1".into(), issues: vec!["CVE-1".into()] });
    assert_eq!(evaluate(&pol(), &e).outcome, Outcome::Allow);

    e.advisory = None;
    e.overrides.push(Override { id: 1, kind: OverrideKind::Quarantine, package: "hello".into(), version: Some("1.0-1".into()), reason: "reviewed".into(), created_at: NOW, user: "u".into() });
    let d = evaluate(&pol(), &e);
    assert_eq!(d.outcome, Outcome::AllowWithWarnings);
    // An override for another version does not apply.
    e.overrides[0].version = Some("0.9-1".into());
    assert!(evaluate(&pol(), &e).blocked());
}

#[test]
fn continuity_block_escalate_warn() {
    let v = Violation { kind: Kind::OrphanAdopted, source: Source::TransparencyLog, prior: "(orphaned)".into(), current: "mallory".into(), prior_observed: Some(NOW - 50 * H), changed_at: Some(NOW - 30 * H) };
    let mut e = ev(good3());
    e.continuity = vec![v];
    assert!(evaluate(&pol(), &e).blocked());

    let esc = Policy::parse(&DEFAULT_POLICY.replace("on_continuity_change         = \"block\"", "on_continuity_change = \"escalate\"")).unwrap();
    let d = evaluate(&esc, &e);
    assert_eq!(d.effective.required_attestations, 3);
    // published 200h ago > escalated 168h, 3 independent attestations: allowed with warning.
    assert_eq!(d.outcome, Outcome::AllowWithWarnings, "{}", render(&d, true));
    e.attestations.pop();
    assert_eq!(evaluate(&esc, &e).rule("attestations").unwrap().status, Status::Warn);
}

#[test]
fn log_failures_fail_closed_but_unavailability_degrades() {
    let mut e = ev(good3());
    e.log = LogStatus::SplitView { detail: "x".into(), evidence: None };
    assert!(evaluate(&pol(), &e).blocked());
    e.log = LogStatus::Invalid("bad sig".into());
    assert!(evaluate(&pol(), &e).blocked());
    e.log = LogStatus::Unavailable("down".into());
    e.attestations.clear();
    let d = evaluate(&pol(), &e);
    assert_eq!(d.outcome, Outcome::AllowWithWarnings, "NFR-REL-2: policy decision, not error");
}

#[test]
fn every_failure_is_explained() {
    // FR-11.2/11.4: sweep a grid of scenarios; every Fail must carry a summary
    // and either a remediation or evidence.
    let actions = ["block", "warn", "allow"];
    let conts = ["block", "escalate", "warn"];
    for a in actions {
        for c in conts {
            for k in [0u32, 1, 2, 3, 5] {
                let text = DEFAULT_POLICY
                    .replace("on_insufficient_attestations = \"warn\"", &format!("on_insufficient_attestations = \"{a}\""))
                    .replace("on_continuity_change         = \"block\"", &format!("on_continuity_change = \"{c}\""))
                    .replace("required_attestations        = 2", &format!("required_attestations = {k}"));
                let text = if k > 3 { text.replace("required_attestations = 3", &format!("required_attestations = {k}")) } else { text };
                let p = Policy::parse(&text).unwrap();
                for scenario in 0..6 {
                    let mut e = ev(good3());
                    match scenario {
                        1 => e.published = NOW - H,
                        2 => e.attestations.push(att(9, "x", "ox", "tx", Some(b"evil"))),
                        3 => e.continuity.push(Violation { kind: Kind::HistoryRewritten, source: Source::LocalBaseline, prior: "a".into(), current: "b".into(), prior_observed: None, changed_at: None }),
                        4 => e.attestations.clear(),
                        5 => e.placement = Some(vec![loom_weave::placement::Finding { path: "/etc/ld.so.preload".into(), severity: loom_weave::placement::Severity::Critical, reason: "x".into() }]),
                        _ => {}
                    }
                    let d = evaluate(&p, &e);
                    // Property: adding a contradicting attestation always blocks.
                    if scenario == 2 {
                        assert!(d.blocked());
                    }
                    // Property: outcome is Block iff some rule failed.
                    assert_eq!(d.blocked(), d.rules.iter().any(|r| r.status == Status::Fail));
                    for r in &d.rules {
                        if r.status == Status::Fail {
                            assert!(!r.summary.is_empty());
                            assert!(r.remediation.is_some() || !r.evidence.is_empty(), "unexplained failure in {}", r.id);
                        }
                    }
                    // Property: the rendered output fits 80 columns.
                    for line in render(&d, true).lines() {
                        assert!(line.chars().count() <= 80 || !line.contains(' '), "too wide: {line}");
                    }
                }
            }
        }
    }
}

fn local_build(denials: &[(&str, &str)], success: bool) -> BuildView {
    BuildView {
        tier: "full".into(),
        layers: vec![],
        reduced: vec![],
        denials: denials
            .iter()
            .map(|(req, res)| DenialView { syscall: "x".into(), resource: (*res).into(), rule: "r".into(), requirement: (*req).into() })
            .collect(),
        exit_code: if success { 0 } else { 1 },
        success,
        setup_error: None,
        duration_ms: 1,
    }
}

fn locally_built(b: BuildView) -> Evidence {
    let mut e = ev(vec![]);
    e.local_build_required = true;
    e.candidate = Some(Candidate { digest: Digest::of(b"local"), origin: "local".into() });
    e.build = Some(b);
    e
}

fn sandbox_status(d: &Decision) -> Status {
    d.rules.iter().find(|r| r.id == "sandbox").unwrap().status
}

#[test]
fn hostile_denials_fail_closed_even_when_build_exits_zero() {
    // `curl ... || true` / `cat ~/.ssh/id_* || true`: the build "succeeds".
    for req in ["FR-3.2", "FR-3.4"] {
        let d = evaluate(&pol(), &locally_built(local_build(&[(req, "probe")], true)));
        assert_eq!(sandbox_status(&d), Status::Fail, "{req}: {}", render(&d, true));
        assert_eq!(d.outcome, Outcome::Block);
    }
    // Incidental denials (undeclared reads, restricted syscalls) are logged only.
    let d = evaluate(&pol(), &locally_built(local_build(&[("FR-3.1", "/etc/x"), ("FR-3.6", "ptrace")], true)));
    assert_eq!(sandbox_status(&d), Status::Pass, "{}", render(&d, true));
}

#[test]
fn network_exception_makes_network_denials_non_hostile_but_not_credentials() {
    let mut e = locally_built(local_build(&[("FR-3.4", "AF_INET")], true));
    e.overrides.push(Override { id: 1, kind: OverrideKind::SandboxNetwork, package: "hello".into(), version: None, reason: "needs npm".into(), created_at: NOW, user: "u".into() });
    assert_eq!(sandbox_status(&evaluate(&pol(), &e)), Status::Pass);
    let mut e2 = e.clone();
    e2.build = Some(local_build(&[("FR-3.2", "/root/.ssh/id_ed25519")], true));
    assert_eq!(sandbox_status(&evaluate(&pol(), &e2)), Status::Fail);
}
