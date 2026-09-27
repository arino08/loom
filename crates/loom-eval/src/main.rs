//! Loom evaluation harness (SRS §8, experiments E1–E6).
//!
//! Runs offline against the Weave policy engine and Warp log primitives, so
//! the acceptance criteria can be checked deterministically in CI. The live
//! attack replay and build-compatibility experiments (E1 end-to-end, E3) are
//! demonstrated by `demo/run.sh` against the full deployment.

mod corpus;

use corpus::{corpus, Entry};
use loom_core::keys::SecretKey;
use loom_warp::notes;
use loom_warp::tree::{verify_consistency, Tree};
use loom_weave::eval::{evaluate, Decision, Status};
use loom_weave::Policy;
use std::collections::BTreeMap;
use std::time::Instant;

/// The enforcement mechanisms, identified by the rule id Weave emits.
const MECHANISMS: &[(&str, &str)] = &[
    ("continuity", "publishing-authority continuity (§5.8)"),
    ("quarantine", "temporal quarantine (§5.7)"),
    ("attestations", "k-of-n independent reproducible builds (§5.6)"),
    ("contradiction", "artifact/source correspondence (FR-6.4)"),
    ("sandbox", "build confinement (§5.3)"),
    ("placement", "install placement policy (audit A4)"),
    ("log", "transparency-log integrity (§5.5)"),
];

fn blocking_rules(d: &Decision) -> Vec<String> {
    d.rules.iter().filter(|r| r.status == Status::Fail).map(|r| r.id.clone()).collect()
}

/// Map a rule id to its mechanism name (the rule id, if it is one of the
/// enforcement mechanisms).
fn mech_of(rule: &str) -> Option<&'static str> {
    MECHANISMS.iter().find(|(id, _)| *id == rule).map(|(id, _)| *id)
}

fn main() {
    let json = std::env::args().any(|a| a == "--json");
    let policy = Policy::default_policy();
    let entries = corpus();
    let mut report = serde_json::Map::new();

    // ---- E1 attack replay (AC-1) + E2 false positives (AC-2) ----
    let decisions: Vec<(&Entry, Decision)> =
        entries.iter().map(|e| (e, evaluate(&policy, &e.evidence))).collect();
    let mal_total = decisions.iter().filter(|(e, _)| e.malicious).count();
    let ben_total = decisions.iter().filter(|(e, _)| !e.malicious).count();
    let mal_blocked = decisions.iter().filter(|(e, d)| e.malicious && d.blocked()).count();
    let ben_blocked = decisions.iter().filter(|(e, d)| !e.malicious && d.blocked()).count();
    let ac1 = 100.0 * mal_blocked as f64 / mal_total.max(1) as f64;
    let ac2 = 100.0 * ben_blocked as f64 / ben_total.max(1) as f64;

    if !json {
        h("E1 — Attack replay (AC-1: ≥90% of malicious blocked before payload)");
        for (e, d) in decisions.iter().filter(|(e, _)| e.malicious) {
            let rules = blocking_rules(d);
            println!(
                "  {:<20} {:<9} caught by [{}]   ⟵ {}",
                e.name,
                if d.blocked() { "BLOCKED" } else { "MISSED!" },
                rules.join(", "),
                e.incident
            );
        }
        println!("  → {mal_blocked}/{mal_total} malicious blocked = {ac1:.0}%  {}", pass(ac1 >= 90.0));

        h("E2 — False positives (AC-2: ≤5% spurious blocks on benign packages)");
        for (e, d) in decisions.iter().filter(|(e, _)| !e.malicious) {
            println!(
                "  {:<20} {:<9} {}",
                e.name,
                if d.blocked() { "BLOCKED!" } else { "allowed" },
                e.incident
            );
        }
        println!("  → {ben_blocked}/{ben_total} benign blocked = {ac2:.0}%  {}", pass(ac2 <= 5.0));
    }
    report.insert("E1_attack_replay".into(), serde_json::json!({"malicious": mal_total, "blocked": mal_blocked, "percent": ac1, "ac1_pass": ac1 >= 90.0}));
    report.insert("E2_false_positives".into(), serde_json::json!({"benign": ben_total, "blocked": ben_blocked, "percent": ac2, "ac2_pass": ac2 <= 5.0}));

    // ---- E4 ablation (AC-4: no single mechanism accounts for all detections) ----
    let mut catch: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut sole: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (e, d) in decisions.iter().filter(|(e, _)| e.malicious) {
        if !d.blocked() {
            continue;
        }
        let rules = blocking_rules(d);
        for r in &rules {
            if let Some(m) = mech_of(r) {
                catch.entry(m).or_default().push(e.name);
            }
        }
        if rules.len() == 1 {
            if let Some(m) = mech_of(&rules[0]) {
                sole.entry(m).or_default().push(e.name);
            }
        }
    }
    let max_single = catch.values().map(|v| v.len()).max().unwrap_or(0);
    let ac4 = max_single < mal_blocked && catch.len() > 1;
    if !json {
        h("E4 — Ablation (AC-4: no single mechanism catches everything)");
        for (id, desc) in MECHANISMS.iter() {
            let n = catch.get(id).map(|v| v.len()).unwrap_or(0);
            let empty: Vec<&str> = vec![];
            let s = sole.get(id).unwrap_or(&empty);
            if n == 0 {
                continue;
            }
            println!("  {:<14} catches {n:>2}/{}   {}", id, mal_blocked, desc);
            if !s.is_empty() {
                println!("                 └─ sole catcher for: {}", s.join(", "));
            }
        }
        println!(
            "  → best single mechanism catches {max_single}/{mal_blocked}; detections are distributed across {} mechanisms  {}",
            catch.len(),
            pass(ac4)
        );
    }
    report.insert("E4_ablation".into(), serde_json::json!({
        "best_single_mechanism_catches": max_single,
        "total_malicious_blocked": mal_blocked,
        "mechanisms_used": catch.len(),
        "sole_catchers": sole.iter().map(|(k, v)| (k.to_string(), v.clone())).collect::<BTreeMap<_,_>>(),
        "ac4_pass": ac4,
    }));

    // ---- E5 overhead (AC-5 proxy: NFR-PERF-1 < 500ms, NFR-PERF-3 < 100ms) ----
    let sample = &entries[0].evidence;
    let iters = 2000;
    let t = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(evaluate(&policy, std::hint::black_box(sample)));
    }
    let eval_us = t.elapsed().as_micros() as f64 / iters as f64;

    let k = SecretKey::generate();
    let rec = loom_core::attest::sign_rebuild(sample_pred(), &k).unwrap();
    let pk = k.public();
    let t = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(loom_core::attest::verify_rebuild(std::hint::black_box(&rec), &pk).ok());
    }
    let verify_us = t.elapsed().as_micros() as f64 / iters as f64;
    if !json {
        h("E5 — Overhead (NFR-PERF-1 <500ms decision, NFR-PERF-3 <100ms/attestation)");
        println!("  policy decision:          {:.3} ms  {}", eval_us / 1000.0, pass(eval_us / 1000.0 < 500.0));
        println!("  attestation verification: {:.3} ms  {}", verify_us / 1000.0, pass(verify_us / 1000.0 < 100.0));
    }
    report.insert("E5_overhead".into(), serde_json::json!({
        "policy_decision_ms": eval_us / 1000.0,
        "attestation_verify_ms": verify_us / 1000.0,
        "nfr_perf_1_pass": eval_us / 1000.0 < 500.0,
        "nfr_perf_3_pass": verify_us / 1000.0 < 100.0,
    }));

    // ---- E6 log integrity (AC-6: split view detected in 100% of trials) ----
    let trials = 200;
    let detected = (0..trials).filter(|i| split_view_detected(*i)).count();
    let ac6 = detected == trials;
    if !json {
        h("E6 — Log integrity (AC-6: split view detected in 100% of trials, ≥2 honest witnesses)");
        println!("  split views detected: {detected}/{trials}  {}", pass(ac6));
        println!("  (the networked version, with live witnesses, is in loom-warp's e2e test and demo scenario 8)");
    }
    report.insert("E6_log_integrity".into(), serde_json::json!({"trials": trials, "detected": detected, "ac6_pass": ac6}));

    let all_pass = ac1 >= 90.0 && ac2 <= 5.0 && ac4 && eval_us / 1000.0 < 500.0 && verify_us / 1000.0 < 100.0 && ac6;
    if json {
        report.insert("all_acceptance_criteria_pass".into(), serde_json::json!(all_pass));
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        h("Summary");
        println!("  AC-1 attack replay      {}", pass(ac1 >= 90.0));
        println!("  AC-2 false positives    {}", pass(ac2 <= 5.0));
        println!("  AC-4 ablation           {}", pass(ac4));
        println!("  AC-5 overhead           {}", pass(eval_us / 1000.0 < 500.0 && verify_us / 1000.0 < 100.0));
        println!("  AC-6 log integrity      {}", pass(ac6));
        println!("  (AC-3 build compatibility and AC-7 requirement coverage: see demo/run.sh and docs/TRACEABILITY.md)");
        println!("\n  {}", if all_pass { "ALL CHECKED ACCEPTANCE CRITERIA PASS" } else { "SOME CRITERIA FAILED" });
    }
    if !all_pass {
        std::process::exit(1);
    }
}

fn sample_pred() -> loom_core::attest::RebuildPredicate {
    use loom_core::attest::*;
    let d = loom_core::digest::Digest::of(b"a");
    RebuildPredicate {
        ecosystem: "aur".into(),
        package: "p".into(),
        version: "1.0-1".into(),
        source: SourceRef { repo: "r".into(), commit: "c".into(), digest: loom_core::digest::Digest::of(b"s") },
        outcome: Outcome::Reproducible,
        artifact: Some(d),
        variant_digests: vec![d, d],
        rebuilder: RebuilderRef { id: "ra".into(), org: "o1".into() },
        toolchain: Toolchain::new("img", BTreeMap::new(), "full"),
        observed: Observed { maintainer: Some("alice".into()), last_modified: 0 },
        timestamp: 0,
        disputes: vec![],
    }
}

/// A minimal in-process split view: the log signs two size-N checkpoints with
/// different roots; a client that has seen one detects the other as
/// inconsistent (no consistency proof can link equal-size, different roots).
fn split_view_detected(seed: usize) -> bool {
    let logk = SecretKey::generate();
    let origin = "eval/warp";
    let mut a = Tree::new();
    let mut b = Tree::new();
    for i in 0..(3 + seed % 5) {
        a.append(format!("real-{i}").into_bytes()).unwrap();
        b.append(format!("real-{i}").into_bytes()).unwrap();
    }
    // Divergent leaf at the same position → same size, different root.
    a.append(format!("A-{seed}").into_bytes()).unwrap();
    b.append(format!("B-{seed}").into_bytes()).unwrap();
    let na = notes::sign_checkpoint(origin, a.size(), a.root(), &logk).unwrap();
    let nb = notes::sign_checkpoint(origin, b.size(), b.root(), &logk).unwrap();
    let ca = notes::open_checkpoint(&na, origin, &logk.public()).unwrap();
    let cb = notes::open_checkpoint(&nb, origin, &logk.public()).unwrap();
    // Both validly signed by the log, equal size, different roots → the
    // client's consistency check must reject (this is the split view).
    ca.size == cb.size && ca.root != cb.root && verify_consistency(&[], ca.size, ca.root, cb.size, cb.root).is_err()
}

fn h(t: &str) {
    println!("\n\x1b[1m{t}\x1b[0m\n{}", "─".repeat(t.len().min(72)));
}
fn pass(b: bool) -> &'static str {
    if b { "\x1b[32m✓ PASS\x1b[0m" } else { "\x1b[31m✗ FAIL\x1b[0m" }
}
