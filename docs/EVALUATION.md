# Loom — Evaluation

The SRS defines six experiments (E1–E6) mapped to seven acceptance criteria
(AC-1...AC-7). Loom exercises them two ways: the **live demo** (`demo/run.sh`)
runs the real deployment through the incident scenarios, and the **offline
harness** (`cargo run -p loom-eval`) checks the acceptance criteria
deterministically against the policy engine and log primitives, so they can run
in CI without the network stack.

## Running

```sh
cargo run -p loom-eval            # human-readable, exits non-zero on failure
cargo run -p loom-eval -- --json  # machine-readable for CI
demo/run.sh                       # the full live deployment, all scenarios
```

## Experiments

### E1 — Attack replay (AC-1: >= 90 % of malicious blocked before payload)

A labelled corpus (`loom-eval/corpus.rs`) renders each 2026 incident class as a
Weave `Evidence` object. The harness evaluates each and confirms it is blocked,
and — because the decision is computed *before* the artifact is obtained — that
the block happens *before payload execution*. The live version is demo scenarios
3–7: each attack is refused, and scenario 7 additionally shows the sandbox
denying the payload's `$HOME` read and network attempt.

### E2 — False positives (AC-2: <= 5 % spurious blocks on benign packages)

The corpus includes benign packages that stress each mechanism: a fresh security
release (advisory fast-path), a *reviewed* maintainer handover (override on
file), a package that ships a system service (a NOTICE, not a block), an allowed
setuid helper, a benign install script. None is blocked.

### E3 — Build compatibility (AC-3: measured and taxonomised)

Build compatibility under confinement is a property of the real build sandbox,
so it is measured by the live demo rather than the offline harness. The demo
builds the fixtures under the full/reduced tier; `divergent-bin` is the
taxonomy's canonical "non-reproducible" case (embeds a timestamp -> rebuilders
disagree -> never reaches *k*). Per the SRS note on AC-3, a low compatibility
figure is not a failure — the requirement is that it is measured and its causes
taxonomised (network-dependent builds, non-determinism, undeclared inputs).

### E4 — Ablation (AC-4: no single mechanism accounts for all detections)

For each blocked attack the harness records *which* mechanism(s) flagged it, then
reports the coverage matrix and the "sole catcher" for each attack caught by
exactly one mechanism. The result is that detections are distributed across
continuity, quarantine, contradiction, the sandbox and placement — no single
mechanism catches everything, so no single bypass is catastrophic.

### E5 — Overhead (AC-5: NFR-PERF-1 < 500 ms decision, NFR-PERF-3 < 100 ms/attestation)

Micro-benchmarks of the policy decision and Ed25519 attestation verification.
Both are far under target (a decision is tens of microseconds; a verification is
tens of microseconds), so the non-build overhead of an install is dominated by
network round-trips, not computation.

### E6 — Log integrity (AC-6: split view detected in 100 % of trials, >= 2 honest witnesses)

The harness runs many trials in which a log signs two equal-size checkpoints
with different roots and confirms the client's consistency check rejects every
one. The *networked* version — a real log in split-view mode with a corrupt
witness, honest witnesses refusing to cosign the fork, and the victim client
detecting it — is `loom-warp`'s `split_view_detected_with_honest_witnesses`
integration test and demo scenario 8.

### AC-7 — Must-priority coverage

Every Must-priority requirement is implemented and verified; see
[docs/TRACEABILITY.md](TRACEABILITY.md), which maps each to its code and test.

## Interpreting the demo's sandbox contrast (the headline result)

```
network sink hits:  confined=0   unconfined=1
HIT ... marker=loom-probe&pkg=npm-helper&stage=npm-install
```

The *same* malicious build, run under Heddle and then unconfined against a local
canary sink: confined it cannot read `$HOME` or reach the network (0 hits);
unconfined it does (1 hit). This is the empirical core of the containment claim
— the sandbox is not asserted to work, it is shown denying the payload.
