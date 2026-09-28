# Loom

**A decentralised, verifying package manager for the Arch User Repository.**

Loom installs AUR packages under an *enforceable trust policy*. It replaces
`yay`/`paru`/`makepkg` at the point of installation and requires no cooperation
from the AUR, from maintainers, or from upstream — a hard constraint, because
the attacks it defends against (the June–August 2026 AUR orphan-adoption waves,
Shai-Hulud/ChainDrop, the Atomic Arch and LiteLLM incidents) exploit packages
that have *no active maintainer*.

This repository is a working, demonstrable prototype implementing the
[Software Requirements Specification](docs/SRS.md) (LOOM-SRS-001). It is written
in Rust and runs a complete deployment — transparency log, witnesses,
rebuilders, peers and client — on loopback.

```
$ loom install hello-loom
:: hello-loom: fetching recipe (no code is executed)
:: hello-loom: fetching attested artifact 4b06e38cc248 from 3 peer(s)
hello-loom 1.2-1 — ALLOWED (pre-install)
  (9 other check(s) passed; `loom explain hello-loom` for the full derivation)
  artifact: 4b06e38cc248 from peer http://127.0.0.1:7733
  => installed hello-loom 1.2-1
```

## The five defences

Loom is a **trust-and-containment** system, not a malware scanner. It combines
five independent mechanisms, so that no single bypass is catastrophic
(evaluation E4 shows detections are distributed across all of them):

| Subsystem | Property | Counters |
|-----------|----------|----------|
| **Heddle** | Build scripts run under a mount namespace + Landlock + a seccomp-BPF supervisor: no `$HOME`/credential reads, no writes outside the build dir, no network. | Credential harvesting, install-time code execution, build-time injection (ADV-5/6) |
| **Thread + Weave** | An artifact is installed only when *k of n* organisationally- and toolchain-independent rebuilders reproduce it bit-for-bit. | Artifacts that don't correspond to their source (ADV-3/4) |
| **Temporal quarantine** | New versions are withheld for a window (default 72h), with an advisory fast-path for security fixes. | Fast-moving worms detected within days (ADV-1) |
| **Continuity** | Any change of maintainer, signing key or commit lineage (incl. orphan adoption and force-push) is detected and escalated. | Orphan-adoption and account-takeover attacks (ADV-1/2) |
| **Warp** | An append-only, witness-cosigned Merkle transparency log of every attestation and revocation; clients detect split views. | Concealment of the publication event; a hostile log (ADV-9) |

Two mechanisms the SRS does not require but the architecture audit added:
a **placement policy** (blocks packages that install persistence/privilege
vectors — pacman hooks, `ld.so.preload`, `.pth` import hooks, setuid — which no
build-time sandbox can see, the LiteLLM class), and continuity evidence drawn
from the **log's own history** so first-time installers are protected, not just
those with a local baseline.

## Quick start

Requirements: Linux ≥ 5.13 (Landlock), `git`, and a Rust toolchain. On a host
with unprivileged user namespaces you get the full sandbox tier; otherwise Loom
degrades to Landlock + seccomp and says so.

```sh
cargo build
python3 demo/fixtures/genfix.py   # materialise the package fixtures
demo/run.sh              # run every scenario end-to-end on loopback
demo/run.sh sandbox      # or just one: the confined-vs-unconfined contrast
LOOM_HOLD=1 demo/run.sh  # keep services + dashboard up afterwards (Ctrl-C to stop)
demo/present.sh          # guided live demo: one keypress per scenario (for presentations)
cargo test --workspace   # 75 unit/integration tests
cargo run -p loom-eval   # the acceptance-criteria harness (E1,E2,E4,E5,E6)
```

`demo/run.sh` provisions keys and configs, starts a mock AUR, the Warp log,
three witnesses and three rebuilders, then walks nine scenarios: a healthy
install by content address, temporal quarantine and the advisory fast-path, an
orphan-adoption attack, a build-time network injection, a force-push with a
planted pacman hook, a `.pth` startup hook, the **confined-vs-unconfined sandbox
contrast against a canary sink**, a split-view attack on the log, and a
read-only provenance audit.

### Deployment console

While the demo runs, open **http://127.0.0.1:7790** for a live console of the
whole deployment: service health and topology, the Warp log drawn as one
thread per signed record (with the victim's forked view beside it during the
split-view attack), a **defence matrix** showing which mechanism fired in each
scenario, every client decision with its failing checks, the sandbox
contrast, and the `loom-eval` acceptance results. At the end the run freezes
the console into a self-contained `$LOOM_HOME/report.html`;
[`docs/demo-report.html`](docs/demo-report.html) is one such snapshot.

The console reads an event journal (`$LOOM_EVENTS`, one JSON object per
decision, rebuild or log sync) that `loom`, `loomd` and `demo/run.sh` append
to when the variable is set, plus live queries to each service. It decodes log
records for display only; the `loom` client still verifies everything itself.

Every "malicious" fixture is an **inert probe**: it reads a planted decoy file
and pings a *local* sink with a fixed marker. Nothing leaves the machine; the
point is to show the sandbox denying the attempt.

## Workspace layout

```
crates/
  loom-core      canonical JSON, DSSE, Ed25519 keys, in-toto attestation schema,
                 pacman vercmp, the ecosystem Backend interface, HTTP plumbing
  loom-warp      RFC 6962 Merkle log, C2SP checkpoints + tlog-cosignature v1
                 witnesses, log server, and the client-side verifier
  loom-heddle    the least-privilege build executor (namespaces/Landlock/seccomp)
  loom-shuttle   content-addressed artifact store and peer transport
  loom-weave     the policy engine: k-of-n independence, quarantine, continuity,
                 placement, and explained decisions
  loom-aur       the AUR backend: RPC, .SRCINFO, git mirrors, pinned fetch,
                 deterministic packaging  (all AUR knowledge lives here)
  loom-thread    the rebuilder: double reproducible builds -> signed attestations
  loom-client    configuration, trust root, state, and the install pipeline
  loom-cli       the `loom` client and `loomd` service binaries
  loom-testbed   the scenario-driven mock AUR and one-shot provisioning
  loom-eval      the evaluation harness (acceptance criteria)
demo/            run.sh and the package fixtures
docs/            SRS, ARCHITECTURE, TRACEABILITY, EVALUATION, CONFIG, SANDBOX
```

`loom-weave`, `loom-warp`, `loom-thread` and `loom-heddle` know nothing about
the AUR: ecosystem-specific logic is isolated behind `loom_core::ecosystem::Backend`
(NFR-MNT-1), so an npm or PyPI backend would slot in without touching them.

## Documentation

- [docs/SRS.md](docs/SRS.md) — the requirements specification (LOOM-SRS-001).
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — design, subsystems, the trust
  model, and the architecture-audit decisions.
- [docs/TRACEABILITY.md](docs/TRACEABILITY.md) — requirements -> threats ->
  incidents -> code -> tests.
- [docs/EVALUATION.md](docs/EVALUATION.md) — the experiments and how to run them.
- [docs/CONFIG.md](docs/CONFIG.md) — policy and client configuration.
- [docs/SANDBOX.md](docs/SANDBOX.md) — the confinement layers and their limits.

## What Loom deliberately does not claim

Attestation proves *correspondence to source*, not *benignity of source*. Loom
does not detect a maintainer who publishes malicious source that all rebuilders
reproduce identically (SRS OOS-5). This is the honest boundary of what
reproducible-build attestation can prove, and it is why the sandbox, quarantine,
continuity and placement mechanisms exist alongside it.

## License

Apache-2.0.
