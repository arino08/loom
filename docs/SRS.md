# Software Requirements Specification — Loom

**Document ID:** LOOM-SRS-001 · **Version:** 1.0 · **Date:** August 2026 ·
**Status:** Baseline · Structured per IEEE Std 830-1998 / ISO/IEC/IEEE 29148:2018.

> This is a markdown reproduction of the baseline SRS that this repository
> implements, provided so the requirement IDs referenced throughout the code and
> docs resolve here. See [TRACEABILITY.md](TRACEABILITY.md) for the mapping to
> code and tests.

## 1. Introduction

### 1.1 Purpose
Specifies the functional and non-functional requirements for **Loom**, a
decentralised package manager for community-maintained software repositories.

### 1.2 Scope
Loom is a command-line client that installs packages from the Arch User
Repository (AUR) under an enforceable trust policy. It provides: sandboxed
execution of build scripts under least privilege; verification against *k-of-n*
independent reproducible-build attestations; temporal quarantine of new
versions; detection of changes to publishing authority; an append-only,
independently witnessed transparency log of attestations and revocations;
peer-to-peer content-addressed distribution; and a read-only audit mode.

**Out of scope:** other ecosystems (npm/PyPI/crates.io — the design is
ecosystem-agnostic, ports are future work); a GUI; malware detection by
behavioural analysis (Loom is trust-and-containment, not a scanner); prevention
of initial maintainer credential compromise; production deployment of an
independent rebuilder network (simulated for evaluation, ASM-4).

### 1.3 Glossary
Artifact, Attestation, AUR, Continuity, **Heddle** (sandboxed build executor),
Hermetic build, k-of-n, Landlock, Orphan adoption, PKGBUILD, Quarantine window,
Rebuilder, seccomp-BPF, **Shuttle** (P2P transport), Split view, **Thread**
(rebuilder daemon), **Warp** (witnessed Merkle log), **Weave** (k-of-n policy
engine), Witness.

## 2. Overall description
Loom replaces `yay`/`paru`/`makepkg` at install time. It is client-side and
requires no cooperation from the AUR, maintainers or upstream. It interacts with
the AUR RPC/git (read-only), `pacman`/`makepkg`, rebuilder and witness peers, and
the Linux kernel (namespaces, Landlock, seccomp).

**Product functions:** F1 resolve/fetch AUR packages · F2 content-addressed P2P
distribution · F3 least-privilege builds · F4 produce/verify attestations ·
F5 witnessed transparency log · F6 trust-policy evaluation · F7 publishing-
authority continuity · F8 provenance audit.

**Operating environment:** Arch or derivative; kernel >= 5.13 (Landlock ABI v1),
>= 6.7 preferred; `pacman` >= 6.0, `bubblewrap`, `git`; x86-64 and aarch64;
degraded but functional offline.

## 3. Constraints, assumptions, dependencies

**Constraints:** CON-1 no AUR modification / no maintainer cooperation · CON-2 no
blockchain/consensus/token · CON-3 the log shall support revocation · CON-4 no
mechanism depends on third-party adoption to demonstrate · CON-5 audited crypto
libraries only, no bespoke crypto · CON-6 security decisions explainable in plain
language, always naming the rule that fired and how to proceed.

**Assumptions:** ASM-1 AUR readable unauthenticated · ASM-2 2026 malicious commits
recoverable from git history · ASM-3 the host/kernel/Loom binary are not already
compromised · ASM-4 rebuilder independence simulated by divergent-toolchain
containers · ASM-5 a non-trivial fraction of packages will not build reproducibly
— degrade gracefully.

**Dependencies:** namespaces, Landlock, seccomp-BPF, bubblewrap, pacman/makepkg,
libp2p, Ed25519, SHA-256/BLAKE3.

## 4. Threat model

**In scope (adversary):** ADV-1 compromise maintainer account/token (incl. email
change) · ADV-2 orphan adoption via legitimate takeover · ADV-3 compromise CI/CD
or reuse a rotated token · ADV-4 publish a correctly-signed artifact not
corresponding to source · ADV-5 execute code at install time and exfiltrate
credentials · ADV-6 self-propagate with harvested credentials · ADV-7 network
adversary on the P2P layer · ADV-8 operate a minority of rebuilders/witnesses
(< k) · ADV-9 present divergent log histories (split view).

**Out of scope:** OOS-1 >= k organisationally-distinct rebuilders compromised
simultaneously · OOS-2 cryptographic breaks · OOS-3 kernel/LSM escape on a
correct host · OOS-4 pre-install compromise of the Loom binary or its root of
trust · OOS-5 malicious code identical across all rebuilds (attestation proves
correspondence to source, not benignity) · OOS-6 shared compiler-toolchain
compromise (Thompson attack; mitigated by NFR-SEC-4, not eliminated).

## 5. Functional requirements
Priority: **M** Must, **S** Should, **C** Could.

### 5.1 Package resolution and retrieval
- **FR-1.1 (M)** resolve a package and its transitive AUR dependencies via the RPC.
- **FR-1.2 (M)** retrieve PKGBUILD + sources from the package's git repo.
- **FR-1.3 (M)** record maintainer identity, last-modified timestamp and HEAD commit.
- **FR-1.4 (M)** delegate official-repo dependency resolution to pacman.
- **FR-1.5 (M)** verify every retrieved artifact against its expected hash; abort on mismatch.

### 5.2 Peer-to-peer distribution (Shuttle)
- **FR-2.1 (M)** address artifacts by cryptographic content hash.
- **FR-2.2 (S)** retrieve artifacts from peers by content address.
- **FR-2.3 (S)** fall back to origin when no peer serves within a timeout.
- **FR-2.4 (C)** serve cached artifacts to peers, with a user opt-out.
- **FR-2.5 (S)** propagate attestations and signed tree heads over the peer network.
- **FR-2.6 (M)** treat all peer data as untrusted; trust only from hash + signature verification.

### 5.3 Sandboxed build execution (Heddle)
- **FR-3.1 (M)** execute PKGBUILD scripts and install hooks in an isolated mount namespace exposing only the build dir and declared inputs.
- **FR-3.2 (M)** deny build-time read of the home directory, with no exception for `~/.ssh`, `~/.gnupg`, `~/.npmrc`, `~/.aws`, `~/.gitconfig`, `~/.config`, or credential stores.
- **FR-3.3 (M)** deny build-time writes outside the build dir and declared outputs.
- **FR-3.4 (M)** deny all build-time network by default.
- **FR-3.5 (M)** permit build-time network only to endpoints in a declared fetch manifest with pinned hashes.
- **FR-3.6 (M)** apply a seccomp-BPF profile restricting the syscall surface.
- **FR-3.7 (M)** log every denied access with the resource and the rule that denied it.
- **FR-3.8 (S)** provide a user-authorised, persistently-recorded exception mechanism, surfaced in `loom audit`.
- **FR-3.9 (M)** never execute a build script outside confinement, including during resolution and metadata extraction.

### 5.4 Attestation generation (Thread)
- **FR-4.1 (M)** perform hermetic builds from published source.
- **FR-4.2 (M)** emit a signed attestation with package, version, source commit, source hash, artifact hash, rebuilder identity, toolchain descriptor and timestamp.
- **FR-4.3 (M)** sign with an Ed25519 key held only by that rebuilder.
- **FR-4.4 (M)** submit attestations to the Warp log.
- **FR-4.5 (M)** record a toolchain descriptor sufficient to judge independence.
- **FR-4.6 (S)** emit a negative attestation when a build produces a differing hash.

### 5.5 Transparency log (Warp)
- **FR-5.1 (M)** append-only Merkle tree over attestation and revocation records.
- **FR-5.2 (M)** issue signed tree heads.
- **FR-5.3 (M)** accept cosignatures from a configured witness set.
- **FR-5.4 (M)** serve inclusion and consistency proofs.
- **FR-5.5 (M)** client verifies inclusion before accepting an attestation.
- **FR-5.6 (M)** client verifies >= a threshold of witness cosignatures.
- **FR-5.7 (M)** client persists the latest verified head and verifies consistency with each new one, refusing on inconsistency.
- **FR-5.8 (M)** support revocation records that invalidate without removing from history.
- **FR-5.9 (M)** client applies all applicable revocations before a decision.

### 5.6 Trust policy evaluation (Weave)
- **FR-6.1 (M)** accept an artifact only with >= k non-revoked attestations from organisationally-distinct rebuilders agreeing on its hash (k user-configurable).
- **FR-6.2 (S)** treat identical-toolchain rebuilders as correlated; do not count them toward k independently.
- **FR-6.3 (M)** configurable action (block/warn/allow) when fewer than k exist.
- **FR-6.4 (M)** block when any attestation contradicts the artifact hash, regardless of agreement count.
- **FR-6.5 (S)** evaluate all rules and report every violation.

### 5.7 Temporal quarantine
- **FR-7.1 (M)** withhold any version published within a configurable window (default 72h).
- **FR-7.2 (M)** permit an explicit, persistently-recorded per-version override.
- **FR-7.3 (M)** exempt versions a configured advisory feed marks as remediating a vulnerability.
- **FR-7.4 (S)** report publication timestamp and time remaining per quarantined package.

### 5.8 Publishing authority continuity
- **FR-8.1 (M)** persist per-package maintainer, signing-key fingerprint and commit lineage at install.
- **FR-8.2 (M)** detect and report maintainer-identity change.
- **FR-8.3 (M)** detect and report signing-key change.
- **FR-8.4 (M)** detect non-linear history (force-push, rewrite, tag reassignment).
- **FR-8.5 (M)** treat orphan adoption as a maintainer change (FR-8.2).
- **FR-8.6 (M)** on a violation, apply a configurable escalated policy (raise k, extend quarantine, or block).
- **FR-8.7 (M)** present violations with prior/current values and the date of change.

### 5.9 Configuration and policy
- **FR-9.1 (M)** read policy from a declarative file.
- **FR-9.2 (M)** support at minimum: `min_age`, `required_attestations`, `witness_threshold`, `install_scripts` (sandbox/deny/allowlist), `on_continuity_change`, per-package overrides.
- **FR-9.3 (M)** ship a secure-by-default policy effective with no configuration.
- **FR-9.4 (M)** validate the policy and refuse to run on a malformed one rather than falling back to permissive defaults.

### 5.10 Audit mode
- **FR-10.1 (M)** scan an installation and report per package its attestation coverage, publication age, continuity status and whether it runs install scripts.
- **FR-10.2 (M)** operate without modifying system state.
- **FR-10.3 (S)** report an aggregate provenance-coverage figure.
- **FR-10.4 (C)** support JSON output for CI.

### 5.11 User interface and reporting
- **FR-11.1 (M)** CLI with `install`, `audit`, `verify`, `policy`, `explain`.
- **FR-11.2 (M)** for every blocked install, state the rule, the evidence and the remediation.
- **FR-11.3 (S)** `loom explain <pkg>` reports the full trust derivation.
- **FR-11.4 (M)** never present a security decision as an unexplained failure.

## 6. Non-functional requirements

**Performance:** NFR-PERF-1 non-build install overhead < 500 ms median ·
NFR-PERF-2 confinement build-time increase < 15 % · NFR-PERF-3 attestation
verification < 100 ms/package · NFR-PERF-4 audit of 1,000 packages < 60 s.

**Security:** NFR-SEC-1 fail closed (any verification/log/sandbox error -> refuse,
never an unconfined or unverified fallback) · NFR-SEC-2 private keys never leave
their host · NFR-SEC-3 audited crypto only · NFR-SEC-4 rebuilder set requires
toolchain diversity so agreement is independent evidence · NFR-SEC-5 correct
against a hostile log, detecting split views with >= 2 honest witnesses ·
NFR-SEC-6 no privilege beyond what pacman already needs.

**Usability:** NFR-USE-1 commands comparable in length to existing helpers ·
NFR-USE-2 every block actionable (states the override command where legitimate) ·
NFR-USE-3 default config effective unedited · NFR-USE-4 legible on an 80-column
terminal without colour.

**Reliability:** NFR-REL-1 P2P failure degrades to origin, not failure ·
NFR-REL-2 log unavailability yields a policy decision, not an unhandled error ·
NFR-REL-3 an interrupted install leaves no partial package and no residual mounts.

**Maintainability/portability:** NFR-MNT-1 ecosystem-specific logic isolated
behind an interface (npm/PyPI backend requires no change to Weave/Warp/Thread) ·
NFR-MNT-2 x86-64 and aarch64 · NFR-MNT-3 function on kernel >= 5.13, degrading
network confinement below Landlock ABI 4 and reporting reduced assurance.

**Observability:** NFR-OBS-1 all trust decisions logged structured/machine-
parseable · NFR-OBS-2 sandbox denials logged with enough detail to diagnose a
build failure.

## 7. External interfaces
CLI only: `loom install|audit|verify|policy|explain`. Software interfaces: AUR
RPC (HTTPS/JSON, outbound read-only), AUR git (git over HTTPS), pacman/makepkg
(process), Warp log (HTTPS/JSON, Merkle proofs), witnesses (HTTPS, cosigned tree
heads), peers (libp2p, content-addressed blocks), kernel (namespaces/Landlock/
seccomp), advisory feed (HTTPS/JSON). Attestation records are canonically
serialised before signing; policy is TOML.

## 8. Verification and acceptance

**Acceptance criteria:** AC-1 >= 90 % of a labelled malicious corpus blocked
before payload (E1) · AC-2 <= 5 % spurious block rate over the top 500 packages
(E2) · AC-3 build compatibility under confinement measured and taxonomised (E3;
a low figure is an acceptable, reportable result) · AC-4 ablation shows no single
mechanism accounts for all detections (E4) · AC-5 NFR-PERF-1/2 met (E5) · AC-6
split views detected in 100 % of trials with >= 2 honest witnesses (E6) · AC-7 all
Must-priority requirements implemented and verified.

**Experiments:** E1 attack replay · E2 false positives · E3 build compatibility ·
E4 ablation · E5 overhead · E6 log integrity. See [EVALUATION.md](EVALUATION.md).

## 10. Appendix A — default policy
```toml
[policy]
min_age = "72h"
required_attestations = 2
witness_threshold = 2
install_scripts = "sandbox"
on_continuity_change = "block"
on_insufficient_attestations = "warn"

[advisory]
fast_path = true
feed = "https://security.archlinux.org/advisories.json"

[peer]
serve_cache = true
origin_fallback_timeout = "5s"
```

**Appendix B — requirement count:** Must 44, Should 12, Could 3 (total 59).

**Appendix C — deferred to future work:** npm/PyPI/crates.io backends (scope;
NFR-MNT-1 preserves the option); permissionless rebuilder admission (Sybil
resistance unresolved); GUI; diverse double-compiling for Thompson-attack
resistance (OOS-6; mitigation only via NFR-SEC-4); formal verification of the
policy engine.
