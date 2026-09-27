# Loom — Architecture

This document describes how Loom is built and why, and records the decisions
taken during the architecture audit (the deviations from and additions to
LOOM-SRS-001). It assumes the SRS ([docs/SRS.md](SRS.md)) for requirements.

## 1. System context

Loom is a client-side system. It interacts with four external entities and
requires cooperation from none of them:

```
                 +-------------+
   +--------+    | AUR RPC/git |  (read-only: metadata + PKGBUILD/.SRCINFO)
   |  User  |    +-------------+
   | (CLI)  |--> +-------------------------------+   +--------------------+
   +--------+    |           loom client         |<->| rebuilders (Thread) |
                 |  Weave . Heddle . Shuttle     |   | + witnesses         |
                 |  Warp-client                  |   +--------------------+
                 +---+---------------+-----------+   +--------------------+
                     v               v               |  Warp log          |
                +--------+     +----------+          +--------------------+
                | pacman |     |  kernel  |  (namespaces, Landlock, seccomp)
                +--------+     +----------+
```

The **rebuilders (Thread)**, **witnesses** and the **Warp log** are operated by
independent parties; in this prototype they run as separate processes on
loopback, and rebuilder independence is *simulated* by deliberately divergent
toolchain descriptors (SRS ASM-4). The protocol and threshold logic are real.

## 2. Data model (loom-core)

Everything the subsystems agree on lives in `loom-core`, and none of it mentions
the AUR:

- **Digest** — `sha256:<hex>`; artifacts are content-addressed (FR-2.1).
- **Canonical JSON** — the RFC 8785 subset used for every signed record, so
  signatures are deterministic (SRS §7.3). `serde_json`'s map is a `BTreeMap`,
  giving sorted keys for free.
- **DSSE envelopes** — attestations and revocations are in-toto Statements
  wrapped in DSSE. The signature covers `PAE(payloadType, body)`, so a signature
  over an attestation can never be replayed as one over a revocation.
- **Attestation schema** — an in-toto v1 Statement whose predicate binds *what
  was built* (artifact digest) to *what it was built from* (source commit +
  source digest) and *who/how* (rebuilder identity + toolchain descriptor).
  Outcome is `reproducible | unreproducible | build_failed` (see §5.2).
- **Ecosystem `Backend` trait** — the single seam behind which all AUR knowledge
  sits (NFR-MNT-1).
- **vercmp** — a faithful port of libalpm's `rpmvercmp`, tested against pacman's
  own vectors, used for advisory matching.

## 3. Warp — the transparency log

Warp is an append-only Merkle tree (RFC 6962) over canonical log records, built
on Cloudflare's `tlog_tiles` port of Go's `sumdb/tlog` — audited primitives, no
bespoke cryptography (SRS CON-5).

- **Checkpoints** follow [c2sp.org/tlog-checkpoint](https://c2sp.org/tlog-checkpoint)
  and are signed with a [c2sp.org/signed-note](https://c2sp.org/signed-note)
  Ed25519 signature.
- **Witness cosignatures** follow [c2sp.org/tlog-cosignature](https://c2sp.org/tlog-cosignature)
  v1: the signed message is `"cosignature/v1\ntime <ts>\n" || checkpoint-body`,
  the signature bytes are `u64be(timestamp) || ed25519_sig`, and the key ID uses
  algorithm byte `0x04`, so a witness key can never be mistaken for a log key.
- **Witnesses** implement [c2sp.org/tlog-witness](https://c2sp.org/tlog-witness):
  a witness cosigns a new checkpoint only after verifying a consistency proof
  from the last checkpoint it cosigned. An honest witness therefore vouches for
  at most one linear history.

**Admission** is permissioned (SRS Appendix C defers permissionless admission,
where Sybil resistance is unresolved). A record is accepted only if signed by a
configured rebuilder key or revocation authority. Revocations must name the leaf
they revoke by index *and* digest, and a rebuilder may only revoke its own
attestations (a revocation authority may revoke any).

**Client verification** (`loom-warp::client`) does, in order: verify the log's
signature; require >= `witness_threshold` valid cosignatures (FR-5.6); verify
consistency with the persisted head and refuse on any inconsistency (FR-5.7);
cross-check each witness's own latest cosigned checkpoint and, on divergence,
save *transferable proof of misbehaviour* (two log-signed, mutually inconsistent
checkpoints); mirror every record and recompute the root locally so the log
cannot hide records — in particular revocations — from the client. It **fails
closed** at every stage (NFR-SEC-1).

### Split-view resistance (audit note A8)

The SRS sets `witness_threshold = 2` with `n >= 2` honest witnesses. Two quorums
of size *t* over *n* witnesses intersect in `2t - n` witnesses; a split view is
*prevented* (not merely *detected*) only if that intersection contains an honest
witness, i.e. `f < 2t - n`. With `t = 2, n = 3` two disjoint quorums do not
exist, so a split view is prevented while <= 1 witness colludes; with `t = 2,
n = 4` they do, and prevention relies on the client's witness cross-check. Weave
surfaces this analysis in `loom policy show`. Detection (the SRS requirement,
AC-6) holds with >= 2 honest witnesses regardless.

## 4. Heddle — the build sandbox

One declarative **access policy** compiles into three enforcement layers, so the
denial a user sees always names the rule the kernel actually enforced (FR-3.7):

- **mount namespace** — the sandbox root is a fresh tmpfs at a per-process
  mountpoint (never an ancestor of the build dir, or the build bind-mount would
  shadow itself). It contains only read-only binds of the toolchain, a *curated*
  subset of `/etc` (not the pacman keyring, host keys or network credentials), a
  minimal `/dev`, a private `/proc`, a private `/tmp`, and the build dir at
  `/build`. `$HOME`, `/root`, `/run`, `/var` simply do not exist inside.
- **Landlock** (ABI up to v6) — filesystem allowlist, TCP restriction and IPC
  scoping. This is the *only* FS enforcement in the reduced tier and defence in
  depth in the full tier. If Landlock is unavailable at all, the build is
  refused.
- **seccomp-BPF + a user-notification supervisor** — dangerous syscalls
  (`mount`, `unshare`, `ptrace`, `bpf`, `io_uring`, module loading, ...) return
  `EPERM`; the x32 ABI is blocked; `clone3` returns `ENOSYS` so libc falls back
  to inspectable `clone`; `socket()` for any family but `AF_UNIX` and path-opens
  are forwarded to a supervisor that **explains** the denial. Enforcement never
  depends on the supervisor's path inspection (that would be a TOCTOU hazard):
  files are enforced by the namespace and Landlock; the supervisor answers
  `EACCES` early for paths the policy denies and otherwise lets the kernel
  decide.

**Tiers.** `full` (all namespaces) -> `reduced` (Landlock + seccomp, where
unprivileged user namespaces are disabled; reported as reduced assurance,
NFR-MNT-3) -> the build is refused if neither is achievable. A separate
`unconfined-demo` backend exists *only* to show, in the demo, what a plain AUR
helper exposes; it is never selected implicitly and every report is marked.

Nothing survives a build: the PID namespace and process-group kill guarantee no
residual processes or mounts (NFR-REL-3).

## 5. Thread + Weave — reproducibility and policy

### 5.1 Thread (the rebuilder)

For each package a rebuilder builds **twice** under deliberately different
environments (time zone, locale, umask, build path — the reprotest approach from
the Reproducible Builds project). If its two builds agree it attests
`reproducible` with that digest; if not, it attests `unreproducible` and makes
**no** digest claim. It signs an in-toto statement with its own Ed25519 key
(FR-4.3), submits it to Warp, and serves the artifact from its content-addressed
store.

### 5.2 Independence (audit note A6)

Only a rebuilder whose *own* two builds agree may contradict another's artifact.
This bounds the denial-of-service power of a single faulty rebuilder under FR-6.4
(one flaky build cannot block an install; it neither supports nor contradicts).

Counting *independent* evidence (FR-6.2, NFR-SEC-4) is a **maximum independent
set** over a correlation graph: two attestations are correlated if they share an
organisation *or* a toolchain descriptor. The SRS's "don't count identical
toolchains twice" is the special case with only toolchain edges; the graph
formulation additionally collapses Sybil rebuilders sharing an org, and is exact
for the small *n* of a rebuilder federation.

### 5.3 Weave (the decision)

`loom_weave::evaluate` is a pure function from (policy, evidence) to an explained
decision. It evaluates *every* rule and reports *every* violation (FR-6.5); each
failing rule carries its evidence and a remediation (FR-11.2), and no rule ever
produces an unexplained failure (FR-11.4). Rules: continuity, log integrity,
independent attestations, artifact/source contradiction, quarantine, source
pinning, sandbox, placement, and install scripts. Continuity is evaluated first
because an escalation raises *k* and the quarantine window for the later rules.

The policy file is strict TOML: unknown keys, bad enum values and unparseable
durations are fatal — Loom refuses to run on a malformed policy rather than
silently falling back to permissive defaults (FR-9.4). With no file at all, the
built-in secure default applies (FR-9.3).

## 6. Shuttle — distribution

Shuttle contributes **availability**, never integrity (SRS note under FR-2.6):
every byte is verified against a digest that came from witness-cosigned
attestations, so a hostile peer can at worst withhold or corrupt bytes, which the
client detects and routes around (the demo's poisoned-peer test). The prototype
uses a small HTTP peer protocol behind the `fetch`/`PeerServer` boundary; a
libp2p (bitswap/kademlia) transport would replace it without touching Weave,
Warp or Thread.

## 7. The client pipeline (loom-client)

`loom install` resolves the package and its AUR dependencies (delegating
official-repo deps to pacman, FR-1.4), then for each package, **dependencies
first**:

1. fetch the recipe and record maintainer/commit/keys — no code runs (FR-3.9);
2. gather evidence: verify the log, parse attestations and revocations, check
   continuity (local baseline + log history), quarantine and advisories;
3. evaluate. If blocked, **refuse before any payload could run** (AC-1);
4. otherwise obtain the artifact — **prefer the attested artifact by content
   address** (verify, don't build: when *k* rebuilders agree, no PKGBUILD code
   runs on the user's machine) and fall back to a local Heddle build only if no
   peer can serve it;
5. inspect the artifact's placement, strip its `.INSTALL` (so pacman never runs
   it unconfined) and re-evaluate;
6. install via `pacman -U` (or extract-into-root for demos/containers), run any
   install script under Heddle per policy, and record the continuity baseline
   and install database.

The audit command (`loom audit`) runs the same evidence-gathering read-only:
it never fetches git, writes state, or modifies the system (FR-10.2).

## 8. Architecture-audit summary

Beyond faithfully implementing the SRS, the audit made these decisions:

- **A1 — verify, don't build.** Prefer the content-addressed attested artifact
  over a local rebuild. Reproducibility's payoff is that most users never
  execute PKGBUILD code at all; the local sandboxed build is the fallback.
- **A2 — continuity for first-time installers.** Draw continuity evidence from
  the log's witnessed history, not only a local baseline, so a victim installing
  an orphan-adopted package *for the first time* is still protected.
- **A4 — placement policy.** Inspect what a package *installs* (pacman hooks,
  `ld.so.preload`, `.pth` import hooks, setuid, service/persistence paths) — the
  LiteLLM class of payload that the build sandbox cannot see.
- **A5 — install scripts under Heddle.** Strip `.INSTALL` from the artifact
  handed to pacman and run scriptlets under the sandbox, never as root
  unconfined.
- **A6 — self-verified contradictions.** Only rebuilders that reproduced their
  own build may contradict others (bounds single-rebuilder DoS).
- **A8 — quorum analysis.** Distinguish split-view *prevention* from *detection*
  and surface it in the policy output.

None of these weaken an SRS "shall"; each closes a gap a strict reading would
leave open.
