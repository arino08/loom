# Working in this repository

Loom is a decentralised, verifying package manager for the AUR. It implements
`docs/SRS.md` (LOOM-SRS-001). Read `docs/ARCHITECTURE.md` first.

## Build & test

```sh
cargo build                     # workspace
cargo test --workspace          # unit + integration (kernel-independent)
cargo run -p loom-eval          # acceptance-criteria harness
python3 demo/fixtures/genfix.py # materialise the package fixtures
demo/run.sh [scenario]          # full live deployment on loopback
LOOM_KERNEL_TESTS=1 cargo test -p loom-heddle --test escape   # sandbox escapes
```

## Layout & invariants

- Crates are layered: `loom-core` (shared types) <- `loom-warp`/`loom-heddle`/
  `loom-shuttle`/`loom-weave` <- `loom-aur`/`loom-thread` <- `loom-client` <-
  `loom-cli`. `loom-testbed`/`loom-eval` are demo/eval tooling.
- **NFR-MNT-1 is load-bearing:** `loom-weave`, `loom-warp`, `loom-thread` and
  `loom-heddle` must not depend on `loom-aur`. All AUR/PKGBUILD knowledge lives
  behind `loom_core::ecosystem::Backend`.
- **Never source a PKGBUILD** to read metadata — parse `.SRCINFO` (FR-3.9).
- **Fail closed** (NFR-SEC-1): any verification/log/sandbox error must refuse,
  never fall back to unverified/unconfined.
- Signed records go through `loom_core::canon` (deterministic) then DSSE.
- Crypto is `ed25519-dalek` + `sha2` only — no bespoke crypto (CON-5).

## Demo/testbed gotchas

- Services bind fixed ports (7700/7710/772x/773x). `demo/run.sh` frees them by
  **port**, never by process name — do not `pkill -f loomd` from a shell whose
  own command line contains "loomd", or it kills itself.
- Each `loom-testbed provision` regenerates keys under `$LOOM_HOME/keys`; stale
  daemons from a previous run hold old keys and will reject the new log.
- The mock AUR reads its scenario from disk per request, so CLI mutations
  (`publish`, `set-age`, `advisories`) are visible to the running server.

## Attribution
End commit messages with the Co-Authored-By / Claude-Session trailers used in
this repo's history.
