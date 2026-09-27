# Loom — Traceability

Requirements -> threat model -> 2026 incidents -> implementation -> verification.
Requirement text is in [docs/SRS.md](SRS.md). "Where" points at the code that
implements it; "Verified by" at the test or demo that exercises it.

## Functional requirements

| Req | Counters (ADV / incident) | Where | Verified by |
|-----|---------------------------|-------|-------------|
| FR-1.1 resolve + transitive deps | — | `loom-client/pipeline.rs::resolve_order`, `loom-aur/lib.rs::resolve` | demo scenario 1 (libweft pulled first) |
| FR-1.2 fetch PKGBUILD/sources | — | `loom-aur/git.rs`, `loom-aur/lib.rs::checkout` | demo (all) |
| FR-1.3 record maintainer/commit/timestamp | — | `loom-aur/lib.rs::checkout`, `loom-client/state.rs::Baseline` | `loom-weave` continuity tests |
| FR-1.4 delegate official deps to pacman | — | `pipeline.rs::resolve_order` (system list), `install.rs::Pacman` | demo (dependency note) |
| FR-1.5 verify every artifact hash, abort on mismatch | ADV-7 | `loom-aur/lib.rs::prepare_build` (pinned fetch), `loom-shuttle/lib.rs::fetch` | `loom-shuttle` poisoned-peer test |
| FR-2.1 content-address artifacts | ADV-7 | `loom-core/digest.rs`, `loom-shuttle/lib.rs::Cas` | `cas_roundtrip_and_corruption` |
| FR-2.2/2.3 retrieve from peers, fall back to origin | — | `loom-shuttle/lib.rs::fetch`, `pipeline.rs` | demo scenario 1 (peer fetch), fallback path |
| FR-2.6 peer data untrusted | ADV-7 | `loom-shuttle/lib.rs::fetch` (hash check) | `poisoned_peer_rejected_honest_peer_wins` |
| FR-3.1 build in isolated mount namespace | ADV-5 | `loom-heddle/mounts.rs`, `lib.rs::init_inner` | escape suite; demo scenario 7 |
| FR-3.2 deny home/credential reads | ADV-5/6 | `loom-heddle/policy.rs::CREDENTIAL_MARKERS`, `mounts.rs` | escape suite; **demo 7: `openat /root/.ssh... denied`** |
| FR-3.3 deny writes outside build dir | ADV-4/5 (LiteLLM `.pth`) | `policy.rs::classify`, `landlock_layer.rs` | escape suite (`/usr/lib/*.pth` write) |
| FR-3.4 deny build-time network | ADV-5/6 (Atomic Arch) | `seccomp.rs` (socket), empty net namespace, Landlock TCP | **demo 7: sink hits confined=0, unconfined=1** |
| FR-3.5 network only for pinned fetch manifest | ADV-5 | `loom-aur/lib.rs::prepare_build` (pins), `unpinned` | `loom-weave` sources rule |
| FR-3.6 seccomp syscall restriction | — | `loom-heddle/seccomp.rs` | `filter_decisions` BPF-interpreter test |
| FR-3.7 log every denial with its rule | — | `seccomp.rs::supervise`, `report.rs::Denial` | demo 7 denial lines |
| FR-3.8 user-authorised confinement exception | — | policy `allow_network`, override `sandbox-network` | `loom-weave` decision tests |
| FR-3.9 never execute build script unconfined | ADV-5 | `.SRCINFO` parsing (no sourcing), `pipeline.rs` | code inspection; no PKGBUILD sourcing anywhere |
| FR-4.1-4.5 hermetic build + signed attestation | ADV-3/4 | `loom-thread/build.rs`, `lib.rs::rebuild` | demo scenario 1 (3 threads agree) |
| FR-4.6 negative attestation on divergence | ADV-4 | `loom-thread/lib.rs` (`Unreproducible`, `disputes`) | `divergent-bin` fixture |
| FR-5.1-5.4 append-only Merkle log, STHs, cosigs, proofs | ADV-9 | `loom-warp/tree.rs`, `notes.rs`, `server.rs` | `rfc6962_*`, `inclusion_all_sizes`, `consistency_all_pairs` |
| FR-5.5 verify inclusion before accepting | — | `client.rs::verify_inclusion` | `warp_e2e::honest_log_verifies` |
| FR-5.6 witness threshold | ADV-9 | `client.rs::update` | `threshold_not_met_is_refused` |
| FR-5.7 persisted-head consistency, refuse on inconsistency | ADV-9 | `client.rs::update`, `tree.rs::verify_consistency` | `split_view_detected_*`; **demo 8** |
| FR-5.8/5.9 revocation records + apply before decision | CON-3 | `attest.rs` (revocation), `server.rs::validate`, `pipeline.rs::context` | `warp_e2e::revocation_rules`; `revocation_removes_contradiction` |
| FR-6.1 k-of-n organisationally-distinct | ADV-3/4/8 | `loom-weave/independence.rs`, `eval.rs` | `healthy_package_allowed`, `correlated_toolchains_counted_once` |
| FR-6.2 correlated toolchains not counted twice | ADV-8, OOS-6 | `independence.rs` (MIS) | `independence.rs::counts`, property test |
| FR-6.3 configurable action on insufficient | — | `policy.rs::Action`, `eval.rs` | `every_failure_is_explained` sweep |
| FR-6.4 any contradiction blocks | ADV-4 | `eval.rs` contradiction rule | `contradiction_blocks_regardless_of_majority` |
| FR-6.5 evaluate all rules, report all | — | `eval.rs::evaluate` | `every_failure_is_explained` |
| FR-7.1-7.4 temporal quarantine + advisory fast-path | ADV-1 (Mastra) | `eval.rs` quarantine rule, `advisory.rs` | `quarantine_and_exemption_and_override`; **demo 2** |
| FR-8.1-8.7 continuity (maintainer/key/lineage/orphan/force-push) | ADV-1/2/3 | `loom-weave/continuity.rs`, `loom-aur/git.rs::is_ancestor` | `continuity.rs` tests; **demo 3 & 5** |
| FR-9.1-9.4 declarative policy, strict validation | — | `loom-weave/policy.rs` | `malformed_corpus_rejected` |
| FR-10.1-10.4 read-only audit + coverage + JSON | — | `loom-client/audit.rs` | **demo 9** |
| FR-11.1-11.4 CLI, explained blocks, `explain`, never unexplained | — | `loom-cli/bin/loom.rs`, `eval.rs::render` | `every_failure_is_explained`; demo (all) |

## Non-functional requirements

| Req | Where | Verified by |
|-----|-------|-------------|
| NFR-PERF-1/3 overhead, attestation verify | `eval.rs`, `attest.rs` | `loom-eval` E5 |
| NFR-SEC-1 fail closed | `client.rs`, `heddle/lib.rs`, `weave` | log-failure tests; sandbox-setup-error rule |
| NFR-SEC-2 keys never leave host | `loom-core/keys.rs` (0600, no export API) | `save_load_roundtrip_and_perms` |
| NFR-SEC-4 toolchain diversity -> independence | `independence.rs`, `attest.rs::Toolchain` | independence tests |
| NFR-SEC-5 split view with >=2 honest witnesses | `warp/client.rs`, `witness.rs` | `split_view_detected_*`; `loom-eval` E6; demo 8 |
| NFR-MNT-1 ecosystem behind an interface | `loom-core/ecosystem.rs` | Weave/Warp/Thread never `use loom_aur` |
| NFR-MNT-3 degrade below full tier, report | `heddle/lib.rs`, `landlock_layer.rs` | `loom sandbox-check` output |
| NFR-OBS-1/2 structured decision + denial logs | `state.rs::log_decision`, `heddle/report.rs` | `decisions.jsonl`, demo denial lines |

## Requirement -> incident (SRS §9.1)

| Incident (2026) | Class | Requirements | Demo scenario |
|-----------------|-------|--------------|---------------|
| Axios (email change, CI bypass) | maintainer compromise, tampered artifact | FR-8.2, FR-6.1, FR-4.1 | 3, 4 |
| Atomic Arch (orphan adoption, npm-in-PKGBUILD) | orphan adoption, build injection | FR-8.5, FR-3.4, FR-3.5 | 3, 4 |
| July–Aug AUR waves | orphan adoption | FR-8.2, FR-8.5 | 3 |
| TeamPCP (110+ tags force-pushed) | history rewrite | FR-8.4 | 5 |
| LiteLLM (`.pth` outside package scope) | tampered artifact / placement | FR-3.3, FR-6.1, placement (A4) | 6 |
| Shai-Hulud / ChainDrop | credential harvest + worm | FR-3.2, FR-3.4, FR-3.6 | 7 |
| Mastra (140 pkgs in 19 min) | fast-moving compromise | FR-7.1 | 2 |
| hostile log operator | split view | FR-5.3, FR-5.6, FR-5.7 | 8 |
