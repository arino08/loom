#!/usr/bin/env bash
# ===========================================================================
# Loom end-to-end demonstration.
#
# Brings up a complete decentralised deployment on loopback — a mock AUR, the
# Warp transparency log, three independent witnesses, three independent
# rebuilders (Thread) — then walks the scenarios that motivate the system:
#
#   1. a healthy package: k-of-n independent rebuilds, verified log, install
#      by content address (no PKGBUILD code runs on the user's machine);
#   2. temporal quarantine of a brand-new version, and the advisory fast-path;
#   3. an orphan-adoption attack whose build tries to read $HOME and phone home;
#   4. a build-time network injection (npm-install-in-PKGBUILD);
#   5. a force-push (history rewrite) that also plants a pacman hook;
#   6. a Python .pth startup-hook (placement policy);
#   7. the sandbox contrast: the SAME malicious build, confined vs unconfined,
#      against a canary sink;
#   8. a split-view attack on the log (a hostile operator colluding with a
#      compromised rebuilder), detected because honest witnesses won't cosign;
#   9. a read-only provenance audit.
#
# Everything is inert: the "malicious" builds only read a planted decoy and
# ping a local sink. Nothing leaves the machine.
#
# A live dashboard of the whole deployment is served on
# http://127.0.0.1:7790 while the demo runs, and a self-contained snapshot is
# written to $LOOM_HOME/report.html at the end. Set LOOM_HOLD=1 to keep the
# services and dashboard up after the last scenario (Ctrl-C to stop).
#
# Usage:  demo/run.sh [scenario]     (default: all)
#   scenarios: healthy quarantine orphan npm forcepush placement sandbox
#              splitview audit
# ===========================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export LOOM_HOME="${LOOM_HOME:-/tmp/loom-demo}"
export LOOM_FIXTURES="$ROOT/demo/fixtures"
BIN="$ROOT/target/debug"
LOG="$LOOM_HOME/logs"
SCENARIO="${1:-all}"
HOST=127.0.0.1
DASH_PORT="${LOOM_DASHBOARD_PORT:-7790}"
# Event journal read by the dashboard (see loom_core::journal).
export LOOM_EVENTS="$LOOM_HOME/events.jsonl"

# ---- pretty printing -------------------------------------------------------
b(){ printf '\033[1m%s\033[0m\n' "$*"; }
hr(){ printf '%s\n' "─────────────────────────────────────────────────────────────────────────"; }
note(){ "$BIN/loom-testbed" note "$@" >/dev/null 2>&1 || true; }
step(){ echo; hr; b "▶ $*"; hr; note scenario "$*"; }
# The takeaway of a scenario: printed, and journalled for the dashboard.
conclude(){ printf '%s\n' "$1" | fold -s -w 76 | sed 's/ *$//; 1s/^/→ /; 2,$s/^/  /'; note conclusion "$1"; }
run(){ printf '\033[2m$ %s\033[0m\n' "$*"; "$@"; }

cleanup(){
  [ -n "${PIDS:-}" ] && kill $PIDS 2>/dev/null
  pkill -f "loomd .*$LOOM_HOME" 2>/dev/null
  pkill -f "loom-testbed serve" 2>/dev/null
  return 0
}
trap cleanup EXIT INT TERM

# ---- build -----------------------------------------------------------------
if [ ! -x "$BIN/loom" ]; then
  b "building loom (release-debug)…"
  ( cd "$ROOT" && cargo build -q ) || exit 1
fi

# ---- sandbox capability ----------------------------------------------------
export LOOM_HEDDLE_BACKEND=kernel
SANDBOX_OK=1
if ! "$BIN/loom" sandbox-check >/dev/null 2>&1; then
  # try after provisioning; some hosts forbid userns. We detect the tier live.
  SANDBOX_OK=0
fi

# ---- provision + start services -------------------------------------------
free_ports(){
  # Kill anything left listening on our ports (by port, never by process name,
  # so this never matches the script's own command line).
  for p in 7700 7710 7721 7722 7723 7731 7732 7733 7781 "$DASH_PORT"; do
    local pid
    pid=$(ss -tlnp 2>/dev/null | grep -F ":$p " | grep -oP 'pid=\K[0-9]+' | head -1)
    [ -n "$pid" ] && kill -9 "$pid" 2>/dev/null
  done
}

# Serve each rebuilder's content-addressed store to the network, so the
# client can fetch attested artifacts by hash (verify, don't build).
start_peers(){
  local ports=(7731 7732 7733) ids=(thread-a thread-b thread-c)
  for j in 0 1 2; do
    "$BIN/loomd" peer --cas "$LOOM_HOME/thread-${ids[$j]}-cache/cas" --listen "$HOST:${ports[$j]}" \
      >"$LOG/peer-${ids[$j]}.log" 2>&1 &
  done
}

start_services(){
  free_ports
  rm -rf "$LOOM_HOME"
  mkdir -p "$LOG"
  run "$BIN/loom-testbed" provision --host "$HOST" >/dev/null
  "$BIN/loom-testbed" serve                 >"$LOG/aur.log"   2>&1 &
  "$BIN/loomd" warp --config "$LOOM_HOME/svc/warp.toml" >"$LOG/warp.log" 2>&1 &
  for i in 1 2 3; do
    "$BIN/loomd" witness --config "$LOOM_HOME/svc/witness-$i.toml" >"$LOG/witness-$i.log" 2>&1 &
  done
  start_peers
  "$BIN/loom-testbed" dashboard --listen "$HOST:$DASH_PORT" >"$LOG/dashboard.log" 2>&1 &
  PIDS="$(jobs -p | tr '\n' ' ')"
  sleep 2
}

rebuild_all(){
  local pkgs=("$@")
  local args=()
  for p in "${pkgs[@]}"; do args+=(--package "$p"); done
  for t in thread-a thread-b thread-c; do
    "$BIN/loomd" thread --config "$LOOM_HOME/svc/$t.toml" --once "${args[@]}" 2>&1 | sed "s/^/  [$t] /"
  done
}

want(){ [ "$SCENARIO" = all ] || [ "$SCENARIO" = "$1" ]; }

# ===========================================================================
b "Loom — decentralised package manager · end-to-end demo"
echo "deployment root: $LOOM_HOME"
start_services
echo "live dashboard:  http://$HOST:$DASH_PORT"
TIER=$("$BIN/loom" sandbox-check 2>/dev/null | awk '/sandbox tier/{print $3}')
echo "sandbox tier on this host: ${TIER:-unavailable}"
[ "$TIER" = full ] || echo "  (note: full tier needs unprivileged user namespaces; reduced tier still enforces Landlock + seccomp)"

# Warm up the log for every scenario except split-view (which manages its own
# services): a first round of rebuilds gives the log records and, once the
# witnesses are up, cosignatures.
if [ "$SCENARIO" != splitview ]; then
  echo; echo "Priming the transparency log (rebuild of the benign baseline)…"
  rebuild_all libweft hello-loom >/dev/null 2>&1
fi

# ---------------------------------------------------------------- healthy
if want healthy; then
  step "1. Healthy package — verify, don't build"
  echo "Three independent rebuilders reproduce hello-loom and its dependency libweft."
  rebuild_all libweft hello-loom
  echo
  b "loom log — the witnessed transparency log the client verifies:"
  run "$BIN/loom" log
  echo
  b "loom install hello-loom — resolves libweft first, installs by content address:"
  run "$BIN/loom" install hello-loom
  echo
  conclude "The artifact came from a peer by content address and three independent rebuilders agreed on it, so no PKGBUILD code ran on this machine."
fi

# ---------------------------------------------------------------- quarantine
if want quarantine; then
  step "2. Temporal quarantine and the advisory fast-path"
  echo "fastmover 0.9 was published minutes ago:"
  "$BIN/loom-testbed" set-age fastmover 1 >/dev/null
  rebuild_all fastmover
  run "$BIN/loom" verify fastmover || true
  echo
  echo "tlsprobe 2.0.1 is also brand-new, but it fixes a CVE. Load the advisory feed:"
  cat > "$LOOM_HOME/adv.json" <<JSON
[{"name":"AVG-2026-1","packages":["tlsprobe"],"status":"Fixed","severity":"Critical","affected":"2.0-1","fixed":"2.0.1-1","issues":["CVE-2026-31337"]}]
JSON
  run "$BIN/loom-testbed" advisories "$LOOM_HOME/adv.json"
  "$BIN/loom-testbed" set-age tlsprobe 1 >/dev/null
  rebuild_all tlsprobe
  run "$BIN/loom" verify tlsprobe || true
  conclude "Quarantine is waived only because the advisory feed says the new version remediates a vulnerability (FR-7.3)."
fi

# ---------------------------------------------------------------- orphan
if want orphan; then
  step "3. Orphan-adoption attack (June–Aug 2026 AUR waves)"
  echo "orphan-tool 1.0 was maintained by bob. Install it cleanly first:"
  rebuild_all orphan-tool
  run "$BIN/loom" install orphan-tool
  echo
  echo "Now 'mallory' adopts the orphaned package and ships 1.1, whose build"
  echo "tries to read \$HOME and phone home. Publish the adoption:"
  run "$BIN/loom-testbed" publish orphan-tool 1.1-1 --maintainer mallory
  "$BIN/loom-testbed" set-age orphan-tool 720 >/dev/null   # clear quarantine to isolate continuity
  rebuild_all orphan-tool
  echo
  b "loom install orphan-tool  (upgrade):"
  run "$BIN/loom" install orphan-tool || true
  echo
  conclude "Loom blocks on the maintainer change (FR-8.5) before building anything. Independently, no rebuilder would vouch for 1.1: its build reached for \$HOME and the network."
fi

# ---------------------------------------------------------------- npm inject
if want npm; then
  step "4. Build-time network injection (Atomic Arch 'npm install' in PKGBUILD)"
  rebuild_all npm-helper
  run "$BIN/loom" install npm-helper
  echo
  echo "carol's account is compromised; npm-helper 2.5 fetches a payload at build time."
  run "$BIN/loom-testbed" publish npm-helper 2.5-1 --maintainer carol
  "$BIN/loom-testbed" set-age npm-helper 720 >/dev/null
  "$BIN/loom-testbed" sink --clear >/dev/null
  echo
  echo "The rebuilders build it under Heddle. The payload swallows its own errors"
  echo "(|| true), so the build exits 0 — but it reached for \$HOME and the network,"
  echo "so every rebuilder refuses to vouch for it:"
  rebuild_all npm-helper
  echo
  echo "No attestations, so the client would have to build it itself. Forcing that:"
  run "$BIN/loom" verify npm-helper --build || true
  echo
  b "did anything reach the network sink?"
  run "$BIN/loom-testbed" sink
  conclude "No rebuilder would vouch for npm-helper 2.5, and the client rejects its own confined build of it. The payload exited 0, but it reached for credentials and the network, and nothing reached the sink."
fi

# ---------------------------------------------------------------- forcepush
if want forcepush; then
  step "5. Force-push / history rewrite + a planted pacman hook (TeamPCP)"
  rebuild_all forcepush-lib
  run "$BIN/loom" install forcepush-lib
  echo
  echo "The maintainer force-pushes a rewritten 3.1 that also installs an alpm hook:"
  run "$BIN/loom-testbed" publish forcepush-lib 3.1-1-rewrite --maintainer frank --rewrite
  "$BIN/loom-testbed" set-age forcepush-lib 720 >/dev/null
  rebuild_all forcepush-lib
  run "$BIN/loom" verify forcepush-lib || true
  echo
  echo "Suppose the user reviews the rewrite and overrides the continuity alarm."
  echo "The artifact still carries a pacman hook — a persistence vector:"
  OV=$("$BIN/loom" override add continuity forcepush-lib --reason "demo: reviewed rewrite" | grep -oP '#\K[0-9]+')
  run "$BIN/loom" verify forcepush-lib || true
  "$BIN/loom" override rm "$OV" >/dev/null
  conclude "Loom detects the non-linear history (FR-8.4). Even with that alarm overridden, the placement policy independently blocks the planted pacman hook (audit A4)."
fi

# ---------------------------------------------------------------- placement
if want placement; then
  step "6. Python .pth startup hook (LiteLLM vector) — placement policy"
  rebuild_all pth-inject
  run "$BIN/loom" verify pth-inject --build || true
  conclude "The .pth file would execute on every Python start; the placement policy blocks it (audit A4)."
fi

# ---------------------------------------------------------------- sandbox
if want sandbox; then
  step "7. Sandbox contrast — same build, confined vs unconfined"
  echo "We plant a decoy canary in \$HOME and run npm-helper 2.5's build two ways."
  echo "loom-probe > \$HOME/.loom-canary"; echo "loom-canary-secret" > "$HOME/.loom-canary"
  "$BIN/loom-testbed" publish npm-helper 2.5-1 --maintainer carol >/dev/null
  "$BIN/loom-testbed" set-age npm-helper 720 >/dev/null
  "$BIN/loom-testbed" sink --clear >/dev/null
  echo
  b "(a) confined (Heddle, tier $TIER):"
  LOOM_HEDDLE_BACKEND=kernel "$BIN/loom" verify npm-helper --build 2>&1 | sed 's/^/    /' || true
  CONF_HITS=$("$BIN/loom-testbed" sink | grep -c HIT || true)
  echo
  b "(b) UNCONFINED (what a plain AUR helper does):"
  "$BIN/loom-testbed" sink --clear >/dev/null
  LOOM_HEDDLE_BACKEND=unconfined-demo LOOM_DEMO_VICTIM_HOME="$HOME" \
    "$BIN/loom" verify npm-helper --build 2>&1 | sed 's/^/    /' || true
  UNCONF_HITS=$("$BIN/loom-testbed" sink | grep -c HIT || true)
  echo
  b "network sink hits:  confined=$CONF_HITS   unconfined=$UNCONF_HITS"
  note sink "confined vs unconfined sink hits" --set confined="$CONF_HITS" --set unconfined="$UNCONF_HITS"
  run "$BIN/loom-testbed" sink
  rm -f "$HOME/.loom-canary"
  conclude "Under Heddle the build cannot read \$HOME or reach the network; unconfined, the same build phones home."
fi

# ---------------------------------------------------------------- split view
if want splitview; then
  step "8. Split-view attack on the log — detected by honest witnesses"
  echo "Restarting Warp in split-view mode with one CORRUPT witness (cosigns anything)."
  kill $PIDS 2>/dev/null; sleep 1
  sed 's/split_view = false/split_view = true/' "$LOOM_HOME/svc/warp.toml" > "$LOOM_HOME/svc/warp-sv.toml"
  sed 's/evil = false/evil = true/' "$LOOM_HOME/svc/witness-3.toml" > "$LOOM_HOME/svc/witness-3-evil.toml"
  "$BIN/loom-testbed" serve >"$LOG/aur.log" 2>&1 &
  "$BIN/loomd" warp --config "$LOOM_HOME/svc/warp-sv.toml" >"$LOG/warp.log" 2>&1 &
  "$BIN/loomd" witness --config "$LOOM_HOME/svc/witness-1.toml" >"$LOG/w1.log" 2>&1 &
  "$BIN/loomd" witness --config "$LOOM_HOME/svc/witness-2.toml" >"$LOG/w2.log" 2>&1 &
  "$BIN/loomd" witness --config "$LOOM_HOME/svc/witness-3-evil.toml" >"$LOG/w3.log" 2>&1 &
  start_peers
  "$BIN/loom-testbed" dashboard --listen "$HOST:$DASH_PORT" >"$LOG/dashboard.log" 2>&1 &
  PIDS="$(jobs -p | tr '\n' ' ')"
  note attack "Warp restarted in split-view mode; witness-3 corrupted" --set corrupt_witness=witness-3 --set victim=victim
  sleep 2
  rebuild_all libweft hello-loom >/dev/null
  echo "The victim client syncs the honest history:"
  LOOM_CLIENT_ID=victim "$BIN/loom" log | sed 's/^/  /'
  echo
  echo "The log operator forks the victim's view:"
  run "$BIN/loomd" fork --log http://$HOST:7710 --victim victim
  echo
  echo "alice pushes a new commit of hello-loom. Honest rebuilders a and b attest it"
  echo "to the PUBLIC history, which the honest witnesses cosign:"
  "$BIN/loom-testbed" publish hello-loom 1.2-1 --maintainer alice >/dev/null
  "$BIN/loom-testbed" set-age hello-loom 720 >/dev/null   # a routine commit, past quarantine
  for t in thread-a thread-b; do
    "$BIN/loomd" thread --config "$LOOM_HOME/svc/$t.toml" --once --package hello-loom 2>&1 | sed "s/^/  [$t] /"
  done
  echo
  echo "Meanwhile the operator colludes with a compromised thread-c: a BACKDOORED"
  echo "hello-loom attestation goes only into the victim's forked history:"
  sed 's/tamper = false/tamper = true/' "$LOOM_HOME/svc/thread-c.toml" > "$LOOM_HOME/svc/thread-c-evil.toml"
  "$BIN/loomd" thread --config "$LOOM_HOME/svc/thread-c-evil.toml" --once --package hello-loom --into-fork 2>&1 \
    | sed "s/^/  [thread-c, compromised → fork] /"
  echo
  b "victim re-syncs:"
  LOOM_CLIENT_ID=victim "$BIN/loom" log 2>&1 | sed 's/^/  /' || true
  echo
  echo
  b "an uninvolved client syncs the public history:"
  "$BIN/loom" log 2>&1 | sed 's/^/  /' || true
  echo
  conclude "The honest witnesses refused to cosign the fork, so the victim's client rejects it (1 < 2-of-3 witness threshold) and never trusts the backdoored attestation, while everyone else keeps the one public history (NFR-SEC-5)."
fi

# ---------------------------------------------------------------- audit
if want audit; then
  step "9. Read-only provenance audit"
  echo "Install a couple of packages, then report coverage without touching state:"
  "$BIN/loom" install hello-loom >/dev/null 2>&1
  "$BIN/loom-testbed" set-age orphan-tool 720 >/dev/null
  "$BIN/loom" install orphan-tool >/dev/null 2>&1
  run "$BIN/loom" audit || true
  conclude "Every installed package is backed by independent attestations in the verified log, and orphan-tool's change of maintainer stays flagged even though the upgrade was refused."
fi

# ---------------------------------------------------------------- report
echo; hr
if [ "$SCENARIO" = all ]; then
  echo "Running the acceptance-criteria harness for the report…"
  "$BIN/loom-eval" --json >"$LOOM_HOME/eval.json" 2>/dev/null || true
fi
"$BIN/loom-testbed" report --out "$LOOM_HOME/report.html"
b "demo complete — logs under $LOG"
if [ "${LOOM_HOLD:-0}" = 1 ]; then
  echo "services and dashboard stay up at http://$HOST:$DASH_PORT — Ctrl-C to stop"
  wait
fi
