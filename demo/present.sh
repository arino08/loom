#!/usr/bin/env bash
# ===========================================================================
# Guided live demo for the major-project review.
#
# Steps through the demo scenarios one keypress at a time, so nobody types
# commands on stage. For each step it shows whose turn it is and what to point
# at, runs the scenario (demo/run.sh with LOOM_HOLD=1), keeps the services and
# the console (http://127.0.0.1:7790) up while the presenter talks, and stops
# everything cleanly before the next step.
#
# Usage:  demo/present.sh              start at step 1
#         demo/present.sh --from 6     start at step 6 (e.g. after a hiccup)
#         demo/present.sh --list       list the steps and exit
#
# Keys:   Enter  run the step / stop it and move on
#         s      skip this step
#         r      (while a step is running) stop it and run it again
#         q      stop everything and quit
# ===========================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$ROOT/demo/run.sh"
CONSOLE="http://127.0.0.1:${LOOM_DASHBOARD_PORT:-7790}"

# step = presenter | scenario | title | what to point at
STEPS=(
  "3|healthy|Healthy package: verify, don't build|'ALLOWED … from peer' and 'post_install() ran under Heddle': no PKGBUILD code ran on this machine"
  "3|quarantine|Temporal quarantine and the advisory fast-path|'fastmover … BLOCKED … 2d 22h remaining', then 'tlsprobe … ALLOWED' (the CVE fix skips the wait)"
  "3|orphan|Orphan-adoption attack|the rebuilders' 'refused: build attempted …' lines, then 'BLOCKED … maintainer changed: bob → mallory'"
  "3|npm|Build-time network injection (npm install in a PKGBUILD)|'BLOCKED … exit 0; 2 hostile access attempt(s)' and '(sink empty — no build reached the network)'"
  "3|sandbox|Sandbox contrast: same build, confined vs unconfined|'network sink hits: confined=0 unconfined=1' and the HIT line"
  "4|forcepush|Force-push plus a planted pacman hook|'history rewritten … does not descend', then '[OVRD] continuity' and '[FAIL] … pacman hook'"
  "4|placement|Python .pth startup hook (LiteLLM vector)|'BLOCKED … .pth file with import lines: executes on every Python start'"
  "4|splitview|Split-view attack on the transparency log|'1 valid witness cosignature(s) [witness-3]; policy requires 2 of 3', then the honest size-8 view"
  "4|all|Finale: all nine scenarios with the live console (≈70 s)|switch to the browser: the defence matrix fills in, red cells in every column"
)

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  B=$'\033[1m'; D=$'\033[2m'; A=$'\033[38;5;214m'; G=$'\033[32m'; R=$'\033[31m'; I=$'\033[38;5;111m'; N=$'\033[0m'
else
  B=; D=; A=; G=; R=; I=; N=
fi
line(){ printf '%s\n' "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; }
field(){ local IFS='|'; read -r F_WHO F_SC F_TITLE F_CUE <<<"$1"; }

list_steps(){
  local i=1
  for s in "${STEPS[@]}"; do
    field "$s"
    printf '  %s%d%s  Presenter %s  %-10s  %s\n' "$B" "$i" "$N" "$F_WHO" "$F_SC" "$F_TITLE"
    i=$((i + 1))
  done
}

FROM=1
case "${1:-}" in
  --list) list_steps; exit 0 ;;
  --from) FROM="${2:-1}" ;;
  -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
  "") ;;
  *) echo "unknown option: $1 (try --help)"; exit 2 ;;
esac
if ! [[ "$FROM" =~ ^[0-9]+$ ]] || [ "$FROM" -lt 1 ] || [ "$FROM" -gt "${#STEPS[@]}" ]; then
  echo "--from expects a step number between 1 and ${#STEPS[@]}"; exit 2
fi

# ---- pre-flight -------------------------------------------------------------
preflight(){
  local ok=1
  echo "${B}Pre-flight checks${N}"
  for t in git gcc curl python3 ss pkill; do
    if command -v "$t" >/dev/null 2>&1; then echo "  ${G}✓${N} $t"
    else echo "  ${R}✗${N} $t is missing — install it before the demo"; ok=0; fi
  done
  if [ -x "$ROOT/target/debug/loom" ] && [ -x "$ROOT/target/debug/loomd" ] && [ -x "$ROOT/target/debug/loom-testbed" ]; then
    echo "  ${G}✓${N} Loom binaries are built"
  else
    echo "  ${A}!${N} Loom is not built yet — building now (cargo build)…"
    ( cd "$ROOT" && cargo build -q ) && echo "  ${G}✓${N} built" || { echo "  ${R}✗${N} cargo build failed"; ok=0; }
  fi
  if [ -d "$ROOT/demo/fixtures/hello-loom" ]; then
    echo "  ${G}✓${N} package fixtures are present"
  else
    echo "  ${A}!${N} fixtures missing — generating (python3 demo/fixtures/genfix.py)…"
    python3 "$ROOT/demo/fixtures/genfix.py" >/dev/null && echo "  ${G}✓${N} generated" || { echo "  ${R}✗${N} fixture generation failed"; ok=0; }
  fi
  [ "$ok" = 1 ] || { echo; echo "${R}Fix the items above, then run demo/present.sh again.${N}"; exit 1; }
}

# ---- running a step ---------------------------------------------------------
CHILD=
READY=
stop_step(){
  if [ -n "$CHILD" ] && kill -0 "$CHILD" 2>/dev/null; then
    kill -TERM "$CHILD" 2>/dev/null
    wait "$CHILD" 2>/dev/null
  fi
  CHILD=
}
on_interrupt(){ echo; echo "${A}Stopping the demo…${N}"; stop_step; exit 130; }
trap on_interrupt INT TERM
trap 'stop_step; [ -n "$READY" ] && rm -f "$READY"' EXIT

key(){ local k; IFS= read -rsn1 k </dev/tty || k=q; printf '%s' "$k"; }

run_step(){ # $1 = scenario
  READY="$(mktemp -u "${TMPDIR:-/tmp}/loom-present.XXXXXX")"
  local arg=("$1"); [ "$1" = all ] && arg=()
  printf '\033[2J\033[H'
  LOOM_HOLD=1 LOOM_READY_FILE="$READY" "$RUN" "${arg[@]}" &
  CHILD=$!
  while [ ! -e "$READY" ]; do
    if ! kill -0 "$CHILD" 2>/dev/null; then
      wait "$CHILD" 2>/dev/null; CHILD=
      echo; echo "${R}The scenario stopped unexpectedly.${N} Press Enter to try it again, s to skip, q to quit."
      return 1
    fi
    sleep 0.2
  done
  rm -f "$READY"; sleep 0.3
  return 0
}

# ---- main loop ----------------------------------------------------------------
preflight
echo
echo "${B}Loom live demo${N} — ${#STEPS[@]} steps. Keep ${I}$CONSOLE${N} open in the browser next to this window."
echo "It reconnects by itself whenever a step starts."
list_steps
echo

i=$FROM
prev_who=
while [ "$i" -le "${#STEPS[@]}" ]; do
  field "${STEPS[$((i - 1))]}"
  echo
  if [ -n "$prev_who" ] && [ "$prev_who" != "$F_WHO" ]; then
    line; echo "${A}${B}  HANDOVER: Presenter $prev_who → Presenter $F_WHO takes the keyboard${N}"; line
  fi
  line
  echo "${B}  Step $i of ${#STEPS[@]} · Presenter $F_WHO · $F_TITLE${N}"
  echo "  ${D}scenario: $F_SC${N}"
  echo "  ${A}Point at:${N} $F_CUE"
  line
  if [ "$F_SC" = all ]; then
    echo "  Enter = run the finale · s = skip it (open docs/demo-report.html instead) · q = quit"
  else
    echo "  Enter = run · s = skip · q = quit"
  fi
  case "$(key)" in
    q) exit 0 ;;
    s) echo "  skipped"; prev_who=$F_WHO; i=$((i + 1)); continue ;;
  esac
  while :; do
    if run_step "$F_SC"; then
      echo
      line
      echo "${G}${B}  ▶ Step $i is live.${N} Console: ${I}$CONSOLE${N}"
      echo "  ${A}Point at:${N} $F_CUE"
      if [ "$i" -lt "${#STEPS[@]}" ]; then
        field "${STEPS[$i]}"; echo "  ${D}Next: step $((i + 1)), Presenter $F_WHO — $F_TITLE${N}"; field "${STEPS[$((i - 1))]}"
      fi
      echo "  Enter = stop and continue · r = run this step again · q = quit"
      line
      k="$(key)"
      stop_step
      case "$k" in
        r) continue ;;
        q) exit 0 ;;
        *) break ;;
      esac
    else
      k="$(key)"
      case "$k" in
        s) break ;;
        q) exit 0 ;;
        *) continue ;;
      esac
    fi
  done
  prev_who=$F_WHO
  i=$((i + 1))
done

echo
line
echo "${G}${B}  Demo complete.${N} Everything is stopped. Presenter 4: return to the slides at slide 13."
line
