#!/bin/bash
# Loom build driver — a minimal, makepkg-compatible executor for a PKGBUILD.
#
# Runs *inside* Heddle. Sources were fetched and hash-verified by Loom before
# the sandbox started (FR-3.5); this script never touches the network.
# It extracts archives, sources the PKGBUILD and runs prepare/build/check/
# package, then leaves the install tree in $BUILD_ROOT/pkg for Loom to pack
# deterministically.
set -uo pipefail
umask "${LOOM_UMASK:-022}"

: "${BUILD_ROOT:?}"
cd "$BUILD_ROOT" || exit 90
export startdir="$BUILD_ROOT"
export srcdir="$BUILD_ROOT/src"
export pkgdir="$BUILD_ROOT/pkg"
rm -rf "$srcdir" "$pkgdir"
mkdir -p "$srcdir" "$pkgdir"

# makepkg.conf-equivalent defaults (reproducible: no host-specific flags).
export CARCH="${CARCH:-x86_64}"
export CHOST="${CHOST:-x86_64-pc-linux-gnu}"
export CFLAGS="${CFLAGS:--O2 -pipe -fno-plt -ffile-prefix-map=$srcdir=/usr/src/debug}"
export CXXFLAGS="${CXXFLAGS:-$CFLAGS}"
export LDFLAGS="${LDFLAGS:--Wl,-O1,--sort-common,--as-needed}"
export MAKEFLAGS="${MAKEFLAGS:--j2}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

msg() { printf '==> %s\n' "$*"; }

# Link/extract sources into $srcdir as makepkg does.
shopt -s nullglob
for f in "$BUILD_ROOT"/sources/*; do
  name=$(basename "$f")
  ln -sf "$f" "$srcdir/$name"
  case "$name" in
    *.tar|*.tar.gz|*.tgz|*.tar.bz2|*.tbz2|*.tar.xz|*.txz|*.tar.zst|*.tzst)
      msg "Extracting $name"
      tar -xf "$f" -C "$srcdir" --no-same-owner --no-same-permissions || { msg "ERROR: failed to extract $name"; exit 92; }
      ;;
  esac
done

msg "Sourcing PKGBUILD"
# shellcheck disable=SC1091
source ./PKGBUILD || { msg "ERROR: PKGBUILD failed to source"; exit 90; }

run_fn() {
  local fn=$1
  if declare -F "$fn" >/dev/null; then
    msg "Running $fn()"
    ( cd "$srcdir"; set -e; "$fn" )
    local rc=$?
    if [ "$rc" -ne 0 ]; then
      msg "ERROR: $fn() failed with status $rc"
      exit 91
    fi
  fi
}

run_fn prepare
run_fn build
[ "${LOOM_SKIP_CHECK:-0}" = 1 ] || run_fn check
if declare -F package >/dev/null; then
  run_fn package
else
  run_fn "package_${pkgname[0]}"
fi
msg "Build finished"
