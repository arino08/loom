# Loom — The Heddle Sandbox

Heddle (`loom-heddle`) runs every PKGBUILD, build step and install scriptlet
under enforced least privilege. This document explains the layers, how to check
what your host provides, and — honestly — what the sandbox does and does not
guarantee.

## Checking your host

```sh
loom sandbox-check
```

reports the tier this host achieves:

- **full** — user, mount, network, PID, IPC, UTS and cgroup namespaces, a
  pivot-rooted minimal tmpfs, Landlock, and seccomp. Needs unprivileged user
  namespaces (most desktop distros; some harden them off).
- **reduced** — Landlock + seccomp only (no namespaces). The build still cannot
  read your home or credentials or reach the network, but there is no filesystem
  *virtualisation*: enforcement is by Landlock's allowlist rather than by the
  paths simply not existing. Loom reports this as reduced assurance (NFR-MNT-3).
- **refused** — if Landlock itself is unavailable (kernel < 5.13 or landlock not
  in the LSM list), Loom refuses to build rather than run unconfined (NFR-SEC-1).

`sandbox_min_tier` in `policy.toml` sets the floor.

## The layers (full tier)

1. **Mount namespace.** The sandbox root is a fresh tmpfs at a per-process
   mountpoint, entered with `pivot_root` and the old root detached. It contains
   only: read-only binds of `/usr`, `/bin`, `/lib`, `/opt`; a **curated** subset
   of `/etc` (passwd/group, ld.so config, CA certificates, makepkg.conf, locale
   — *not* the pacman keyring, host SSH keys, sudoers, or network credentials); a
   minimal `/dev`; a private `/proc` and `/tmp`; and the build directory at
   `/build`. Your home, `/root`, `/run`, `/var`, `/srv`, `/mnt` do not exist
   inside. (FR-3.1, FR-3.2)

2. **Landlock** (ABI up to v6). A filesystem allowlist (read+execute on the
   toolchain, full access to the build dir and `/tmp`), TCP bind/connect
   restriction, and abstract-UNIX-socket + signal scoping. This is the only FS
   enforcement in the reduced tier. (FR-3.2, FR-3.3, FR-3.4)

3. **seccomp-BPF + supervisor.** A hand-assembled classic-BPF filter:
   - kills the process on a foreign audit architecture; rejects the x32 ABI;
   - returns `EPERM` for `mount`, `unshare`, `setns`, `ptrace`, `bpf`,
     `io_uring_*` (which would bypass seccomp), `keyctl`, module loading, and
     other privileged calls (FR-3.6);
   - returns `ENOSYS` for `clone3` so libc falls back to `clone`, whose namespace
     flags are then refused;
   - forwards `socket()` for any family but `AF_UNIX`, and path-opening calls, to
     a user-notification supervisor that **logs the denial with the rule that
     fired** (FR-3.7) and answers `EACCES`.

   The supervisor is used only to *explain* denials, never as the sole enforcer:
   file access is enforced by the namespace and Landlock, and the supervisor lets
   the kernel make the final decision (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`) for
   anything it does not itself deny, so the well-known user-notification TOCTOU
   cannot weaken confinement.

Nothing survives a build: the PID namespace and a process-group `SIGKILL` leave
no residual processes, and the sandbox's mounts vanish with the namespace
(NFR-REL-3).

## Declared network fetches (FR-3.5)

Builds have no network by default. Sources are fetched and hash-verified by
trusted Loom code *before* the sandbox starts; an unpinned remote source (a
`SKIP` checksum, or a mutable VCS source) is refused rather than fetched. A
package that genuinely needs build-time network can be granted a recorded,
per-package exception (`allow_network`, or `loom override add sandbox-network`),
which `loom audit` then lists.

## Install scripts

The artifact handed to `pacman -U` has its `.INSTALL` scriptlet **removed**, so
pacman never runs it as root unconfined. Loom runs install scripts itself, under
Heddle, according to `install_scripts` (`sandbox` / `deny` / `allowlist`).

## What the sandbox does not do

- It does not stop a build that only does legitimate things (compile, link,
  install into the build dir). Reproducible-build attestation, not the sandbox,
  is what catches an artifact that does not correspond to its source.
- It does not detect malicious *source* that every rebuilder reproduces
  identically (SRS OOS-5) — that is outside what any of Loom's mechanisms claim.
- It assumes a correctly configured host kernel; a Landlock/seccomp escape on
  such a kernel is out of scope (SRS OOS-3), as is a shared compromised compiler
  toolchain (the Thompson attack, OOS-6), which toolchain diversity mitigates but
  does not eliminate.

## Verifying it yourself

```sh
LOOM_KERNEL_TESTS=1 cargo test -p loom-heddle --test escape
```

runs the adversarial suite: each of FR-3.2–3.6 has a corresponding escape attempt
that must fail (read a canary in `$HOME`, read `/etc/shadow`, write a `.pth` into
`/usr`, open a TCP/UDP connection, nest a user namespace, ptrace). The suite also
checks that a background process started by a build is killed when the build
ends (NFR-REL-3).
