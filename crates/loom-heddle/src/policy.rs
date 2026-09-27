//! The access policy that every confinement layer implements.
//!
//! One declarative description is compiled into (a) the mount namespace
//! layout, (b) the Landlock ruleset, and (c) the seccomp supervisor's
//! classifier used to *explain* denials (FR-3.7). Keeping a single source of
//! truth means the explanation a user sees always names the rule the kernel
//! actually enforced.

use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

/// Why an access was refused. The `rule` strings are stable identifiers shown
/// to users and written to the structured log (NFR-OBS-2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    pub rule: String,
    pub requirement: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessPolicy {
    /// Read + execute allowed beneath these (inside-sandbox) paths.
    pub read: Vec<PathBuf>,
    /// Full access beneath these (inside-sandbox) paths.
    pub write: Vec<PathBuf>,
}

/// Path components that identify credential stores (FR-3.2). A read of any
/// path containing one of these is reported as a credential-access attempt
/// even when the path does not exist inside the sandbox.
pub const CREDENTIAL_MARKERS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".npmrc",
    ".aws",
    ".gitconfig",
    ".git-credentials",
    ".netrc",
    ".docker",
    ".kube",
    ".config",
    ".pypirc",
    ".cargo/credentials",
    ".password-store",
    ".local/share/keyrings",
    ".mozilla",
    "id_rsa",
    "id_ed25519",
];

/// System locations exposed read-only inside the sandbox. `/etc` is *not*
/// exposed wholesale: see [`ETC_ALLOWLIST`].
pub const SYSTEM_READ: &[&str] = &["/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt"];

/// The subset of `/etc` a build legitimately needs. Everything else (host
/// keys, pacman keyring, network credentials, sudoers, ...) stays invisible.
pub const ETC_ALLOWLIST: &[&str] = &[
    "passwd",
    "group",
    "nsswitch.conf",
    "ld.so.cache",
    "ld.so.conf",
    "ld.so.conf.d",
    "localtime",
    "makepkg.conf",
    "ssl",
    "ca-certificates",
    "alternatives",
    "bash.bashrc",
    "profile",
    "inputrc",
    "os-release",
    "locale.conf",
    "mime.types",
    "protocols",
    "services",
];

/// Lexically normalise a path (resolve `.` and `..`, no filesystem access).
pub fn normalise(p: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    for c in p.components() {
        match c {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(s) => out.push(s),
        }
    }
    out
}

impl AccessPolicy {
    /// Policy for a build whose writable root is `build_root` (inside view).
    pub fn for_build(build_root: &Path, extra_read: &[PathBuf]) -> Self {
        let mut read: Vec<PathBuf> = SYSTEM_READ.iter().map(PathBuf::from).collect();
        read.extend(ETC_ALLOWLIST.iter().map(|e| Path::new("/etc").join(e)));
        read.push("/proc".into());
        read.push("/dev".into());
        read.extend(extra_read.iter().cloned());
        let write = vec![
            build_root.to_path_buf(),
            "/tmp".into(),
            "/dev/null".into(),
            "/dev/zero".into(),
            "/dev/full".into(),
            "/dev/shm".into(),
            "/dev/tty".into(),
        ];
        AccessPolicy { read, write }
    }

    fn beneath(list: &[PathBuf], p: &Path) -> bool {
        list.iter().any(|base| p.starts_with(base))
    }

    /// Classify an access. `None` = permitted.
    pub fn classify(&self, path: &Path, write: bool) -> Option<Verdict> {
        let p = normalise(path);
        if Self::beneath(&self.write, &p) {
            return None;
        }
        let s = p.to_string_lossy();
        let credential = CREDENTIAL_MARKERS.iter().any(|m| {
            s.contains(&format!("/{m}/")) || s.ends_with(&format!("/{m}"))
        }) || p.starts_with("/home")
            || p.starts_with("/root")
            || p.starts_with("/run/user");
        if credential {
            return Some(Verdict {
                rule: "deny-home-and-credentials".into(),
                requirement: "FR-3.2".into(),
                reason: format!("build attempted to access user/credential path {s}"),
            });
        }
        if write {
            return Some(Verdict {
                rule: "deny-write-outside-build".into(),
                requirement: "FR-3.3".into(),
                reason: format!("build attempted to write {s}, outside the build directory"),
            });
        }
        if Self::beneath(&self.read, &p) {
            return None;
        }
        Some(Verdict {
            rule: "deny-undeclared-read".into(),
            requirement: "FR-3.1".into(),
            reason: format!("build attempted to read undeclared path {s}"),
        })
    }
}

pub fn network_verdict(what: &str) -> Verdict {
    Verdict {
        rule: "deny-network".into(),
        requirement: "FR-3.4".into(),
        reason: format!("build attempted network access ({what}); builds run with no network — declare sources with pinned hashes instead (FR-3.5)"),
    }
}

pub fn syscall_verdict(name: &str) -> Verdict {
    Verdict {
        rule: "deny-dangerous-syscall".into(),
        requirement: "FR-3.6".into(),
        reason: format!("build attempted restricted system call {name}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pol() -> AccessPolicy {
        AccessPolicy::for_build(Path::new("/build"), &[])
    }

    #[test]
    fn build_dir_is_writable() {
        assert!(pol().classify(Path::new("/build/src/x.o"), true).is_none());
        assert!(pol().classify(Path::new("/tmp/cc123.s"), true).is_none());
    }

    #[test]
    fn credentials_denied_even_by_traversal() {
        for p in [
            "/home/alice/.ssh/id_ed25519",
            "/build/../home/alice/.aws/credentials",
            "/root/.gnupg/secring.gpg",
            "/build/home/.npmrc/../.ssh",
        ] {
            let v = pol().classify(Path::new(p), false);
            // The last case normalises to /build/home/.ssh which is inside
            // the build dir (the sandbox's own empty HOME) and is allowed.
            if p.starts_with("/build/home") {
                assert!(v.is_none(), "{p}");
            } else {
                assert_eq!(v.unwrap().requirement, "FR-3.2", "{p}");
            }
        }
    }

    #[test]
    fn writes_outside_build_denied() {
        let v = pol().classify(Path::new("/usr/lib/python3.13/site-packages/evil.pth"), true);
        assert_eq!(v.unwrap().requirement, "FR-3.3");
    }

    #[test]
    fn etc_is_curated() {
        assert!(pol().classify(Path::new("/etc/passwd"), false).is_none());
        assert!(pol().classify(Path::new("/etc/ssl/certs/ca.pem"), false).is_none());
        let v = pol().classify(Path::new("/etc/ssh/ssh_host_ed25519_key"), false).unwrap();
        assert_eq!(v.requirement, "FR-3.1");
        assert!(pol().classify(Path::new("/usr/bin/gcc"), false).is_none());
    }
}
