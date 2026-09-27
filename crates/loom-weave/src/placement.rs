//! Artifact placement policy (audit item A4).
//!
//! The SRS confines *build-time* behaviour, but a package can also carry its
//! payload in *what it installs*: a libalpm hook runs as root on every later
//! pacman transaction, `/etc/ld.so.preload` injects into every process, a
//! `.pth` file runs Python code at every interpreter start (the LiteLLM
//! incident), a setuid binary is a privilege-escalation primitive. None of
//! these require the build to misbehave, so the sandbox cannot see them.
//! Loom inspects the artifact's file list before installation and blocks
//! persistence/privilege vectors unless explicitly allowed per package.

use loom_core::ecosystem::{ArtifactManifest, FileKind};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Blocks under the default `placement = "block"`.
    Critical,
    /// Reported for information only.
    Notice,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub path: String,
    pub severity: Severity,
    pub reason: String,
}

const CRITICAL_PREFIXES: &[(&str, &str)] = &[
    ("/usr/share/libalpm/hooks/", "pacman hook: runs as root on every future package transaction"),
    ("/etc/pacman.d/hooks/", "pacman hook: runs as root on every future package transaction"),
    ("/etc/ld.so.preload", "preloads a library into every process on the system"),
    ("/etc/sudoers", "changes sudo privileges"),
    ("/etc/pam.d/", "changes authentication (PAM) configuration"),
    ("/usr/lib/security/", "installs a PAM module (runs inside authentication)"),
    ("/etc/profile.d/", "runs in every login shell"),
    ("/etc/environment", "changes every session's environment"),
    ("/etc/cron", "installs scheduled jobs"),
    ("/var/spool/cron/", "installs scheduled jobs"),
    ("/etc/systemd/system/", "enables/overrides system services (persistence)"),
    ("/usr/lib/systemd/system-generators/", "systemd generator: runs as root at boot"),
    ("/etc/xdg/autostart/", "autostarts in every desktop session"),
    ("/etc/ssh/", "changes SSH configuration or keys"),
    ("/home/", "writes into user home directories"),
    ("/root/", "writes into root's home directory"),
    ("/tmp/", "installs into a temporary directory"),
    ("/var/tmp/", "installs into a temporary directory"),
    ("/run/", "writes into runtime state"),
    ("/dev/", "writes device nodes"),
    ("/proc/", "writes into procfs"),
    ("/sys/", "writes into sysfs"),
    ("/boot/", "modifies the boot partition"),
];

const NOTICE_PREFIXES: &[(&str, &str)] = &[
    ("/usr/lib/udev/rules.d/", "udev rule: runs on device events"),
    ("/usr/lib/systemd/system/", "ships a system service (not enabled by the package)"),
    ("/usr/lib/modules-load.d/", "loads kernel modules at boot"),
    ("/usr/lib/sysctl.d/", "changes kernel parameters at boot"),
];

pub fn analyse(m: &ArtifactManifest, allow: &[String]) -> Vec<Finding> {
    let mut out = vec![];
    for f in &m.files {
        if f.kind == FileKind::Dir {
            continue;
        }
        if allow.iter().any(|a| &f.path == a || (a.ends_with('/') && f.path.starts_with(a.as_str()))) {
            continue;
        }
        if let Some((_, why)) = CRITICAL_PREFIXES.iter().find(|(p, _)| f.path.starts_with(p)) {
            out.push(Finding { path: f.path.clone(), severity: Severity::Critical, reason: why.to_string() });
            continue;
        }
        if f.kind == FileKind::File && f.mode & 0o6000 != 0 {
            out.push(Finding {
                path: f.path.clone(),
                severity: Severity::Critical,
                reason: format!("{} binary (mode {:o})", if f.mode & 0o4000 != 0 { "setuid" } else { "setgid" }, f.mode),
            });
            continue;
        }
        if f.notes.iter().any(|n| n == "python-startup-hook") {
            out.push(Finding {
                path: f.path.clone(),
                severity: Severity::Critical,
                reason: ".pth file with import lines: executes on every Python start (LiteLLM-style)".into(),
            });
            continue;
        }
        if let Some((_, why)) = NOTICE_PREFIXES.iter().find(|(p, _)| f.path.starts_with(p)) {
            out.push(Finding { path: f.path.clone(), severity: Severity::Notice, reason: why.to_string() });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use loom_core::ecosystem::ArtifactFile;

    fn file(p: &str, mode: u32, notes: &[&str]) -> ArtifactFile {
        ArtifactFile { path: p.into(), mode, kind: FileKind::File, size: 1, notes: notes.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn findings() {
        let m = ArtifactManifest {
            files: vec![
                file("/usr/bin/hello", 0o755, &[]),
                file("/usr/share/libalpm/hooks/zz-evil.hook", 0o644, &[]),
                file("/usr/bin/su-helper", 0o4755, &[]),
                file("/usr/lib/python3.13/site-packages/x.pth", 0o644, &["python-startup-hook"]),
                file("/usr/lib/python3.13/site-packages/ok.pth", 0o644, &[]),
                file("/usr/lib/udev/rules.d/70-dev.rules", 0o644, &[]),
            ],
            ..Default::default()
        };
        let f = analyse(&m, &[]);
        let crit: Vec<_> = f.iter().filter(|x| x.severity == Severity::Critical).map(|x| x.path.as_str()).collect();
        assert_eq!(crit.len(), 3, "{f:?}");
        assert!(f.iter().any(|x| x.severity == Severity::Notice));
        // Explicit allow list.
        let f = analyse(&m, &["/usr/share/libalpm/hooks/".into(), "/usr/bin/su-helper".into()]);
        assert_eq!(f.iter().filter(|x| x.severity == Severity::Critical).count(), 1);
    }
}
