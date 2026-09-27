//! Installing a verified artifact.
//!
//! The artifact handed to the system package manager has its `.INSTALL`
//! scriptlet removed: pacman would otherwise run it as root, unconfined.
//! Loom runs install scripts itself, under Heddle, according to the
//! `install_scripts` policy (FR-3.1, audit item A5).

use loom_heddle::{Backend as Sandbox, RunReport, SandboxSpec, Tier};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub enum Installer {
    /// `pacman -U` (the real system path; FR-1.4).
    Pacman { pkg_cache: PathBuf },
    /// Extract into a directory tree (demo / tests / containers).
    Root { root: PathBuf },
}

impl Installer {
    pub fn describe(&self) -> String {
        match self {
            Installer::Pacman { .. } => "pacman -U".into(),
            Installer::Root { root } => format!("extract into {}", root.display()),
        }
    }

    /// Install `artifact` (already stripped of `.INSTALL`). Returns the list
    /// of installed paths.
    pub fn install(
        &self,
        name: &str,
        version: &str,
        artifact: &[u8],
        previous_files: &[String],
        as_dependency: bool,
    ) -> anyhow::Result<Vec<String>> {
        match self {
            Installer::Pacman { pkg_cache } => {
                std::fs::create_dir_all(pkg_cache)?;
                let file = pkg_cache.join(format!("{name}-{version}-{}.pkg.tar.gz", std::env::consts::ARCH));
                std::fs::write(&file, artifact)?;
                let root = unsafe { libc::geteuid() } == 0;
                let mut cmd = if root {
                    std::process::Command::new("pacman")
                } else {
                    let mut c = std::process::Command::new("sudo");
                    c.arg("pacman");
                    c
                };
                cmd.args(["-U", "--noconfirm"]);
                if as_dependency {
                    cmd.arg("--asdeps");
                }
                cmd.arg(&file);
                let st = cmd.status()?;
                if !st.success() {
                    anyhow::bail!("pacman -U failed ({st})");
                }
                Ok(list_files(artifact)?)
            }
            Installer::Root { root } => install_into_root(root, name, artifact, previous_files),
        }
    }
}

pub fn list_files(artifact: &[u8]) -> anyhow::Result<Vec<String>> {
    let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(artifact));
    let mut out = vec![];
    for e in ar.entries()? {
        let e = e?;
        let p = e.path()?.to_string_lossy().trim_end_matches('/').to_string();
        if p.starts_with('.') && !p.contains('/') {
            continue;
        }
        if e.header().entry_type() != tar::EntryType::Directory {
            out.push(format!("/{p}"));
        }
    }
    Ok(out)
}

/// Staged install: extract into a staging dir inside the root (same
/// filesystem), then rename each file into place. The installed-database
/// entry is written by the caller only after this returns, so an interrupted
/// install is never recorded as complete (NFR-REL-3).
fn install_into_root(root: &Path, name: &str, artifact: &[u8], previous: &[String]) -> anyhow::Result<Vec<String>> {
    let staging = root.join(".loom-staging").join(name);
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging)?;
    let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(artifact));
    ar.set_preserve_permissions(true);
    ar.set_overwrite(true);
    for e in ar.entries()? {
        let mut e = e?;
        let p = e.path()?.to_string_lossy().to_string();
        if p.starts_with('.') && !p.contains('/') {
            let mut sink = vec![];
            e.read_to_end(&mut sink)?;
            continue;
        }
        // unpack_in refuses paths escaping the staging dir.
        if !e.unpack_in(&staging)? {
            anyhow::bail!("artifact entry {p} escapes the install root");
        }
    }
    let mut files = vec![];
    fn walk(base: &Path, rel: &Path, root: &Path, files: &mut Vec<String>) -> anyhow::Result<()> {
        for e in std::fs::read_dir(base.join(rel))? {
            let e = e?;
            let r = rel.join(e.file_name());
            let meta = std::fs::symlink_metadata(e.path())?;
            if meta.is_dir() {
                std::fs::create_dir_all(root.join(&r))?;
                walk(base, &r, root, files)?;
            } else {
                let dst = root.join(&r);
                if let Some(d) = dst.parent() {
                    std::fs::create_dir_all(d)?;
                }
                std::fs::rename(e.path(), &dst)?;
                files.push(format!("/{}", r.display()));
            }
        }
        Ok(())
    }
    walk(&staging, Path::new(""), root, &mut files)?;
    let _ = std::fs::remove_dir_all(&staging);
    for old in previous {
        if !files.contains(old) {
            let _ = std::fs::remove_file(root.join(old.trim_start_matches('/')));
        }
    }
    files.sort();
    Ok(files)
}

/// Run a package's install-time function under Heddle.
pub fn run_install_hook(
    script: &str,
    function: &str,
    version: &str,
    work: &Path,
    sandbox: &Sandbox,
    min_tier: Tier,
) -> anyhow::Result<Option<RunReport>> {
    if !script.contains(function) {
        return Ok(None);
    }
    let _ = std::fs::remove_dir_all(work);
    std::fs::create_dir_all(work)?;
    std::fs::write(work.join("dot-install.sh"), script)?;
    std::fs::write(
        work.join("run-hook.sh"),
        format!("#!/bin/bash\nsource ./dot-install.sh\nif declare -F {function} >/dev/null; then {function} \"$1\"; fi\n"),
    )?;
    let mut spec = SandboxSpec::new(work, vec!["/bin/bash".into(), "run-hook.sh".into(), version.into()]);
    spec.min_tier = min_tier;
    spec.timeout = Duration::from_secs(120);
    Ok(Some(loom_heddle::run(&spec, sandbox)?))
}
