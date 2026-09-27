//! Git operations on AUR package repositories (read-only; FR-1.2, FR-8.4).
//!
//! Loom keeps a bare mirror per package base. Automatic garbage collection is
//! disabled, so after a force-push the previously observed commit is still
//! present locally and `merge-base --is-ancestor` can prove the rewrite.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

fn git(dir: Option<&Path>) -> Command {
    let mut c = Command::new("git");
    if let Some(d) = dir {
        c.arg("--git-dir").arg(d);
    }
    c.args(["-c", "gc.auto=0", "-c", "core.hooksPath=/dev/null"])
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE");
    c
}

fn run(mut c: Command, what: &str) -> anyhow::Result<String> {
    let out = c.output().map_err(|e| anyhow::anyhow!("{what}: cannot run git: {e}"))?;
    if !out.status.success() {
        anyhow::bail!("{what}: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Clone or update the bare mirror at `mirror` from `url`.
pub fn sync_mirror(url: &str, mirror: &Path) -> anyhow::Result<()> {
    if mirror.join("HEAD").exists() {
        let mut c = git(Some(mirror));
        c.args(["fetch", "--prune", "--force", "--tags", url, "+refs/heads/*:refs/heads/*"]);
        run(c, "git fetch")?;
    } else {
        if let Some(p) = mirror.parent() {
            std::fs::create_dir_all(p)?;
        }
        let mut c = git(None);
        c.args(["clone", "--mirror", "--quiet", url]).arg(mirror);
        run(c, "git clone")?;
    }
    Ok(())
}

pub fn head(mirror: &Path) -> anyhow::Result<String> {
    let mut c = git(Some(mirror));
    c.args(["rev-parse", "HEAD"]);
    run(c, "git rev-parse")
}

pub fn commit_time(mirror: &Path, rev: &str) -> anyhow::Result<i64> {
    let mut c = git(Some(mirror));
    c.args(["log", "-1", "--format=%ct", rev]);
    Ok(run(c, "git log")?.parse()?)
}

pub fn tags(mirror: &Path) -> anyhow::Result<BTreeMap<String, String>> {
    let mut c = git(Some(mirror));
    c.args(["for-each-ref", "--format=%(refname:short) %(objectname)", "refs/tags"]);
    Ok(run(c, "git for-each-ref")?
        .lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .collect())
}

pub fn show(mirror: &Path, rev: &str, file: &str) -> anyhow::Result<String> {
    let mut c = git(Some(mirror));
    c.args(["show", &format!("{rev}:{file}")]);
    run(c, "git show")
}

/// `true` if `old` is an ancestor of `new`; `false` if not, or if `old` no
/// longer exists (history rewritten and garbage-collected upstream).
pub fn is_ancestor(mirror: &Path, old: &str, new: &str) -> anyhow::Result<bool> {
    let mut c = git(Some(mirror));
    c.args(["merge-base", "--is-ancestor", old, new]);
    let st = c.status()?;
    Ok(st.success())
}

/// Export the tree at `rev` into `dest` (no hooks, no .git).
pub fn export(mirror: &Path, rev: &str, dest: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dest)?;
    let mut c = git(Some(mirror));
    c.args(["archive", "--format=tar", rev]);
    let out = c.output()?;
    if !out.status.success() {
        anyhow::bail!("git archive: {}", String::from_utf8_lossy(&out.stderr));
    }
    let mut ar = tar::Archive::new(std::io::Cursor::new(out.stdout));
    ar.set_preserve_permissions(false);
    ar.unpack(dest)?;
    Ok(())
}

/// List files (path, blob contents digest) in the tree at `rev`.
pub fn tree_files(mirror: &Path, rev: &str) -> anyhow::Result<Vec<String>> {
    let mut c = git(Some(mirror));
    c.args(["ls-tree", "-r", "--name-only", rev]);
    Ok(run(c, "git ls-tree")?.lines().map(|s| s.to_string()).collect())
}
