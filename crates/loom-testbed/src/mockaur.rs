//! A scenario-driven mock of the AUR, for the demo and evaluation.
//!
//! It stands in for the four external read-only surfaces Loom talks to:
//!   * the AUR RPC `info` interface (maintainer, version, deps);
//!   * per-package git repositories (built from the fixtures as real commits,
//!     so force-push and orphan adoption are genuine git history);
//!   * upstream source downloads (pinned by hash);
//!   * the Arch security advisory feed.
//!
//! It also runs the demo's LOCAL sink: the endpoint the simulated payloads
//! try (and, thanks to Heddle, fail) to reach. The sink records every hit so
//! the demo can assert that a *blocked* build produced no hit while an
//! *unconfined* one did (E1/E4).
//!
//! Placeholders in fixtures are rewritten at publish time: `@AUR@` → this
//! server's base URL, `@SHA256:name@` → the hash of `upstream/name`.

use loom_core::digest::Digest;
use loom_core::http::{Handler, Request, Response};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PkgState {
    pub base: String,
    pub version: String,
    pub maintainer: Option<String>,
    pub last_modified: i64,
    pub depends: Vec<String>,
    pub make_depends: Vec<String>,
    pub commit: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Scenario {
    pub packages: BTreeMap<String, PkgState>,
    #[serde(default)]
    pub advisories: Vec<serde_json::Value>,
    #[serde(default)]
    pub sink_hits: Vec<String>,
}

pub struct MockAur {
    root: PathBuf,
    fixtures: PathBuf,
    base_url: Mutex<String>,
    scenario: Mutex<Scenario>,
}

fn git(dir: &Path, args: &[&str]) -> anyhow::Result<String> {
    let out = Command::new("git")
        .args(["-C", dir.to_str().unwrap()])
        .args(args)
        .env("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()?;
    if !out.status.success() {
        anyhow::bail!("git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

impl MockAur {
    pub fn open(root: &Path, fixtures: &Path) -> anyhow::Result<Arc<Self>> {
        std::fs::create_dir_all(root.join("git"))?;
        std::fs::create_dir_all(root.join("work"))?;
        let scen = match std::fs::read(root.join("scenario.json")) {
            Ok(b) => serde_json::from_slice(&b)?,
            Err(_) => Scenario::default(),
        };
        Ok(Arc::new(MockAur {
            root: root.to_path_buf(),
            fixtures: fixtures.to_path_buf(),
            base_url: Mutex::new(String::new()),
            scenario: Mutex::new(scen),
        }))
    }

    pub fn set_base_url(&self, url: &str) {
        *self.base_url.lock().unwrap() = url.trim_end_matches('/').to_string();
    }

    pub fn repo_path(&self, base: &str) -> PathBuf {
        self.root.join("git").join(format!("{base}.git"))
    }

    pub fn repo_url(&self, base: &str) -> String {
        format!("file://{}", self.repo_path(base).display())
    }

    fn save(&self) -> anyhow::Result<()> {
        let s = self.scenario.lock().unwrap();
        std::fs::write(self.root.join("scenario.json"), serde_json::to_vec_pretty(&*s)?)?;
        Ok(())
    }

    /// Read the scenario fresh from disk. The serving process and the CLI
    /// mutation commands are separate processes, so the server must not cache
    /// state across requests.
    fn current(&self) -> Scenario {
        match std::fs::read(self.root.join("scenario.json")) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_default(),
            Err(_) => self.scenario.lock().unwrap().clone(),
        }
    }

    fn upstream_hash(&self, name: &str) -> anyhow::Result<String> {
        let p = self.fixtures.join("upstream").join(name);
        Ok(Digest::of_file(&p)?.hex())
    }

    fn rewrite(&self, text: &str) -> anyhow::Result<String> {
        let base = self.base_url.lock().unwrap().clone();
        let mut out = text.replace("@AUR@", &base);
        while let Some(i) = out.find("@SHA256:") {
            let rest = &out[i + 8..];
            let end = rest.find('@').ok_or_else(|| anyhow::anyhow!("unterminated @SHA256:"))?;
            let name = &rest[..end];
            let h = self.upstream_hash(name)?;
            out = format!("{}{}{}", &out[..i], h, &out[i + 8 + end + 1..]);
        }
        Ok(out)
    }

    /// Publish a fixture version as a commit on the package's branch.
    /// `rewrite_history` resets the branch first (force-push simulation).
    pub fn publish(&self, pkg: &str, dir: &str, maintainer: &str, rewrite_history: bool) -> anyhow::Result<String> {
        let src = self.fixtures.join(pkg).join(dir);
        if !src.join(".SRCINFO").exists() {
            anyhow::bail!("fixture {}/{} has no .SRCINFO", pkg, dir);
        }
        let si_text = self.rewrite(&std::fs::read_to_string(src.join(".SRCINFO"))?)?;
        let si = loom_aur::srcinfo::parse(&si_text, std::env::consts::ARCH)?;
        let base = si.pkgbase.clone();
        let repo = self.repo_path(&base);
        let work = self.root.join("work").join(&base);

        if !repo.exists() {
            git(&self.root, &["init", "--quiet", "--bare", repo.to_str().unwrap()])?;
        }
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work)?;
        git(&work, &["init", "--quiet", "-b", "master"])?;
        git(&work, &["config", "user.email", &format!("{maintainer}@aur")])?;
        git(&work, &["config", "user.name", maintainer])?;
        git(&work, &["remote", "add", "origin", repo.to_str().unwrap()])?;
        if !rewrite_history {
            // Continue existing history if any.
            let _ = git(&work, &["fetch", "--quiet", "origin", "master"]);
            let _ = git(&work, &["reset", "--quiet", "--hard", "FETCH_HEAD"]);
            for f in std::fs::read_dir(&work)? {
                let f = f?;
                if f.file_name() != ".git" {
                    let _ = std::fs::remove_file(f.path());
                    let _ = std::fs::remove_dir_all(f.path());
                }
            }
        }
        // Materialise the (placeholder-rewritten) recipe.
        for e in std::fs::read_dir(&src)? {
            let e = e?;
            if !e.file_type()?.is_file() {
                continue;
            }
            let name = e.file_name();
            let raw = std::fs::read(e.path())?;
            let data = match std::str::from_utf8(&raw) {
                Ok(t) => self.rewrite(t)?.into_bytes(),
                Err(_) => raw,
            };
            std::fs::write(work.join(&name), data)?;
        }
        git(&work, &["add", "-A"])?;
        git(&work, &["commit", "--quiet", "-m", &format!("{base} {}", si.full_version()), "--allow-empty"])?;
        let force = if rewrite_history { "+" } else { "" };
        git(&work, &["push", "--quiet", "origin", &format!("{force}HEAD:master")])?;
        let commit = git(&repo, &["rev-parse", "master"])?;

        let maint = if maintainer == "orphan" { None } else { Some(maintainer.to_string()) };
        let mut s = self.scenario.lock().unwrap();
        let prev_submitted = s.packages.get(&base).map(|p| p.last_modified).unwrap_or(loom_core::time::now());
        s.packages.insert(
            base.clone(),
            PkgState {
                base: base.clone(),
                version: si.full_version(),
                maintainer: maint,
                last_modified: loom_core::time::now(),
                depends: si.depends.iter().map(|d| loom_aur::srcinfo::dep_name(d)).collect(),
                make_depends: si.makedepends.iter().map(|d| loom_aur::srcinfo::dep_name(d)).collect(),
                commit: commit.clone(),
            },
        );
        let _ = prev_submitted;
        drop(s);
        self.save()?;
        Ok(commit)
    }

    pub fn set_published(&self, pkg: &str, ts: i64) -> anyhow::Result<()> {
        let mut s = self.scenario.lock().unwrap();
        if let Some(p) = s.packages.get_mut(pkg) {
            p.last_modified = ts;
        }
        drop(s);
        self.save()
    }

    pub fn set_advisories(&self, adv: Vec<serde_json::Value>) -> anyhow::Result<()> {
        self.scenario.lock().unwrap().advisories = adv;
        self.save()
    }

    pub fn sink_hits(&self) -> Vec<String> {
        self.current().sink_hits
    }

    pub fn clear_sink(&self) -> anyhow::Result<()> {
        self.scenario.lock().unwrap().sink_hits.clear();
        self.save()
    }

    pub fn handler(self: Arc<Self>) -> Handler {
        Arc::new(move |r: &Request| self.handle(r))
    }

    fn rpc_info(&self, names: &[String]) -> Response {
        let s = self.current();
        let results: Vec<serde_json::Value> = names
            .iter()
            .filter_map(|n| s.packages.get(n))
            .map(|p| {
                serde_json::json!({
                    "Name": p.base,
                    "PackageBase": p.base,
                    "Version": p.version,
                    "Description": format!("{} (mock AUR)", p.base),
                    "Maintainer": p.maintainer,
                    "CoMaintainers": [],
                    "FirstSubmitted": 1_700_000_000,
                    "LastModified": p.last_modified,
                    "Depends": p.depends,
                    "MakeDepends": p.make_depends,
                })
            })
            .collect();
        Response::json(&serde_json::json!({
            "resultcount": results.len(),
            "results": results,
            "type": "multiinfo",
            "version": 5,
        }))
    }

    fn handle(&self, r: &Request) -> Response {
        // AUR RPC v5: /rpc/v5/info?arg[]=a&arg[]=b  (also &arg[0][]= style)
        if r.path.starts_with("/rpc") {
            let names: Vec<String> = r
                .query_pairs
                .iter()
                .filter(|(k, _)| k.starts_with("arg"))
                .map(|(_, v)| v.clone())
                .collect();
            return self.rpc_info(&names);
        }
        if let Some(name) = r.path.strip_prefix("/upstream/") {
            let p = self.fixtures.join("upstream").join(name);
            return match std::fs::read(&p) {
                Ok(b) => Response::bytes(200, "application/octet-stream", b),
                Err(_) => Response::not_found(),
            };
        }
        if r.path == "/packages.gz" || r.path == "/packages" {
            let s = self.current();
            let body = s.packages.keys().cloned().collect::<Vec<_>>().join("\n");
            return Response::bytes(200, "text/plain", body.into_bytes());
        }
        if r.path == "/advisories.json" || r.path == "/all.json" {
            return Response::json(&self.current().advisories);
        }
        // The demo sink: record the hit, always answer 200 so an *unconfined*
        // build "succeeds" in reaching it (making the contrast with a
        // sandboxed build stark).
        if r.path == "/sink" || r.path.starts_with("/sink") {
            let tag = format!(
                "{} {}",
                loom_core::time::rfc3339(loom_core::time::now()),
                r.query.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&")
            );
            let mut cur = self.current();
            cur.sink_hits.push(tag);
            let _ = std::fs::write(self.root.join("scenario.json"), serde_json::to_vec_pretty(&cur).unwrap_or_default());
            *self.scenario.lock().unwrap() = cur;
            return Response::text(200, "recorded-by-demo-sink\n");
        }
        if r.path == "/sink/hits" {
            return Response::json(&self.sink_hits());
        }
        Response::not_found()
    }
}
