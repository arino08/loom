//! The AUR ecosystem backend (all AUR/PKGBUILD knowledge lives here, NFR-MNT-1).

pub mod git;
pub mod package;
pub mod srcinfo;

use anyhow::Context;
use loom_core::digest::Digest;
use loom_core::ecosystem::{ArtifactManifest, Backend, BuildPlan, Checkout, PackageMeta, SourceInput};
use loom_core::http::Client;
use serde::Deserialize;
use sha2::Digest as _;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const DRIVER: &str = include_str!("driver.sh");

#[derive(Clone, Debug)]
pub struct AurConfig {
    /// e.g. `https://aur.archlinux.org/rpc/v5`
    pub rpc: String,
    /// e.g. `https://aur.archlinux.org/{pkgbase}.git`
    pub git_template: String,
    /// e.g. `https://aur.archlinux.org/packages.gz`
    pub packages_list: String,
    pub carch: String,
    /// Content-addressed cache for downloaded sources.
    pub source_cache: PathBuf,
}

impl AurConfig {
    pub fn official(cache: &Path) -> Self {
        AurConfig {
            rpc: "https://aur.archlinux.org/rpc/v5".into(),
            git_template: "https://aur.archlinux.org/{pkgbase}.git".into(),
            packages_list: "https://aur.archlinux.org/packages.gz".into(),
            carch: std::env::consts::ARCH.into(),
            source_cache: cache.join("sources"),
        }
    }
}

pub struct AurBackend {
    pub cfg: AurConfig,
    http: Client,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct RpcResult {
    Name: String,
    PackageBase: String,
    Version: String,
    #[serde(default)]
    Description: Option<String>,
    #[serde(default)]
    Maintainer: Option<String>,
    #[serde(default)]
    CoMaintainers: Vec<String>,
    FirstSubmitted: i64,
    LastModified: i64,
    #[serde(default)]
    Depends: Vec<String>,
    #[serde(default)]
    MakeDepends: Vec<String>,
}

#[derive(Deserialize)]
struct RpcResponse {
    #[serde(default)]
    results: Vec<RpcResult>,
    #[serde(default)]
    error: Option<String>,
}

fn verify_pin(alg: &str, expected: &str, data: &[u8]) -> bool {
    let got = match alg {
        "sha256sums" => hex::encode(sha2::Sha256::digest(data)),
        "sha512sums" => hex::encode(sha2::Sha512::digest(data)),
        "b2sums" => hex::encode(blake2::Blake2b512::digest(data)),
        _ => return false,
    };
    got.eq_ignore_ascii_case(expected.trim())
}

impl AurBackend {
    pub fn new(cfg: AurConfig) -> Self {
        AurBackend {
            cfg,
            http: Client::new(Duration::from_secs(10)),
        }
    }

    fn git_url(&self, base: &str) -> String {
        self.cfg.git_template.replace("{pkgbase}", base)
    }

    fn fetch_remote(&self, url: &str) -> anyhow::Result<Vec<u8>> {
        Ok(self.http.get(url).with_context(|| format!("fetching {url}"))?)
    }

    pub fn srcinfo(&self, checkout: &Checkout) -> anyhow::Result<srcinfo::SrcInfo> {
        let text = std::fs::read_to_string(checkout.dir.join(".SRCINFO"))
            .context("package has no .SRCINFO")?;
        srcinfo::parse(&text, &self.cfg.carch)
    }
}

fn safe_name(n: &str) -> anyhow::Result<()> {
    if n.is_empty() || n.contains('/') || n == "." || n == ".." || n.starts_with('.') && n.len() <= 2 {
        anyhow::bail!("unsafe source file name {n:?}");
    }
    Ok(())
}

fn copy_recipe(src: &Path, dst: &Path) -> anyhow::Result<Vec<(String, Digest)>> {
    let mut files = vec![];
    let mut entries: Vec<_> = std::fs::read_dir(src)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let name = e.file_name().to_string_lossy().to_string();
        let meta = std::fs::symlink_metadata(e.path())?;
        if !meta.is_file() {
            continue; // AUR repos are flat; ignore dirs/symlinks
        }
        let data = std::fs::read(e.path())?;
        std::fs::write(dst.join(&name), &data)?;
        files.push((name, Digest::of(&data)));
    }
    Ok(files)
}

impl Backend for AurBackend {
    fn ecosystem(&self) -> &'static str {
        "aur"
    }

    fn resolve(&self, names: &[String]) -> anyhow::Result<Vec<PackageMeta>> {
        if names.is_empty() {
            return Ok(vec![]);
        }
        let q: Vec<String> = names.iter().map(|n| format!("arg[]={n}")).collect();
        let url = format!("{}/info?{}", self.cfg.rpc, q.join("&"));
        let body = self.http.get(&url).with_context(|| format!("AUR RPC {url}"))?;
        let resp: RpcResponse = serde_json::from_slice(&body).context("AUR RPC response")?;
        if let Some(e) = resp.error {
            anyhow::bail!("AUR RPC error: {e}");
        }
        Ok(resp
            .results
            .into_iter()
            .map(|r| PackageMeta {
                repo_url: self.git_url(&r.PackageBase),
                name: r.Name,
                base: r.PackageBase,
                version: r.Version,
                description: r.Description.unwrap_or_default(),
                maintainer: r.Maintainer,
                co_maintainers: r.CoMaintainers,
                first_submitted: r.FirstSubmitted,
                last_modified: r.LastModified,
                depends: r.Depends.iter().map(|d| srcinfo::dep_name(d)).collect(),
                make_depends: r.MakeDepends.iter().map(|d| srcinfo::dep_name(d)).collect(),
            })
            .collect())
    }

    fn list_packages(&self) -> anyhow::Result<Vec<String>> {
        let body = self.http.get(&self.cfg.packages_list)?;
        let text = if body.starts_with(&[0x1f, 0x8b]) {
            let mut s = String::new();
            flate2::read::GzDecoder::new(body.as_slice()).read_to_string(&mut s)?;
            s
        } else {
            String::from_utf8(body)?
        };
        Ok(text
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.to_string())
            .collect())
    }

    fn checkout(&self, meta: &PackageMeta, cache: &Path) -> anyhow::Result<Checkout> {
        let mirror = cache.join("git").join(format!("{}.git", meta.base));
        git::sync_mirror(&meta.repo_url, &mirror)
            .with_context(|| format!("fetching recipe for {}", meta.base))?;
        let commit = git::head(&mirror)?;
        let commit_time = git::commit_time(&mirror, &commit)?;
        let tags = git::tags(&mirror)?;
        let dir = cache.join("work").join(format!("{}-{}", meta.base, &commit[..12]));
        if !dir.join(".SRCINFO").exists() {
            let _ = std::fs::remove_dir_all(&dir);
            git::export(&mirror, &commit, &dir)?;
        }
        let si = srcinfo::parse(
            &std::fs::read_to_string(dir.join(".SRCINFO")).context("package has no .SRCINFO")?,
            &self.cfg.carch,
        )?;
        Ok(Checkout {
            dir,
            mirror,
            commit,
            commit_time,
            tags,
            signing_keys: si.validpgpkeys.clone(),
            version: si.full_version(),
        })
    }

    fn is_ancestor(&self, checkout: &Checkout, baseline: &str) -> anyhow::Result<bool> {
        git::is_ancestor(&checkout.mirror, baseline, &checkout.commit)
    }

    fn prepare_build(&self, checkout: &Checkout, meta: &PackageMeta, workdir: &Path) -> anyhow::Result<BuildPlan> {
        let si = self.srcinfo(checkout)?;
        if workdir.exists() {
            std::fs::remove_dir_all(workdir)?;
        }
        std::fs::create_dir_all(workdir.join("sources"))?;
        std::fs::create_dir_all(workdir.join(".loom"))?;
        let recipe = copy_recipe(&checkout.dir, workdir)?;

        let mut inputs = vec![];
        let mut unpinned = vec![];
        for (i, entry) in si.sources.iter().enumerate() {
            let (fname, loc) = srcinfo::source_parts(entry);
            safe_name(&fname)?;
            // Strongest declared pin that is not SKIP.
            let pins: Vec<(&str, &str)> = ["b2sums", "sha512sums", "sha256sums"]
                .iter()
                .filter_map(|a| si.sums.get(*a).map(|l| (*a, l[i].as_str())))
                .filter(|(_, v)| !v.eq_ignore_ascii_case("SKIP"))
                .collect();
            let remote = srcinfo::is_remote(&loc);
            if remote && srcinfo::is_vcs(&loc) {
                unpinned.push(format!(
                    "{fname}: VCS source {loc} has no content hash (mutable; Loom cannot pin it)"
                ));
                continue;
            }
            if remote && pins.is_empty() {
                unpinned.push(format!("{fname}: remote source {loc} is not pinned (checksum SKIP or missing)"));
                continue;
            }
            let data = if remote {
                let key = format!("{}-{}", pins[0].0, pins[0].1);
                let cached = self.cfg.source_cache.join(&key);
                match std::fs::read(&cached) {
                    Ok(d) if verify_pin(pins[0].0, pins[0].1, &d) => d,
                    _ => {
                        let d = self.fetch_remote(&loc)?;
                        std::fs::create_dir_all(&self.cfg.source_cache)?;
                        std::fs::write(&cached, &d)?;
                        d
                    }
                }
            } else {
                std::fs::read(checkout.dir.join(&fname))
                    .with_context(|| format!("local source {fname} missing from recipe"))?
            };
            for (alg, want) in &pins {
                if !verify_pin(alg, want, &data) {
                    anyhow::bail!(
                        "source {fname} does not match its pinned {alg} (FR-1.5): refusing to build"
                    );
                }
            }
            std::fs::write(workdir.join("sources").join(&fname), &data)?;
            inputs.push(SourceInput {
                filename: fname,
                location: loc,
                remote,
                pinned: Some(Digest::of(&data)),
            });
        }

        #[derive(serde::Serialize)]
        struct SourceDigestInput<'a> {
            commit: &'a str,
            recipe: &'a [(String, Digest)],
            inputs: Vec<(&'a str, Option<Digest>)>,
        }
        let source_digest = Digest::of(&loom_core::canon::to_vec(&SourceDigestInput {
            commit: &checkout.commit,
            recipe: &recipe,
            inputs: inputs.iter().map(|i| (i.filename.as_str(), i.pinned)).collect(),
        })?);

        std::fs::write(workdir.join(".loom/driver.sh"), DRIVER)?;
        let env = BTreeMap::from([
            ("SOURCE_DATE_EPOCH".to_string(), checkout.commit_time.to_string()),
            ("CARCH".to_string(), self.cfg.carch.clone()),
            ("LOOM_PACKAGE".to_string(), meta.name.clone()),
        ]);
        Ok(BuildPlan {
            workdir: workdir.to_path_buf(),
            argv: vec!["/bin/bash".into(), ".loom/driver.sh".into()],
            env,
            source_digest,
            inputs,
            unpinned,
            output_subdir: "pkg".into(),
            source_date_epoch: checkout.commit_time,
            install_script: si.install.clone(),
        })
    }

    fn package(&self, plan: &BuildPlan, _meta: &PackageMeta) -> anyhow::Result<Vec<u8>> {
        let si = srcinfo::parse(
            &std::fs::read_to_string(plan.workdir.join(".SRCINFO"))?,
            &self.cfg.carch,
        )?;
        let install = match &plan.install_script {
            Some(n) => {
                safe_name(n)?;
                Some(std::fs::read(plan.workdir.join(n)).with_context(|| format!("install script {n}"))?)
            }
            None => None,
        };
        package::pack(&package::PackInput {
            pkgdir: &plan.workdir.join(&plan.output_subdir),
            info: &si,
            install_script: install.as_deref(),
            source_date_epoch: plan.source_date_epoch,
            carch: &self.cfg.carch,
        })
    }

    fn inspect(&self, artifact: &[u8]) -> anyhow::Result<ArtifactManifest> {
        package::inspect(artifact)
    }

    fn is_official(&self, name: &str) -> bool {
        std::process::Command::new("pacman")
            .args(["-Si", name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins() {
        let d = b"hello";
        assert!(verify_pin("sha256sums", "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", d));
        assert!(!verify_pin("sha256sums", "00", d));
        assert!(verify_pin("b2sums", &hex::encode(blake2::Blake2b512::digest(d)), d));
    }

    #[test]
    fn names() {
        assert!(safe_name("../x").is_err());
        assert!(safe_name("a/b").is_err());
        assert!(safe_name("hello.c").is_ok());
    }
}
