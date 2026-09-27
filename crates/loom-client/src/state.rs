//! Persistent client state: continuity baselines (FR-8.1), the installed
//! package database, user overrides (FR-3.8, FR-7.2) and the structured
//! decision log (NFR-OBS-1). All JSON, written atomically.

use loom_core::digest::Digest;
use loom_weave::continuity::Baseline;
use loom_weave::eval::{Decision, Override, OverrideKind};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

fn load<T: DeserializeOwned + Default>(p: &Path) -> anyhow::Result<T> {
    match std::fs::read(p) {
        Ok(b) => Ok(serde_json::from_slice(&b).map_err(|e| anyhow::anyhow!("{} is corrupt: {e}", p.display()))?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(e.into()),
    }
}

fn save<T: Serialize>(p: &Path, v: &T) -> anyhow::Result<()> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(v)?)?;
    std::fs::rename(tmp, p)?;
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Installed {
    pub name: String,
    pub version: String,
    pub digest: Digest,
    pub installed_at: i64,
    pub published: i64,
    pub files: Vec<String>,
    pub install_script: bool,
    /// What happened to the install script: ran-sandboxed / skipped / none.
    pub install_script_action: String,
    /// Where the artifact came from: "peer ..." / "local build (tier)".
    pub origin: String,
    pub independent_attestations: usize,
    pub outcome: String,
    pub as_dependency: bool,
}

pub struct State {
    pub dir: PathBuf,
    /// Audit mode: never write (FR-10.2).
    pub read_only: bool,
}

impl State {
    pub fn new(dir: &Path, read_only: bool) -> Self {
        State { dir: dir.to_path_buf(), read_only }
    }

    fn p(&self, n: &str) -> PathBuf {
        self.dir.join(n)
    }

    pub fn baselines(&self) -> anyhow::Result<BTreeMap<String, Baseline>> {
        load(&self.p("baselines.json"))
    }

    pub fn set_baseline(&self, b: Baseline) -> anyhow::Result<()> {
        if self.read_only {
            return Ok(());
        }
        let mut all = self.baselines()?;
        all.insert(b.package.clone(), b);
        save(&self.p("baselines.json"), &all)
    }

    pub fn installed(&self) -> anyhow::Result<BTreeMap<String, Installed>> {
        load(&self.p("installed.json"))
    }

    pub fn set_installed(&self, i: Installed) -> anyhow::Result<()> {
        if self.read_only {
            return Ok(());
        }
        let mut all = self.installed()?;
        all.insert(i.name.clone(), i);
        save(&self.p("installed.json"), &all)
    }

    pub fn overrides(&self) -> anyhow::Result<Vec<Override>> {
        load(&self.p("overrides.json"))
    }

    pub fn add_override(&self, kind: OverrideKind, package: &str, version: Option<&str>, reason: &str) -> anyhow::Result<Override> {
        if reason.trim().is_empty() {
            anyhow::bail!("an override needs a --reason (it is recorded and shown by `loom audit`)");
        }
        if kind.needs_version() && version.is_none() {
            anyhow::bail!("a {} override must name a specific version (FR-7.2)", kind.as_str());
        }
        let mut all = self.overrides()?;
        let o = Override {
            id: all.iter().map(|o| o.id).max().unwrap_or(0) + 1,
            kind,
            package: package.into(),
            version: version.map(|s| s.into()),
            reason: reason.into(),
            created_at: loom_core::time::now(),
            user: std::env::var("USER").unwrap_or_else(|_| "unknown".into()),
        };
        all.push(o.clone());
        save(&self.p("overrides.json"), &all)?;
        Ok(o)
    }

    pub fn remove_override(&self, id: u64) -> anyhow::Result<bool> {
        let mut all = self.overrides()?;
        let n = all.len();
        all.retain(|o| o.id != id);
        save(&self.p("overrides.json"), &all)?;
        Ok(all.len() != n)
    }

    /// Continuity overrides are consumed once the new authority becomes the
    /// baseline, so a *later* change is caught again.
    pub fn consume_continuity_override(&self, package: &str) -> anyhow::Result<()> {
        if self.read_only {
            return Ok(());
        }
        let mut all = self.overrides()?;
        all.retain(|o| !(o.kind == OverrideKind::Continuity && o.package == package));
        save(&self.p("overrides.json"), &all)
    }

    /// Append a decision to the structured log (NFR-OBS-1).
    pub fn log_decision(&self, d: &Decision) -> anyhow::Result<()> {
        if self.read_only {
            return Ok(());
        }
        std::fs::create_dir_all(&self.dir)?;
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(self.p("decisions.jsonl"))?;
        #[derive(Serialize)]
        struct Line<'a> {
            ts: i64,
            package: &'a str,
            version: &'a str,
            stage: &'a str,
            outcome: &'a loom_weave::Outcome,
            target: Option<String>,
            independent_support: usize,
            rules: Vec<serde_json::Value>,
        }
        let line = Line {
            ts: d.timestamp,
            package: &d.package,
            version: &d.version,
            stage: &d.stage,
            outcome: &d.outcome,
            target: d.target.map(|t| t.to_string()),
            independent_support: d.independent_support,
            rules: d
                .rules
                .iter()
                .map(|r| serde_json::json!({"id": r.id, "status": r.status, "summary": r.summary}))
                .collect(),
        };
        writeln!(f, "{}", serde_json::to_string(&line)?)?;
        Ok(())
    }
}
