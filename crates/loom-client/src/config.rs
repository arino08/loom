//! Client configuration: endpoints and the bundled root of trust.
//!
//! `loom.toml` holds *who is trusted* (log key, witness keys, rebuilder keys
//! and organisations, revocation authorities) and *where they are*.
//! `policy.toml` holds *how much evidence is required* (FR-9.1). Both are
//! parsed strictly; a malformed file is fatal (FR-9.4).
//!
//! Locations: `$LOOM_HOME/{etc,state,cache}` when `LOOM_HOME` is set (tests,
//! demo), otherwise `/etc/loom`, `$XDG_STATE_HOME/loom`, `$XDG_CACHE_HOME/loom`.

use loom_core::keys::PublicKey;
use loom_weave::Policy;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AurSection {
    pub rpc: String,
    pub git: String,
    #[serde(default = "d_packages")]
    pub packages: String,
}

fn d_packages() -> String {
    "https://aur.archlinux.org/packages.gz".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSection {
    pub url: String,
    pub origin: String,
    /// Note verifier key (`<origin>+<id>+<b64>`).
    pub key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessEntry {
    pub name: String,
    pub key: String,
    pub url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RebuilderEntry {
    pub id: String,
    pub org: String,
    pub key: String,
    pub url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokerEntry {
    pub name: String,
    pub key: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeersSection {
    #[serde(default)]
    pub urls: Vec<String>,
    /// Where `loom serve` listens (FR-2.4).
    pub listen: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallSection {
    /// `pacman` or `root` (extract into `root`, for demos and tests).
    pub backend: String,
    pub root: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxSection {
    /// `kernel` (default) or `unconfined-demo`.
    pub backend: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub aur: AurSection,
    pub log: LogSection,
    #[serde(default)]
    pub witness: Vec<WitnessEntry>,
    #[serde(default)]
    pub rebuilder: Vec<RebuilderEntry>,
    #[serde(default)]
    pub revoker: Vec<RevokerEntry>,
    #[serde(default)]
    pub peers: PeersSection,
    pub install: InstallSection,
    #[serde(default)]
    pub sandbox: SandboxSection,
}

impl Config {
    pub fn parse(text: &str) -> anyhow::Result<Config> {
        let c: Config = toml::from_str(text).map_err(|e| anyhow::anyhow!("loom.toml: {e}"))?;
        loom_warp::notes::parse_vkey(&c.log.key).map_err(|e| anyhow::anyhow!("loom.toml: log.key: {e}"))?;
        for w in &c.witness {
            PublicKey::from_b64(&w.key).map_err(|e| anyhow::anyhow!("loom.toml: witness {}: {e}", w.name))?;
        }
        let mut ids = std::collections::BTreeSet::new();
        for r in &c.rebuilder {
            PublicKey::from_b64(&r.key).map_err(|e| anyhow::anyhow!("loom.toml: rebuilder {}: {e}", r.id))?;
            if !ids.insert(r.id.clone()) {
                anyhow::bail!("loom.toml: duplicate rebuilder id {}", r.id);
            }
        }
        for r in &c.revoker {
            PublicKey::from_b64(&r.key).map_err(|e| anyhow::anyhow!("loom.toml: revoker {}: {e}", r.name))?;
        }
        match c.install.backend.as_str() {
            "pacman" => {}
            "root" if c.install.root.is_some() => {}
            "root" => anyhow::bail!("loom.toml: install.backend = \"root\" requires install.root"),
            b => anyhow::bail!("loom.toml: unknown install.backend {b:?}"),
        }
        match c.sandbox.backend.as_deref() {
            None | Some("kernel") | Some("unconfined-demo") => {}
            Some(b) => anyhow::bail!("loom.toml: unknown sandbox.backend {b:?}"),
        }
        Ok(c)
    }

    pub fn log_key(&self) -> PublicKey {
        loom_warp::notes::parse_vkey(&self.log.key).unwrap().1
    }
}

#[derive(Clone, Debug)]
pub struct Paths {
    pub etc: PathBuf,
    pub state: PathBuf,
    pub cache: PathBuf,
}

impl Paths {
    pub fn from_env() -> Paths {
        if let Some(h) = std::env::var_os("LOOM_HOME") {
            let h = PathBuf::from(h);
            return Paths { etc: h.join("etc"), state: h.join("state"), cache: h.join("cache") };
        }
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| "/root".into());
        let xdg = |var: &str, dflt: &str| {
            std::env::var_os(var).map(PathBuf::from).unwrap_or_else(|| home.join(dflt))
        };
        Paths {
            etc: std::env::var_os("LOOM_CONFIG_DIR").map(PathBuf::from).unwrap_or_else(|| "/etc/loom".into()),
            state: xdg("XDG_STATE_HOME", ".local/state").join("loom"),
            cache: xdg("XDG_CACHE_HOME", ".cache").join("loom"),
        }
    }

    pub fn under(root: &Path) -> Paths {
        Paths { etc: root.join("etc"), state: root.join("state"), cache: root.join("cache") }
    }

    pub fn load_config(&self) -> anyhow::Result<Config> {
        let p = self.etc.join("loom.toml");
        let text = std::fs::read_to_string(&p)
            .map_err(|e| anyhow::anyhow!("cannot read {}: {e} (run `loom init` or see docs/CONFIG.md)", p.display()))?;
        Config::parse(&text)
    }

    /// Load `policy.toml`, or the built-in secure default if absent (FR-9.3).
    /// A present-but-malformed file is an error (FR-9.4).
    pub fn load_policy(&self) -> anyhow::Result<(Policy, Option<PathBuf>)> {
        let p = self.etc.join("policy.toml");
        match std::fs::read_to_string(&p) {
            Ok(t) => Ok((Policy::parse(&t)?, Some(p))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((Policy::default_policy(), None)),
            Err(e) => Err(anyhow::anyhow!("cannot read {}: {e}", p.display())),
        }
    }
}
