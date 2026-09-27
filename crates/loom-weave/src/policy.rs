//! Declarative policy file (FR-9.x).
//!
//! The file is TOML. Unknown keys, bad enum values and unparseable durations
//! are errors: Loom refuses to run on a malformed policy rather than falling
//! back to permissive defaults (FR-9.4). With no file at all, the built-in
//! secure default ([`DEFAULT_POLICY`], SRS Appendix A plus the audit
//! extensions) applies (FR-9.3).

use loom_core::duration;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

pub const DEFAULT_POLICY: &str = r#"# Loom default policy (SRS LOOM-SRS-001 Appendix A + architecture-audit extensions)
[policy]
min_age                      = "72h"
required_attestations        = 2
witness_threshold            = 2
install_scripts              = "sandbox"
on_continuity_change         = "block"
on_insufficient_attestations = "warn"
# --- extensions (see docs/ARCHITECTURE.md, "Audit") ---
continuity_window            = "30d"
sandbox_min_tier             = "reduced"
prefer_attested_artifact     = true
placement                    = "block"

[escalation]
required_attestations = 3
min_age               = "168h"

[advisory]
fast_path = true
feed      = "https://security.archlinux.org/all.json"

[peer]
serve_cache             = true
origin_fallback_timeout = "5s"
"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InstallScripts {
    Sandbox,
    Deny,
    Allowlist,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnContinuity {
    Block,
    Escalate,
    Warn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Block,
    Warn,
    Allow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlacementAction {
    Block,
    Warn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MinTier {
    Reduced,
    Full,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySection {
    pub min_age: String,
    pub required_attestations: u32,
    pub witness_threshold: u32,
    pub install_scripts: InstallScripts,
    #[serde(default)]
    pub install_script_allowlist: Vec<String>,
    pub on_continuity_change: OnContinuity,
    pub on_insufficient_attestations: Action,
    #[serde(default = "d_window")]
    pub continuity_window: String,
    #[serde(default = "d_tier")]
    pub sandbox_min_tier: MinTier,
    #[serde(default = "d_true")]
    pub prefer_attested_artifact: bool,
    #[serde(default = "d_placement")]
    pub placement: PlacementAction,
}

fn d_window() -> String {
    "30d".into()
}
fn d_tier() -> MinTier {
    MinTier::Reduced
}
fn d_true() -> bool {
    true
}
fn d_placement() -> PlacementAction {
    PlacementAction::Block
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Escalation {
    pub required_attestations: u32,
    pub min_age: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisorySection {
    pub fast_path: bool,
    pub feed: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerSection {
    pub serve_cache: bool,
    pub origin_fallback_timeout: String,
}

/// Per-package overrides (FR-9.2).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageOverride {
    pub min_age: Option<String>,
    pub required_attestations: Option<u32>,
    pub install_scripts: Option<InstallScripts>,
    pub on_continuity_change: Option<OnContinuity>,
    pub on_insufficient_attestations: Option<Action>,
    /// FR-3.8 exception: allow build-time network for this package.
    pub allow_network: Option<bool>,
    /// Install paths exempted from the placement policy.
    #[serde(default)]
    pub allow_placement: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub policy: PolicySection,
    pub escalation: Escalation,
    pub advisory: AdvisorySection,
    pub peer: PeerSection,
    #[serde(default)]
    pub package: BTreeMap<String, PackageOverride>,
}

/// The policy after per-package overrides and continuity escalation.
#[derive(Clone, Debug, Serialize)]
pub struct Effective {
    pub required_attestations: u32,
    #[serde(with = "secs")]
    pub min_age: Duration,
    pub install_scripts: InstallScripts,
    pub on_continuity_change: OnContinuity,
    pub on_insufficient_attestations: Action,
    #[serde(with = "secs")]
    pub continuity_window: Duration,
    pub allow_network: bool,
    pub allow_placement: Vec<String>,
    pub escalated: bool,
}

mod secs {
    use serde::Serializer;
    pub fn serialize<S: Serializer>(d: &std::time::Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&loom_core::duration::human(*d))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning(pub String);

impl Policy {
    pub fn default_policy() -> Policy {
        Policy::parse(DEFAULT_POLICY).expect("built-in policy is valid")
    }

    /// Parse and validate. Any error is fatal (FR-9.4).
    pub fn parse(text: &str) -> anyhow::Result<Policy> {
        let p: Policy = toml::from_str(text).map_err(|e| anyhow::anyhow!("policy: {e}"))?;
        p.validate()?;
        Ok(p)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let chk = |name: &str, v: &str| -> anyhow::Result<()> {
            duration::parse(v).map_err(|e| anyhow::anyhow!("policy: {name}: {e}"))?;
            Ok(())
        };
        chk("policy.min_age", &self.policy.min_age)?;
        chk("policy.continuity_window", &self.policy.continuity_window)?;
        chk("escalation.min_age", &self.escalation.min_age)?;
        chk("peer.origin_fallback_timeout", &self.peer.origin_fallback_timeout)?;
        if self.policy.witness_threshold == 0 {
            anyhow::bail!("policy: witness_threshold must be at least 1 (0 would accept an unwitnessed log)");
        }
        if self.escalation.required_attestations < self.policy.required_attestations {
            anyhow::bail!("policy: escalation.required_attestations must be >= policy.required_attestations");
        }
        if duration::parse(&self.escalation.min_age)? < duration::parse(&self.policy.min_age)? {
            anyhow::bail!("policy: escalation.min_age must be >= policy.min_age");
        }
        if !self.advisory.feed.starts_with("https://") && !self.advisory.feed.starts_with("http://127.") && !self.advisory.feed.starts_with("http://localhost") {
            anyhow::bail!("policy: advisory.feed must be an https:// URL");
        }
        for (name, o) in &self.package {
            if let Some(m) = &o.min_age {
                chk(&format!("package.{name}.min_age"), m)?;
            }
            for p in &o.allow_placement {
                if !p.starts_with('/') {
                    anyhow::bail!("policy: package.{name}.allow_placement entries must be absolute paths");
                }
            }
        }
        Ok(())
    }

    /// Non-fatal advice, including witness-quorum analysis (audit item A8).
    pub fn warnings(&self, configured_witnesses: usize) -> Vec<Warning> {
        let mut w = vec![];
        let n = configured_witnesses as i64;
        let t = self.policy.witness_threshold as i64;
        if t > n {
            w.push(Warning(format!(
                "witness_threshold {t} exceeds the {n} configured witnesses: every checkpoint will be rejected"
            )));
        } else if n > 0 {
            // Two quorums of size t intersect in at least 2t - n witnesses.
            // A split view is *prevented* (not just detectable) iff that
            // intersection contains an honest witness: f < 2t - n.
            let tolerated = 2 * t - n - 1;
            if tolerated < 0 {
                w.push(Warning(format!(
                    "witness_threshold {t} of {n}: two disjoint quorums exist, so split views are prevented only \
                     by cross-checking witnesses (enabled when witness URLs are configured). \
                     Use witness_threshold >= {} to prevent them outright.",
                    n / 2 + 1
                )));
            } else {
                w.push(Warning(format!(
                    "witness_threshold {t} of {n}: split views prevented while at most {tolerated} witness(es) collude with the log"
                )));
            }
        }
        if self.policy.required_attestations == 0 {
            w.push(Warning("required_attestations = 0: reproducible-build verification is disabled".into()));
        }
        if self.policy.on_insufficient_attestations == Action::Allow {
            w.push(Warning("on_insufficient_attestations = allow: unattested packages install silently".into()));
        }
        if duration::parse(&self.policy.min_age).map(|d| d.is_zero()).unwrap_or(false) {
            w.push(Warning("min_age = 0: temporal quarantine disabled".into()));
        }
        if !self.advisory.fast_path {
            w.push(Warning(
                "advisory.fast_path = false: security fixes will be held in quarantine too (SRS: net harm)".into(),
            ));
        }
        w
    }

    pub fn effective(&self, package: &str) -> Effective {
        let o = self.package.get(package).cloned().unwrap_or_default();
        Effective {
            required_attestations: o.required_attestations.unwrap_or(self.policy.required_attestations),
            min_age: duration::parse(o.min_age.as_deref().unwrap_or(&self.policy.min_age)).unwrap(),
            install_scripts: o.install_scripts.unwrap_or(self.policy.install_scripts),
            on_continuity_change: o.on_continuity_change.unwrap_or(self.policy.on_continuity_change),
            on_insufficient_attestations: o
                .on_insufficient_attestations
                .unwrap_or(self.policy.on_insufficient_attestations),
            continuity_window: duration::parse(&self.policy.continuity_window).unwrap(),
            allow_network: o.allow_network.unwrap_or(false),
            allow_placement: o.allow_placement,
            escalated: false,
        }
    }

    pub fn escalate(&self, e: &mut Effective) {
        e.required_attestations = e.required_attestations.max(self.escalation.required_attestations);
        e.min_age = e.min_age.max(duration::parse(&self.escalation.min_age).unwrap());
        e.escalated = true;
    }

    pub fn fallback_timeout(&self) -> Duration {
        duration::parse(&self.peer.origin_fallback_timeout).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_valid_and_matches_appendix_a() {
        let p = Policy::default_policy();
        assert_eq!(p.policy.required_attestations, 2);
        assert_eq!(p.policy.witness_threshold, 2);
        assert_eq!(p.policy.install_scripts, InstallScripts::Sandbox);
        assert_eq!(p.policy.on_continuity_change, OnContinuity::Block);
        assert_eq!(p.policy.on_insufficient_attestations, Action::Warn);
        assert_eq!(p.effective("x").min_age, Duration::from_secs(72 * 3600));
        assert!(p.advisory.fast_path);
    }

    /// FR-9.4 malformed-policy corpus: every entry must be rejected.
    #[test]
    fn malformed_corpus_rejected() {
        let base = DEFAULT_POLICY;
        let corpus: Vec<(&str, String)> = vec![
            ("unknown key", base.replace("min_age                      = \"72h\"", "min_age = \"72h\"\nminimum_age = \"1h\"")),
            ("bad duration", base.replace("\"72h\"", "\"72 hours\"")),
            ("unitless duration", base.replace("\"72h\"", "\"72\"")),
            ("bad enum", base.replace("install_scripts              = \"sandbox\"", "install_scripts = \"yolo\"")),
            ("negative k", base.replace("required_attestations        = 2", "required_attestations = -1")),
            ("zero witness threshold", base.replace("witness_threshold            = 2", "witness_threshold = 0")),
            ("escalation weaker", base.replace("required_attestations = 3", "required_attestations = 1")),
            ("missing section", base.replace("[peer]\nserve_cache             = true\norigin_fallback_timeout = \"5s\"\n", "")),
            ("http feed", base.replace("https://security", "http://security")),
            ("unknown package key", format!("{base}\n[package.foo]\nallow_everything = true\n")),
            ("relative placement", format!("{base}\n[package.foo]\nallow_placement = [\"etc/x\"]\n")),
            ("not toml", "[[[".to_string()),
            ("wrong type", base.replace("fast_path = true", "fast_path = \"yes\"")),
        ];
        for (name, text) in corpus {
            assert!(Policy::parse(&text).is_err(), "malformed policy accepted: {name}");
        }
    }

    #[test]
    fn per_package_and_escalation() {
        let text = format!("{DEFAULT_POLICY}\n[package.fast]\nmin_age = \"1h\"\nrequired_attestations = 1\n");
        let p = Policy::parse(&text).unwrap();
        let mut e = p.effective("fast");
        assert_eq!(e.required_attestations, 1);
        assert_eq!(e.min_age, Duration::from_secs(3600));
        p.escalate(&mut e);
        assert_eq!(e.required_attestations, 3);
        assert_eq!(e.min_age, Duration::from_secs(168 * 3600));
    }

    #[test]
    fn quorum_analysis() {
        let p = Policy::default_policy();
        let w = p.warnings(3);
        assert!(w.iter().any(|w| w.0.contains("at most 0 witness")), "{w:?}");
        let w = p.warnings(4);
        assert!(w.iter().any(|w| w.0.contains("two disjoint quorums")), "{w:?}");
        let w = p.warnings(1);
        assert!(w.iter().any(|w| w.0.contains("exceeds")));
    }
}
