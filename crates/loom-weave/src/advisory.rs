//! Security advisory feed (FR-7.3): versions that remediate a known
//! vulnerability bypass quarantine.
//!
//! The format is the Arch Linux security tracker's `all.json`: a list of
//! AVG groups, each with affected packages, an `affected` and `fixed`
//! version, severity and CVE list.

use loom_core::vercmp::vercmp;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Group {
    pub name: String,
    pub packages: Vec<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub affected: String,
    #[serde(default)]
    pub fixed: Option<String>,
    #[serde(default)]
    pub issues: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Match {
    pub group: String,
    pub severity: String,
    pub fixed: String,
    pub issues: Vec<String>,
}

pub fn parse(bytes: &[u8]) -> anyhow::Result<Vec<Group>> {
    Ok(serde_json::from_slice(bytes)?)
}

/// Is `version` of `package` a remediation listed by the feed? A version
/// qualifies if it is at or above a group's `fixed` version *and* the
/// currently installed version (if any) is below it — i.e. installing it
/// actually closes the vulnerability.
pub fn remediates(groups: &[Group], package: &str, version: &str, installed: Option<&str>) -> Option<Match> {
    groups.iter().find_map(|g| {
        if !g.packages.iter().any(|p| p == package) {
            return None;
        }
        let fixed = g.fixed.as_deref()?;
        if vercmp(version, fixed) == Ordering::Less {
            return None;
        }
        if let Some(i) = installed {
            if vercmp(i, fixed) != Ordering::Less {
                return None;
            }
        }
        Some(Match {
            group: g.name.clone(),
            severity: g.severity.clone(),
            fixed: fixed.to_string(),
            issues: g.issues.clone(),
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching() {
        let feed = br#"[{"name":"AVG-9","packages":["tlsprobe"],"status":"Fixed","severity":"High","affected":"2.0-1","fixed":"2.0.1-1","issues":["CVE-2026-0001"]}]"#;
        let g = parse(feed).unwrap();
        assert!(remediates(&g, "tlsprobe", "2.0.1-1", None).is_some());
        assert!(remediates(&g, "tlsprobe", "2.1-1", Some("2.0-1")).is_some());
        assert!(remediates(&g, "tlsprobe", "2.0-1", None).is_none());
        assert!(remediates(&g, "tlsprobe", "2.1-1", Some("2.0.1-1")).is_none());
        assert!(remediates(&g, "other", "9", None).is_none());
    }
}
