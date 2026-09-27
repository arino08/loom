//! Publishing-authority continuity (SRS §5.8).
//!
//! Two sources of history are combined (audit item A2):
//!
//! * the **local baseline** recorded when this machine installed the package
//!   (FR-8.1) — catches any change since *we* last looked;
//! * the **transparency log**: every rebuilder attestation records the
//!   maintainer and commit it observed, so the log is a witnessed history of
//!   publishing authority. This protects first-time installers, for whom a
//!   purely local baseline would be trust-on-first-use — exactly the position
//!   of a victim of an orphan-adoption attack who has never installed the
//!   package before.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    pub package: String,
    pub version: String,
    pub maintainer: Option<String>,
    pub signing_keys: Vec<String>,
    pub commit: String,
    pub tags: BTreeMap<String, String>,
    pub observed_at: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    MaintainerChanged,
    OrphanAdopted,
    SigningKeyChanged,
    HistoryRewritten,
    TagMoved,
}

impl Kind {
    pub fn describe(&self) -> &'static str {
        match self {
            Kind::MaintainerChanged => "maintainer changed",
            Kind::OrphanAdopted => "orphaned package adopted by a new maintainer",
            Kind::SigningKeyChanged => "upstream signing keys changed",
            Kind::HistoryRewritten => "recipe history rewritten (force-push)",
            Kind::TagMoved => "tag reassigned to a different commit",
        }
    }
    pub fn requirement(&self) -> &'static str {
        match self {
            Kind::MaintainerChanged => "FR-8.2",
            Kind::OrphanAdopted => "FR-8.5",
            Kind::SigningKeyChanged => "FR-8.3",
            Kind::HistoryRewritten | Kind::TagMoved => "FR-8.4",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    LocalBaseline,
    TransparencyLog,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    pub kind: Kind,
    pub source: Source,
    pub prior: String,
    pub current: String,
    /// When the prior value was last observed.
    pub prior_observed: Option<i64>,
    /// Best available date of the change (FR-8.7).
    pub changed_at: Option<i64>,
}

pub struct Current<'a> {
    pub maintainer: Option<&'a str>,
    pub signing_keys: &'a [String],
    pub commit: &'a str,
    pub tags: &'a BTreeMap<String, String>,
    pub now: i64,
}

/// One rebuilder observation of the package, from the log.
#[derive(Clone, Debug)]
pub struct LogObservation {
    pub version: String,
    pub commit: String,
    pub maintainer: Option<String>,
    pub timestamp: i64,
}

fn show(m: Option<&str>) -> String {
    m.map(|s| s.to_string()).unwrap_or_else(|| "(orphaned)".into())
}

pub fn check(
    baseline: Option<&Baseline>,
    cur: &Current,
    history: &[LogObservation],
    window: Duration,
    is_ancestor: &dyn Fn(&str) -> bool,
) -> Vec<Violation> {
    let mut out = vec![];
    let mut hist: Vec<&LogObservation> = history.iter().collect();
    hist.sort_by_key(|o| o.timestamp);
    let first_seen_with = |m: Option<&str>, after: i64| {
        hist.iter()
            .filter(|o| o.timestamp >= after && o.maintainer.as_deref() == m)
            .map(|o| o.timestamp)
            .min()
    };

    if let Some(b) = baseline {
        if b.maintainer.as_deref() != cur.maintainer {
            out.push(Violation {
                kind: if b.maintainer.is_none() { Kind::OrphanAdopted } else { Kind::MaintainerChanged },
                source: Source::LocalBaseline,
                prior: show(b.maintainer.as_deref()),
                current: show(cur.maintainer),
                prior_observed: Some(b.observed_at),
                changed_at: first_seen_with(cur.maintainer, b.observed_at),
            });
        }
        let mut a = b.signing_keys.clone();
        let mut c = cur.signing_keys.to_vec();
        a.sort();
        c.sort();
        if a != c {
            out.push(Violation {
                kind: Kind::SigningKeyChanged,
                source: Source::LocalBaseline,
                prior: if a.is_empty() { "(none)".into() } else { a.join(", ") },
                current: if c.is_empty() { "(none)".into() } else { c.join(", ") },
                prior_observed: Some(b.observed_at),
                changed_at: None,
            });
        }
        if b.commit != cur.commit && !is_ancestor(&b.commit) {
            out.push(Violation {
                kind: Kind::HistoryRewritten,
                source: Source::LocalBaseline,
                prior: format!("commit {} (installed {})", short(&b.commit), b.version),
                current: format!("commit {} does not descend from it", short(cur.commit)),
                prior_observed: Some(b.observed_at),
                changed_at: None,
            });
        }
        for (tag, old) in &b.tags {
            if let Some(new) = cur.tags.get(tag) {
                if new != old {
                    out.push(Violation {
                        kind: Kind::TagMoved,
                        source: Source::LocalBaseline,
                        prior: format!("{tag} -> {}", short(old)),
                        current: format!("{tag} -> {}", short(new)),
                        prior_observed: Some(b.observed_at),
                        changed_at: None,
                    });
                }
            }
        }
    }

    // --- transparency-log history (protects first-time installers) ---
    let cutoff = cur.now - window.as_secs() as i64;
    let have_maintainer = out
        .iter()
        .any(|v| matches!(v.kind, Kind::MaintainerChanged | Kind::OrphanAdopted));
    let have_rewrite = out.iter().any(|v| v.kind == Kind::HistoryRewritten);
    // Walk maintainers chronologically, ending with the current one.
    let mut seq: Vec<(Option<&str>, i64)> = hist.iter().map(|o| (o.maintainer.as_deref(), o.timestamp)).collect();
    seq.push((cur.maintainer, cur.now));
    let mut log_violation = None;
    for w in seq.windows(2) {
        let ((pm, pt), (cm, ct)) = (w[0], w[1]);
        if pm != cm && ct >= cutoff {
            log_violation = Some(Violation {
                kind: if pm.is_none() { Kind::OrphanAdopted } else { Kind::MaintainerChanged },
                source: Source::TransparencyLog,
                prior: show(pm),
                current: show(cm),
                prior_observed: Some(pt),
                changed_at: if ct == cur.now { None } else { Some(ct) },
            });
        }
    }
    if let Some(v) = log_violation {
        if !have_maintainer && v.current == show(cur.maintainer) {
            out.push(v);
        }
    }

    if !have_rewrite {
        let mut seen = std::collections::BTreeSet::new();
        for o in hist.iter().rev().take(20) {
            if o.commit == cur.commit || !seen.insert(o.commit.clone()) {
                continue;
            }
            if !is_ancestor(&o.commit) {
                out.push(Violation {
                    kind: Kind::HistoryRewritten,
                    source: Source::TransparencyLog,
                    prior: format!("commit {} (version {} as attested in the log)", short(&o.commit), o.version),
                    current: format!("commit {} does not descend from it", short(cur.commit)),
                    prior_observed: Some(o.timestamp),
                    changed_at: None,
                });
                break;
            }
        }
    }
    out
}

fn short(c: &str) -> &str {
    &c[..c.len().min(12)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Baseline {
        Baseline {
            package: "p".into(),
            version: "1-1".into(),
            maintainer: Some("alice".into()),
            signing_keys: vec!["K1".into()],
            commit: "c1".into(),
            tags: BTreeMap::from([("v1".into(), "c1".into())]),
            observed_at: 100,
        }
    }

    fn obs(v: &str, c: &str, m: Option<&str>, t: i64) -> LogObservation {
        LogObservation { version: v.into(), commit: c.into(), maintainer: m.map(|s| s.into()), timestamp: t }
    }

    const DAY: i64 = 86400;

    #[test]
    fn unchanged_is_clean() {
        let b = base();
        let keys = vec!["K1".to_string()];
        let cur = Current { maintainer: Some("alice"), signing_keys: &keys, commit: "c2", tags: &b.tags, now: 200 };
        assert!(check(Some(&b), &cur, &[], Duration::from_secs(30 * 86400), &|_| true).is_empty());
    }

    #[test]
    fn local_detects_everything() {
        let b = base();
        let keys = vec!["K2".to_string()];
        let tags = BTreeMap::from([("v1".to_string(), "cX".to_string())]);
        let cur = Current { maintainer: Some("mallory"), signing_keys: &keys, commit: "cX", tags: &tags, now: 200 };
        let v = check(Some(&b), &cur, &[obs("2-1", "cX", Some("mallory"), 150)], Duration::from_secs(1), &|_| false);
        let kinds: Vec<Kind> = v.iter().map(|x| x.kind).collect();
        assert!(kinds.contains(&Kind::MaintainerChanged));
        assert!(kinds.contains(&Kind::SigningKeyChanged));
        assert!(kinds.contains(&Kind::HistoryRewritten));
        assert!(kinds.contains(&Kind::TagMoved));
        let m = v.iter().find(|x| x.kind == Kind::MaintainerChanged).unwrap();
        assert_eq!(m.changed_at, Some(150), "date of change from the log (FR-8.7)");
    }

    #[test]
    fn first_time_installer_protected_by_log() {
        // No local baseline. Log: orphaned for a while, adopted 2 days ago.
        let now = 100 * DAY;
        let hist = [
            obs("1-1", "c1", Some("bob"), 10 * DAY),
            obs("1-2", "c2", None, 60 * DAY),
            obs("2-1", "c3", Some("mallory"), 98 * DAY),
        ];
        let tags = BTreeMap::new();
        let cur = Current { maintainer: Some("mallory"), signing_keys: &[], commit: "c3", tags: &tags, now };
        let v = check(None, &cur, &hist, Duration::from_secs(30 * 86400), &|_| true);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, Kind::OrphanAdopted);
        assert_eq!(v[0].source, Source::TransparencyLog);
        assert_eq!(v[0].changed_at, Some(98 * DAY));
    }

    #[test]
    fn old_changes_outside_window_ignored() {
        let now = 400 * DAY;
        let hist = [obs("1-1", "c1", Some("bob"), 10 * DAY), obs("2-1", "c2", Some("carol"), 20 * DAY)];
        let tags = BTreeMap::new();
        let cur = Current { maintainer: Some("carol"), signing_keys: &[], commit: "c3", tags: &tags, now };
        assert!(check(None, &cur, &hist, Duration::from_secs(30 * 86400), &|_| true).is_empty());
    }

    #[test]
    fn log_detects_force_push_for_new_user() {
        let hist = [obs("1-1", "c1", Some("a"), 1)];
        let tags = BTreeMap::new();
        let cur = Current { maintainer: Some("a"), signing_keys: &[], commit: "evil", tags: &tags, now: 10 };
        let v = check(None, &cur, &hist, Duration::from_secs(1), &|c| c != "c1");
        assert_eq!(v[0].kind, Kind::HistoryRewritten);
        assert_eq!(v[0].source, Source::TransparencyLog);
    }
}
