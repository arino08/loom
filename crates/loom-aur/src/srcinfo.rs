//! `.SRCINFO` parser.
//!
//! Metadata is read from the static `.SRCINFO` file committed alongside every
//! AUR PKGBUILD, never by sourcing the PKGBUILD: sourcing it is executing
//! untrusted code (FR-3.9).

use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SrcInfo {
    pub pkgbase: String,
    pub pkgnames: Vec<String>,
    pub pkgver: String,
    pub pkgrel: String,
    pub epoch: Option<String>,
    pub pkgdesc: String,
    pub url: String,
    pub arch: Vec<String>,
    pub license: Vec<String>,
    pub depends: Vec<String>,
    pub makedepends: Vec<String>,
    pub checkdepends: Vec<String>,
    pub sources: Vec<String>,
    /// Checksum algorithm -> list (parallel to `sources`).
    pub sums: BTreeMap<String, Vec<String>>,
    pub validpgpkeys: Vec<String>,
    pub install: Option<String>,
}

impl SrcInfo {
    pub fn full_version(&self) -> String {
        match &self.epoch {
            Some(e) if !e.is_empty() && e != "0" => format!("{e}:{}-{}", self.pkgver, self.pkgrel),
            _ => format!("{}-{}", self.pkgver, self.pkgrel),
        }
    }
}

pub const SUM_ALGS: &[&str] = &["sha256sums", "sha512sums", "b2sums"];

pub fn parse(text: &str, carch: &str) -> anyhow::Result<SrcInfo> {
    let mut s = SrcInfo::default();
    let mut in_pkgbase = false;
    let mut seen_pkgname = false;
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line
            .split_once(" = ")
            .or_else(|| line.split_once('=').map(|(a, b)| (a.trim_end(), b.trim_start())))
            .ok_or_else(|| anyhow::anyhow!(".SRCINFO line {}: expected key = value", lineno + 1))?;
        let (k, v) = (k.trim(), v.trim().to_string());
        match k {
            "pkgbase" => {
                s.pkgbase = v;
                in_pkgbase = true;
                continue;
            }
            "pkgname" => {
                s.pkgnames.push(v);
                in_pkgbase = false;
                seen_pkgname = true;
                continue;
            }
            _ => {}
        }
        // Per-package overrides for split packages are ignored except for the
        // first package's depends (prototype supports single-package bases).
        if !in_pkgbase && seen_pkgname && s.pkgnames.len() > 1 {
            continue;
        }
        let arch_suffix = format!("_{carch}");
        let key = k.strip_suffix(&arch_suffix).unwrap_or(k);
        match key {
            "pkgver" => s.pkgver = v,
            "pkgrel" => s.pkgrel = v,
            "epoch" => s.epoch = Some(v),
            "pkgdesc" => s.pkgdesc = v,
            "url" => s.url = v,
            "arch" => s.arch.push(v),
            "license" => s.license.push(v),
            "depends" => s.depends.push(v),
            "makedepends" => s.makedepends.push(v),
            "checkdepends" => s.checkdepends.push(v),
            "source" => s.sources.push(v),
            "validpgpkeys" => s.validpgpkeys.push(v),
            "install" => s.install = Some(v),
            a if SUM_ALGS.contains(&a) => s.sums.entry(a.to_string()).or_default().push(v),
            _ => {} // other arch-specific keys, options, etc.
        }
    }
    if s.pkgbase.is_empty() {
        anyhow::bail!(".SRCINFO has no pkgbase");
    }
    if s.pkgnames.is_empty() {
        s.pkgnames.push(s.pkgbase.clone());
    }
    if s.pkgver.is_empty() || s.pkgrel.is_empty() {
        anyhow::bail!(".SRCINFO missing pkgver/pkgrel");
    }
    for (alg, list) in &s.sums {
        if list.len() != s.sources.len() {
            anyhow::bail!(
                ".SRCINFO: {} has {} entries for {} sources",
                alg,
                list.len(),
                s.sources.len()
            );
        }
    }
    Ok(s)
}

/// Strip version constraints: `foo>=1.2` -> `foo`.
pub fn dep_name(d: &str) -> String {
    d.split(['<', '>', '=', ':']).next().unwrap_or(d).trim().to_string()
}

/// Split a `source` entry into (filename, location).
pub fn source_parts(entry: &str) -> (String, String) {
    let (name, loc) = match entry.split_once("::") {
        Some((n, l)) => (Some(n.to_string()), l.to_string()),
        None => (None, entry.to_string()),
    };
    let fname = name.unwrap_or_else(|| {
        let no_frag = loc.split('#').next().unwrap_or(&loc);
        let no_q = no_frag.split('?').next().unwrap_or(no_frag);
        no_q.trim_end_matches('/').rsplit('/').next().unwrap_or(no_q).to_string()
    });
    (fname, loc)
}

pub fn is_remote(loc: &str) -> bool {
    loc.contains("://")
}

pub fn is_vcs(loc: &str) -> bool {
    let scheme = loc.split("://").next().unwrap_or("");
    scheme.contains('+') || ["git", "svn", "hg", "bzr", "fossil"].contains(&scheme)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "pkgbase = hello\n\tpkgdesc = Say hello\n\tpkgver = 1.2\n\tpkgrel = 3\n\tepoch = 1\n\turl = https://example.org\n\tarch = x86_64\n\tlicense = MIT\n\tmakedepends = gcc\n\tdepends = glibc>=2.38\n\tsource = hello.c\n\tsource = hello-1.2.tar.gz::https://example.org/v1.2.tar.gz\n\tsource_x86_64 = extra.bin\n\tsha256sums = SKIP\n\tsha256sums = 0000000000000000000000000000000000000000000000000000000000000000\n\tsha256sums_x86_64 = 1111111111111111111111111111111111111111111111111111111111111111\n\tvalidpgpkeys = ABCDEF0123456789\n\tinstall = hello.install\n\npkgname = hello\n";

    #[test]
    fn parses() {
        let s = parse(SAMPLE, "x86_64").unwrap();
        assert_eq!(s.pkgbase, "hello");
        assert_eq!(s.full_version(), "1:1.2-3");
        assert_eq!(s.sources.len(), 3);
        assert_eq!(s.sums["sha256sums"].len(), 3);
        assert_eq!(s.depends, vec!["glibc>=2.38"]);
        assert_eq!(dep_name(&s.depends[0]), "glibc");
        assert_eq!(s.validpgpkeys, vec!["ABCDEF0123456789"]);
        assert_eq!(s.install.as_deref(), Some("hello.install"));
    }

    #[test]
    fn mismatched_sums_rejected() {
        let bad = "pkgbase = x\n\tpkgver = 1\n\tpkgrel = 1\n\tsource = a\n\tsource = b\n\tsha256sums = SKIP\npkgname = x\n";
        assert!(parse(bad, "x86_64").is_err());
    }

    #[test]
    fn source_splitting() {
        assert_eq!(source_parts("a.tar.gz::https://x/y"), ("a.tar.gz".into(), "https://x/y".into()));
        assert_eq!(source_parts("https://x/y/z.tgz"), ("z.tgz".into(), "https://x/y/z.tgz".into()));
        assert_eq!(source_parts("git+https://x/repo.git#tag=v1").0, "repo.git");
        assert!(is_vcs("git+https://x/repo.git"));
        assert!(!is_vcs("https://x/a.tgz"));
    }
}
