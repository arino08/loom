//! The ecosystem boundary (NFR-MNT-1).
//!
//! Everything that knows about a particular package ecosystem — AUR RPC,
//! PKGBUILD/.SRCINFO semantics, how a build output becomes an installable
//! artifact — lives behind [`Backend`]. Weave (policy), Warp (log), Thread
//! (rebuilder) and Heddle (sandbox) only ever see the types in this module,
//! so an npm or PyPI backend would slot in without touching them.

use crate::digest::Digest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Package metadata as published by the repository (FR-1.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageMeta {
    pub name: String,
    pub base: String,
    pub version: String,
    pub description: String,
    /// `None` = orphaned.
    pub maintainer: Option<String>,
    pub co_maintainers: Vec<String>,
    pub first_submitted: i64,
    /// Publication time of the current version (Unix seconds).
    pub last_modified: i64,
    /// Runtime + build dependencies, version constraints stripped.
    pub depends: Vec<String>,
    pub make_depends: Vec<String>,
    /// Where the build recipe lives (git URL for the AUR).
    pub repo_url: String,
}

/// A local, verified copy of the build recipe at a specific commit (FR-1.2).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Checkout {
    pub dir: PathBuf,
    /// Bare mirror used for lineage queries.
    pub mirror: PathBuf,
    pub commit: String,
    pub commit_time: i64,
    pub tags: BTreeMap<String, String>,
    /// Upstream signing key fingerprints declared by the recipe
    /// (e.g. PKGBUILD `validpgpkeys`).
    pub signing_keys: Vec<String>,
    /// Version declared in the recipe at this commit.
    pub version: String,
}

/// One declared build input. `pinned` is the content hash the recipe
/// commits to; unpinned remote inputs are refused (FR-3.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceInput {
    pub filename: String,
    pub location: String,
    pub remote: bool,
    pub pinned: Option<Digest>,
}

/// Everything Heddle needs to run a build, produced by the backend.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BuildPlan {
    /// Host directory that becomes the sandbox's writable build root.
    pub workdir: PathBuf,
    /// Command to run inside the sandbox, relative to the build root.
    pub argv: Vec<String>,
    /// Extra environment for the build (merged over Heddle's clean env).
    pub env: BTreeMap<String, String>,
    /// Digest over every build input after hash verification.
    pub source_digest: Digest,
    pub inputs: Vec<SourceInput>,
    /// Inputs that could not be fetched under a pinned hash.
    pub unpinned: Vec<String>,
    /// Subdirectory of `workdir` holding the install tree after the build.
    pub output_subdir: String,
    /// Reproducible-builds `SOURCE_DATE_EPOCH`.
    pub source_date_epoch: i64,
    /// Whether the package ships an install-time script (FR-10.1).
    pub install_script: Option<String>,
}

/// A file inside a built artifact, as seen by the placement policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactFile {
    /// Absolute install path, e.g. `/usr/bin/hello`.
    pub path: String,
    pub mode: u32,
    pub kind: FileKind,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    File,
    Dir,
    Symlink,
}

/// What an artifact would do to the system if installed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactManifest {
    pub name: String,
    pub version: String,
    pub files: Vec<ArtifactFile>,
    /// Install-time script shipped in the artifact (e.g. `.INSTALL`).
    pub install_script: Option<String>,
}

pub trait Backend: Send + Sync {
    fn ecosystem(&self) -> &'static str;

    /// Resolve package metadata by name (FR-1.1).
    fn resolve(&self, names: &[String]) -> anyhow::Result<Vec<PackageMeta>>;

    /// List all package names known to the repository (rebuilder discovery).
    fn list_packages(&self) -> anyhow::Result<Vec<String>>;

    /// Fetch/update the recipe and check out its current head (FR-1.2).
    fn checkout(&self, meta: &PackageMeta, cache: &Path) -> anyhow::Result<Checkout>;

    /// Is `baseline` an ancestor of the checkout's head? `false` means history
    /// was rewritten (FR-8.4).
    fn is_ancestor(&self, checkout: &Checkout, baseline: &str) -> anyhow::Result<bool>;

    /// Fetch and verify all declared inputs into `workdir` and describe the
    /// build. Must not execute any recipe code (FR-3.9).
    fn prepare_build(
        &self,
        checkout: &Checkout,
        meta: &PackageMeta,
        workdir: &Path,
    ) -> anyhow::Result<BuildPlan>;

    /// Turn the build output tree into a deterministic artifact.
    fn package(&self, plan: &BuildPlan, meta: &PackageMeta) -> anyhow::Result<Vec<u8>>;

    /// List what an artifact contains without executing anything.
    fn inspect(&self, artifact: &[u8]) -> anyhow::Result<ArtifactManifest>;

    /// Is `name` provided by the system's official repositories (FR-1.4)?
    fn is_official(&self, name: &str) -> bool;
}
