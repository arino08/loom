//! Append-only Merkle tree storage.

use anyhow::Context;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use tlog_tiles::tlog::{self, Hash, HashReader};

/// Stored hashes + leaves, kept in memory and optionally appended to disk.
#[derive(Default, Clone)]
pub struct Tree {
    leaves: Vec<Vec<u8>>,
    hashes: Vec<Hash>,
    path: Option<PathBuf>,
}

struct Reader<'a>(&'a [Hash]);

impl HashReader for Reader<'_> {
    fn read_hashes(&self, indexes: &[u64]) -> Result<Vec<Hash>, tlog::Error> {
        indexes
            .iter()
            .map(|&i| self.0.get(i as usize).copied().ok_or(tlog::Error::IndexesNotInTree))
            .collect()
    }
}

impl Tree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open (or create) a tree persisted as one leaf per line (JSONL).
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let mut t = Tree {
            path: Some(path.to_path_buf()),
            ..Default::default()
        };
        if path.exists() {
            let f = std::fs::File::open(path)?;
            for line in std::io::BufReader::new(f).lines() {
                let line = line?;
                if line.is_empty() {
                    continue;
                }
                t.push_mem(line.into_bytes())?;
            }
        } else if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        Ok(t)
    }

    fn push_mem(&mut self, leaf: Vec<u8>) -> anyhow::Result<u64> {
        let n = self.leaves.len() as u64;
        let new = tlog::stored_hashes(n, &leaf, &Reader(&self.hashes))
            .map_err(|e| anyhow::anyhow!("stored_hashes: {e:?}"))?;
        debug_assert_eq!(self.hashes.len() as u64, tlog::stored_hash_index(0, n));
        self.hashes.extend(new);
        self.leaves.push(leaf);
        Ok(n)
    }

    /// Append a leaf. Leaves must be single-line (canonical JSON).
    pub fn append(&mut self, leaf: Vec<u8>) -> anyhow::Result<u64> {
        if leaf.contains(&b'\n') {
            anyhow::bail!("leaf contains newline");
        }
        if let Some(p) = &self.path {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .with_context(|| format!("open {}", p.display()))?;
            f.write_all(&leaf)?;
            f.write_all(b"\n")?;
            f.sync_data()?;
        }
        self.push_mem(leaf)
    }

    pub fn size(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn leaf(&self, i: u64) -> Option<&[u8]> {
        self.leaves.get(i as usize).map(|v| v.as_slice())
    }

    pub fn leaves(&self, start: u64, end: u64) -> &[Vec<u8>] {
        let end = end.min(self.size());
        let start = start.min(end);
        &self.leaves[start as usize..end as usize]
    }

    pub fn root(&self) -> Hash {
        self.root_at(self.size()).expect("root of own size")
    }

    pub fn root_at(&self, n: u64) -> anyhow::Result<Hash> {
        if n > self.size() {
            anyhow::bail!("tree size {n} beyond {}", self.size());
        }
        tlog::tree_hash(n, &Reader(&self.hashes)).map_err(|e| anyhow::anyhow!("{e:?}"))
    }

    /// Inclusion proof for leaf `index` in the tree of size `size`.
    pub fn prove_inclusion(&self, index: u64, size: u64) -> anyhow::Result<Vec<Hash>> {
        if index >= size || size > self.size() {
            anyhow::bail!("bad inclusion request index={index} size={size}");
        }
        tlog::prove_record(size, index, &Reader(&self.hashes)).map_err(|e| anyhow::anyhow!("{e:?}"))
    }

    /// Consistency proof that the tree of size `old` is a prefix of `new`.
    pub fn prove_consistency(&self, old: u64, new: u64) -> anyhow::Result<Vec<Hash>> {
        if old > new || new > self.size() {
            anyhow::bail!("bad consistency request old={old} new={new}");
        }
        if old == 0 || old == new {
            return Ok(vec![]);
        }
        tlog::prove_tree(new, old, &Reader(&self.hashes)).map_err(|e| anyhow::anyhow!("{e:?}"))
    }
}

pub fn leaf_hash(leaf: &[u8]) -> Hash {
    tlog::record_hash(leaf)
}

/// Verify an inclusion proof (FR-5.5).
pub fn verify_inclusion(
    proof: &[Hash],
    size: u64,
    root: Hash,
    index: u64,
    leaf: &[u8],
) -> anyhow::Result<()> {
    let proof = proof.to_vec();
    let h = tlog::record_hash(leaf);
    // Fail closed even if the proof checker panics on adversarial input.
    std::panic::catch_unwind(move || tlog::check_record(&proof, size, root, index, h))
        .map_err(|_| anyhow::anyhow!("inclusion proof rejected (malformed)"))?
        .map_err(|e| anyhow::anyhow!("inclusion proof invalid: {e:?}"))
}

/// Verify a consistency proof (FR-5.7).
pub fn verify_consistency(
    proof: &[Hash],
    old_size: u64,
    old_root: Hash,
    new_size: u64,
    new_root: Hash,
) -> anyhow::Result<()> {
    if old_size > new_size {
        anyhow::bail!("tree shrank from {old_size} to {new_size} (rollback)");
    }
    if old_size == new_size {
        if old_root != new_root {
            anyhow::bail!("same size {old_size} but different roots");
        }
        return Ok(());
    }
    if old_size == 0 {
        return Ok(());
    }
    let proof = proof.to_vec();
    std::panic::catch_unwind(move || tlog::check_tree(&proof, new_size, new_root, old_size, old_root))
        .map_err(|_| anyhow::anyhow!("consistency proof rejected (malformed)"))?
        .map_err(|e| anyhow::anyhow!("consistency proof invalid: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(n: u64) -> Tree {
        let mut t = Tree::new();
        for i in 0..n {
            t.append(format!("leaf-{i}").into_bytes()).unwrap();
        }
        t
    }

    #[test]
    fn rfc6962_empty_and_single() {
        let t = Tree::new();
        assert_eq!(t.root(), tlog::EMPTY_HASH);
        let t = build(1);
        assert_eq!(t.root(), leaf_hash(b"leaf-0"));
    }

    #[test]
    fn inclusion_all_sizes() {
        let t = build(37);
        for size in 1..=37 {
            let root = t.root_at(size).unwrap();
            for i in 0..size {
                let p = t.prove_inclusion(i, size).unwrap();
                verify_inclusion(&p, size, root, i, t.leaf(i).unwrap()).unwrap();
                // Wrong leaf must fail.
                assert!(verify_inclusion(&p, size, root, i, b"evil").is_err());
            }
        }
    }

    #[test]
    fn consistency_all_pairs() {
        let t = build(20);
        for new in 1..=20 {
            for old in 1..=new {
                let p = t.prove_consistency(old, new).unwrap();
                verify_consistency(&p, old, t.root_at(old).unwrap(), new, t.root_at(new).unwrap())
                    .unwrap();
            }
        }
    }

    #[test]
    fn fork_is_inconsistent() {
        let a = build(10);
        let mut b = build(8);
        b.append(b"forked-8".to_vec()).unwrap();
        b.append(b"forked-9".to_vec()).unwrap();
        b.append(b"forked-10".to_vec()).unwrap();
        // b claims to extend a's size-10 tree; no proof from b can link them.
        let p = b.prove_consistency(10, 11).unwrap();
        assert!(verify_consistency(&p, 10, a.root(), 11, b.root()).is_err());
    }

    #[test]
    fn persistence() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("log.jsonl");
        let mut t = Tree::open(&p).unwrap();
        for i in 0..5 {
            t.append(format!("{{\"i\":{i}}}").into_bytes()).unwrap();
        }
        let root = t.root();
        let t2 = Tree::open(&p).unwrap();
        assert_eq!(t2.size(), 5);
        assert_eq!(t2.root(), root);
    }
}
