//! Wire encoding for proofs: one base64 hash per line (as in c2sp.org/tlog-witness).

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use tlog_tiles::tlog::Hash;

pub fn encode(proof: &[Hash]) -> String {
    proof.iter().map(|h| B64.encode(h.0) + "\n").collect()
}

pub fn decode(s: &str) -> anyhow::Result<Vec<Hash>> {
    s.lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let raw = B64.decode(l.trim())?;
            let arr: [u8; 32] = raw
                .try_into()
                .map_err(|_| anyhow::anyhow!("proof hash must be 32 bytes"))?;
            Ok(Hash(arr))
        })
        .collect()
}

pub fn hash_b64(h: &Hash) -> String {
    B64.encode(h.0)
}

pub fn hash_from_b64(s: &str) -> anyhow::Result<Hash> {
    let raw = B64.decode(s.trim())?;
    Ok(Hash(raw.try_into().map_err(|_| anyhow::anyhow!("bad hash length"))?))
}
