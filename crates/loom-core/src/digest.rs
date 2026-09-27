//! Content digests. Loom addresses every artifact by SHA-256 (FR-2.1), written
//! as `sha256:<hex>` so the algorithm is always explicit.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn of(bytes: &[u8]) -> Self {
        Digest(Sha256::digest(bytes).into())
    }

    pub fn of_reader<R: Read>(mut r: R) -> std::io::Result<Self> {
        let mut h = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = r.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        Ok(Digest(h.finalize().into()))
    }

    pub fn of_file(p: &Path) -> std::io::Result<Self> {
        Self::of_reader(std::fs::File::open(p)?)
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Short form for human output (first 12 hex chars).
    pub fn short(&self) -> String {
        self.hex()[..12].to_string()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Digest {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> anyhow::Result<Self> {
        let hexpart = s.strip_prefix("sha256:").unwrap_or(s);
        let raw = hex::decode(hexpart)?;
        let arr: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("digest must be 32 bytes"))?;
        Ok(Digest(arr))
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let d = Digest::of(b"loom");
        let s = d.to_string();
        assert!(s.starts_with("sha256:"));
        assert_eq!(s.parse::<Digest>().unwrap(), d);
        assert_eq!(d.hex().parse::<Digest>().unwrap(), d);
    }
}
