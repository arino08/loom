//! Canonical JSON serialisation (SRS §7.3: "log records are canonically
//! serialised prior to signing to ensure signature determinism").
//!
//! The encoding follows the subset of RFC 8785 (JCS) that Loom records use:
//! object keys sorted lexicographically by code point, no insignificant
//! whitespace, and no floating-point values. Values are routed through
//! `serde_json::Value`, whose map type is a `BTreeMap` (sorted) because the
//! workspace never enables serde_json's `preserve_order` feature.

use serde::Serialize;
use serde_json::Value;

/// Serialise `v` to canonical JSON bytes.
pub fn to_vec<T: Serialize>(v: &T) -> anyhow::Result<Vec<u8>> {
    let value = serde_json::to_value(v)?;
    reject_floats(&value)?;
    Ok(serde_json::to_vec(&value)?)
}

/// Serialise to a canonical JSON string.
pub fn to_string<T: Serialize>(v: &T) -> anyhow::Result<String> {
    Ok(String::from_utf8(to_vec(v)?)?)
}

/// Re-canonicalise arbitrary JSON bytes. Used by the log to make sure that
/// what it stores is byte-identical to what any client would recompute.
pub fn recanonicalise(bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
    let value: Value = serde_json::from_slice(bytes)?;
    reject_floats(&value)?;
    Ok(serde_json::to_vec(&value)?)
}

fn reject_floats(v: &Value) -> anyhow::Result<()> {
    match v {
        Value::Number(n) if !(n.is_i64() || n.is_u64()) => {
            anyhow::bail!("canonical JSON forbids non-integer numbers ({n})")
        }
        Value::Array(a) => a.iter().try_for_each(reject_floats),
        Value::Object(o) => o.values().try_for_each(reject_floats),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_are_sorted_and_compact() {
        let v = json!({"b": 1, "a": {"z": [1, 2], "y": "s"}});
        assert_eq!(to_string(&v).unwrap(), r#"{"a":{"y":"s","z":[1,2]},"b":1}"#);
    }

    #[test]
    fn recanonicalise_is_idempotent() {
        let a = br#"{ "b" : 1, "a":2 }"#;
        let c1 = recanonicalise(a).unwrap();
        let c2 = recanonicalise(&c1).unwrap();
        assert_eq!(c1, c2);
        assert_eq!(c1, br#"{"a":2,"b":1}"#);
    }

    #[test]
    fn floats_rejected() {
        assert!(to_vec(&json!({"x": 1.5})).is_err());
    }
}
