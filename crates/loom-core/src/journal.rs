//! Demo/evaluation event journal.
//!
//! When `LOOM_EVENTS` names a file, Loom's binaries append one JSON object
//! per notable event (a decision, a rebuild, a log sync, a scenario step).
//! The testbed dashboard renders the journal alongside live service state.
//! Journaling is best-effort observability: it never affects a decision,
//! and a write failure is ignored.

use std::io::Write;

/// Append `{"ts": <now>, "kind": kind, ...fields}` to `$LOOM_EVENTS`.
/// `fields` must be a JSON object; anything else is recorded under `data`.
pub fn record(kind: &str, fields: serde_json::Value) {
    let Some(path) = std::env::var_os("LOOM_EVENTS") else {
        return;
    };
    let mut obj = match fields {
        serde_json::Value::Object(m) => m,
        other => {
            let mut m = serde_json::Map::new();
            m.insert("data".into(), other);
            m
        }
    };
    obj.insert("ts".into(), crate::time::now().into());
    obj.insert("kind".into(), kind.into());
    let Ok(mut line) = serde_json::to_vec(&obj) else { return };
    line.push(b'\n');
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        // One write per line so concurrent writers interleave whole lines.
        let _ = f.write_all(&line);
    }
}

pub fn enabled() -> bool {
    std::env::var_os("LOOM_EVENTS").is_some()
}
