//! Time helpers. All persisted timestamps are Unix seconds (UTC).
//!
//! `LOOM_NOW` overrides the clock (Unix seconds) so quarantine behaviour can
//! be tested with synthetic timestamp fixtures (SRS §8.1, FR-7.x).

pub fn now() -> i64 {
    if let Ok(v) = std::env::var("LOOM_NOW") {
        if let Ok(n) = v.parse() {
            return n;
        }
    }
    chrono::Utc::now().timestamp()
}

pub fn rfc3339(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| ts.to_string())
}
