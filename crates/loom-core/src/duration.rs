//! Human durations as used in the policy file (`"72h"`, `"5s"`, `"7d"`,
//! `"1h30m"`).

use std::time::Duration;

pub fn parse(s: &str) -> anyhow::Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("empty duration");
    }
    let mut total: u64 = 0;
    let mut num = String::new();
    let mut saw_unit = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let unit: String = if c == 'm' && chars.peek() == Some(&'s') {
            chars.next();
            "ms".into()
        } else {
            c.to_string()
        };
        if num.is_empty() {
            anyhow::bail!("duration {s:?}: unit {unit:?} without a number");
        }
        let n: u64 = num.parse()?;
        num.clear();
        let ms = match unit.as_str() {
            "ms" => n,
            "s" => n * 1_000,
            "m" => n * 60_000,
            "h" => n * 3_600_000,
            "d" => n * 86_400_000,
            "w" => n * 7 * 86_400_000,
            _ => anyhow::bail!("duration {s:?}: unknown unit {unit:?} (use ms, s, m, h, d, w)"),
        };
        total = total
            .checked_add(ms)
            .ok_or_else(|| anyhow::anyhow!("duration overflow"))?;
        saw_unit = true;
    }
    if !num.is_empty() {
        anyhow::bail!("duration {s:?}: trailing number without unit (e.g. \"72h\")");
    }
    if !saw_unit {
        anyhow::bail!("duration {s:?} has no unit");
    }
    Ok(Duration::from_millis(total))
}

/// Render a duration compactly for humans: `2d 3h`, `45m`, `12s`.
pub fn human(d: Duration) -> String {
    let secs = d.as_secs();
    let (days, h, m, s) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60, secs % 60);
    let mut parts = vec![];
    if days > 0 {
        parts.push(format!("{days}d"));
    }
    if h > 0 {
        parts.push(format!("{h}h"));
    }
    if m > 0 && days == 0 {
        parts.push(format!("{m}m"));
    }
    if parts.is_empty() {
        parts.push(format!("{s}s"));
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses() {
        assert_eq!(parse("72h").unwrap(), Duration::from_secs(72 * 3600));
        assert_eq!(parse("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse("1h30m").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse("7d").unwrap(), Duration::from_secs(7 * 86400));
        assert_eq!(parse("250ms").unwrap(), Duration::from_millis(250));
        for bad in ["", "72", "h", "3x", "1h2"] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn humanises() {
        assert_eq!(human(Duration::from_secs(3 * 86400 + 7200)), "3d 2h");
        assert_eq!(human(Duration::from_secs(2700)), "45m");
        assert_eq!(human(Duration::from_secs(9)), "9s");
    }
}
