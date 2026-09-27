//! pacman-compatible version comparison (`alpm_pkg_vercmp`), used for
//! advisory matching (FR-7.3). A faithful port of libalpm's `rpmvercmp` and
//! `parseEVR`.

use std::cmp::Ordering;

/// Split `[epoch:]version[-release]`.
fn parse_evr(s: &str) -> (&str, &str, Option<&str>) {
    let digits_end = s.bytes().take_while(|b| b.is_ascii_digit()).count();
    let (epoch, rest) = if s.as_bytes().get(digits_end) == Some(&b':') {
        let e = &s[..digits_end];
        (if e.is_empty() { "0" } else { e }, &s[digits_end + 1..])
    } else {
        ("0", s)
    };
    match rest.rfind('-') {
        Some(i) => (epoch, &rest[..i], Some(&rest[i + 1..])),
        None => (epoch, rest, None),
    }
}

fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let a = a.as_bytes();
    let b = b.as_bytes();
    let (mut one, mut two) = (0usize, 0usize);
    let at = |s: &[u8], i: usize| -> u8 { s.get(i).copied().unwrap_or(0) };

    while at(a, one) != 0 && at(b, two) != 0 {
        let (sep1, sep2) = (one, two);
        while at(a, one) != 0 && !at(a, one).is_ascii_alphanumeric() {
            one += 1;
        }
        while at(b, two) != 0 && !at(b, two).is_ascii_alphanumeric() {
            two += 1;
        }
        if !(at(a, one) != 0 && at(b, two) != 0) {
            break;
        }
        if (one - sep1) != (two - sep2) {
            return if (one - sep1) < (two - sep2) {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }
        let (mut p1, mut p2) = (one, two);
        let isnum;
        if at(a, p1).is_ascii_digit() {
            while at(a, p1).is_ascii_digit() {
                p1 += 1;
            }
            while at(b, p2).is_ascii_digit() {
                p2 += 1;
            }
            isnum = true;
        } else {
            while at(a, p1).is_ascii_alphabetic() {
                p1 += 1;
            }
            while at(b, p2).is_ascii_alphabetic() {
                p2 += 1;
            }
            isnum = false;
        }
        if one == p1 {
            return Ordering::Less;
        }
        if two == p2 {
            return if isnum {
                Ordering::Greater
            } else {
                Ordering::Less
            };
        }
        let (mut s1, mut s2) = (&a[one..p1], &b[two..p2]);
        if isnum {
            while s1.first() == Some(&b'0') {
                s1 = &s1[1..];
            }
            while s2.first() == Some(&b'0') {
                s2 = &s2[1..];
            }
            match s1.len().cmp(&s2.len()) {
                Ordering::Equal => {}
                o => return o,
            }
        }
        match s1.cmp(s2) {
            Ordering::Equal => {}
            o => return o,
        }
        one = p1;
        two = p2;
    }

    let (c1, c2) = (at(a, one), at(b, two));
    if c1 == 0 && c2 == 0 {
        return Ordering::Equal;
    }
    if (c1 == 0 && !c2.is_ascii_alphabetic()) || c1.is_ascii_alphabetic() {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// Compare two full package versions the way pacman does.
pub fn vercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (e1, v1, r1) = parse_evr(a);
    let (e2, v2, r2) = parse_evr(b);
    match rpmvercmp(e1, e2) {
        Ordering::Equal => {}
        o => return o,
    }
    match rpmvercmp(v1, v2) {
        Ordering::Equal => {}
        o => return o,
    }
    match (r1, r2) {
        (Some(r1), Some(r2)) => rpmvercmp(r1, r2),
        _ => Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::*;

    // Cases taken from pacman's test/util/vercmptest.sh.
    #[test]
    fn pacman_test_vectors() {
        let cases = [
            ("1.5.0", "1.5.0", Equal),
            ("1.5.1", "1.5.0", Greater),
            ("1.5.1", "1.5", Greater),
            ("1.5.0-1", "1.5.0-1", Equal),
            ("1.5.0-1", "1.5.0-2", Less),
            ("1.5.0-1", "1.5.1-1", Less),
            ("1.5.0-2", "1.5.1-1", Less),
            ("1.5-1", "1.5", Equal),
            ("1.1-1", "1.1", Equal),
            ("1.0-1", "1.1", Less),
            ("1.1-1", "1.0", Greater),
            ("1.5b-1", "1.5-1", Less),
            ("1.5b", "1.5", Less),
            ("1.5b-1", "1.5", Less),
            ("1.5b", "1.5.1", Less),
            ("1.0a", "1.0alpha", Less),
            ("1.0alpha", "1.0b", Less),
            ("1.0b", "1.0beta", Less),
            ("1.0beta", "1.0rc", Less),
            ("1.0rc", "1.0", Less),
            ("1.5.a", "1.5", Greater),
            ("1.5.b", "1.5.a", Greater),
            ("1.5.1", "1.5.b", Greater),
            ("1.5.b-1", "1.5.b", Equal),
            ("1.5-1", "1.5.b", Less),
            ("2.0", "2_0", Equal),
            ("2.0_a", "2_0.a", Equal),
            ("2.0a", "2.0.a", Less),
            ("2___a", "2_a", Greater),
            ("0:1.0", "0:1.0", Equal),
            ("0:1.0", "0:1.1", Less),
            ("1:1.0", "0:1.0", Greater),
            ("1:1.0", "0:1.1", Greater),
            ("1:1.0", "2:1.1", Less),
            ("0:1.0", "1.0", Equal),
            ("0:1.0", "1.1", Less),
            ("0:1.1", "1.0", Greater),
            ("1:1.0", "1.0", Greater),
            ("1:1.0", "1.1", Greater),
            ("1:1.1", "1.1", Greater),
            ("1.0.0", "1.0", Greater),
            ("1.0.0", "1.0a", Greater),
            ("1.0a", "1.0.0", Less),
            ("1.1.0", "1.1", Greater),
        ];
        for (a, b, want) in cases {
            assert_eq!(vercmp(a, b), want, "vercmp({a}, {b})");
            assert_eq!(vercmp(b, a), want.reverse(), "vercmp({b}, {a})");
        }
    }
}
