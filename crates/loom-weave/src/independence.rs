//! Counting *independent* evidence (FR-6.1, FR-6.2, NFR-SEC-4).
//!
//! Two attestations are correlated if they come from the same organisation
//! or were produced with the same toolchain (a shared compromised compiler or
//! a shared operator explains both). The number of independent attestations
//! is the size of the largest set of pairwise-uncorrelated ones — a maximum
//! independent set in the correlation graph. The SRS's "don't count
//! identical toolchains independently" is the special case of this graph with
//! only toolchain edges. For the small n of a rebuilder federation an exact
//! search is cheap; above 20 a greedy bound (never an over-count) is used.

#[derive(Clone, Debug)]
pub struct Witnessing<'a> {
    pub rebuilder: &'a str,
    pub org: &'a str,
    pub toolchain: &'a str,
}

fn correlated(a: &Witnessing, b: &Witnessing) -> bool {
    a.rebuilder == b.rebuilder || a.org == b.org || a.toolchain == b.toolchain
}

/// Returns (count, chosen indices).
pub fn independent_count(xs: &[Witnessing]) -> (usize, Vec<usize>) {
    let n = xs.len();
    if n == 0 {
        return (0, vec![]);
    }
    if n <= 20 {
        let mut adj = vec![0u32; n];
        for i in 0..n {
            for j in 0..n {
                if i != j && correlated(&xs[i], &xs[j]) {
                    adj[i] |= 1 << j;
                }
            }
        }
        let mut best = 0u32;
        for mask in 1u32..(1u32 << n) {
            if mask.count_ones() <= best.count_ones() {
                continue;
            }
            let ok = (0..n).all(|i| mask & (1 << i) == 0 || adj[i] & mask == 0);
            if ok {
                best = mask;
            }
        }
        let chosen = (0..n).filter(|i| best & (1 << i) != 0).collect::<Vec<_>>();
        return (chosen.len(), chosen);
    }
    // Greedy: lowest-degree first.
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by_key(|&i| (0..n).filter(|&j| j != i && correlated(&xs[i], &xs[j])).count());
    let mut chosen: Vec<usize> = vec![];
    for i in order {
        if chosen.iter().all(|&c| !correlated(&xs[i], &xs[c])) {
            chosen.push(i);
        }
    }
    (chosen.len(), chosen)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w<'a>(r: &'a str, o: &'a str, t: &'a str) -> Witnessing<'a> {
        Witnessing { rebuilder: r, org: o, toolchain: t }
    }

    #[test]
    fn counts() {
        assert_eq!(independent_count(&[]).0, 0);
        // Three distinct orgs and toolchains.
        assert_eq!(independent_count(&[w("a", "1", "x"), w("b", "2", "y"), w("c", "3", "z")]).0, 3);
        // Shared toolchain (FR-6.2): a and c collapse.
        assert_eq!(independent_count(&[w("a", "1", "x"), w("b", "2", "y"), w("c", "3", "x")]).0, 2);
        // Sybil: one org, many rebuilders.
        assert_eq!(independent_count(&[w("s1", "evil", "x"), w("s2", "evil", "y"), w("s3", "evil", "z")]).0, 1);
        // Union-find would say 1 here; exact MIS finds a and c.
        assert_eq!(independent_count(&[w("a", "1", "x"), w("b", "2", "x"), w("c", "2", "y")]).0, 2);
        // Same rebuilder twice counts once.
        assert_eq!(independent_count(&[w("a", "1", "x"), w("a", "1", "x")]).0, 1);
    }

    /// Property: the count never exceeds the number of distinct orgs or
    /// distinct toolchains, and adding an attestation never lowers it.
    #[test]
    fn monotone_and_bounded() {
        let orgs = ["o1", "o2", "o3", "o4"];
        let tcs = ["t1", "t2", "t3"];
        let names: Vec<String> = (0..12).map(|i| format!("r{i}")).collect();
        let mut seed = 12345u64;
        let mut rnd = |m: usize| {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((seed >> 33) as usize) % m
        };
        for _ in 0..300 {
            let n = rnd(9);
            let xs: Vec<Witnessing> = (0..n)
                .map(|i| w(&names[i], orgs[rnd(4)], tcs[rnd(3)]))
                .collect();
            let (c, chosen) = independent_count(&xs);
            let distinct_orgs: std::collections::BTreeSet<_> = xs.iter().map(|x| x.org).collect();
            let distinct_tcs: std::collections::BTreeSet<_> = xs.iter().map(|x| x.toolchain).collect();
            assert!(c <= distinct_orgs.len() && c <= distinct_tcs.len());
            for a in &chosen {
                for b in &chosen {
                    if a != b {
                        assert!(!correlated(&xs[*a], &xs[*b]));
                    }
                }
            }
            let mut more = xs.clone();
            more.push(w("extra", orgs[rnd(4)], tcs[rnd(3)]));
            assert!(independent_count(&more).0 >= c);
        }
    }
}
