//! Landlock layer. Applied in both kernel tiers; it is the *only* filesystem
//! enforcement in the `reduced` tier, and defence in depth in `full`.

use crate::policy::AccessPolicy;
use landlock::{
    path_beneath_rules, Access, AccessFs, AccessNet, RestrictionStatus, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};

pub struct Applied {
    pub description: String,
    pub reduced: Vec<String>,
}

/// Restrict the calling thread (and its future children). Fails closed if
/// Landlock is not enforced at all (NFR-SEC-1).
pub fn apply(policy: &AccessPolicy, allow_network: bool) -> anyhow::Result<Applied> {
    let abi = ABI::V6;
    let mut rs = Ruleset::default().handle_access(AccessFs::from_all(abi))?;
    if !allow_network {
        rs = rs.handle_access(AccessNet::from_all(abi))?;
    }
    rs = rs.scope(Scope::from_all(abi))?;
    let status: RestrictionStatus = rs
        .create()?
        .add_rules(path_beneath_rules(&policy.read, AccessFs::from_read(abi)))?
        .add_rules(path_beneath_rules(&policy.write, AccessFs::from_all(abi)))?
        .restrict_self()?;
    let mut reduced = vec![];
    let description = match status.ruleset {
        RulesetStatus::FullyEnforced => "Landlock: fully enforced (filesystem, TCP, IPC scoping)".to_string(),
        RulesetStatus::PartiallyEnforced => {
            reduced.push(
                "Landlock partially enforced: kernel older than ABI v6 (e.g. no TCP restriction below 6.7, no IPC scoping below 6.12); \
                 network denial relies on the network namespace / seccomp instead"
                    .into(),
            );
            "Landlock: partially enforced".to_string()
        }
        RulesetStatus::NotEnforced => {
            anyhow::bail!("Landlock is not available on this kernel (needs Linux >= 5.13 with landlock in the LSM list); refusing to build unconfined")
        }
    };
    Ok(Applied {
        description,
        reduced,
    })
}
