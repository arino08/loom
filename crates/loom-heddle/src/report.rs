use serde::{Deserialize, Serialize};

/// Confinement tier actually achieved for a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tier {
    /// No kernel confinement. Only for demonstrations on hosts where the
    /// operator has forbidden sandbox creation; never selected implicitly.
    UnconfinedDemo,
    /// Landlock + seccomp, no namespaces (unprivileged user namespaces
    /// disabled on this host). Reduced assurance, reported to the user
    /// (NFR-MNT-3).
    Reduced,
    /// User, mount, network, PID, IPC and UTS namespaces + Landlock + seccomp.
    Full,
}

impl Tier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Tier::UnconfinedDemo => "unconfined-demo",
            Tier::Reduced => "reduced",
            Tier::Full => "full",
        }
    }
    pub fn parse(s: &str) -> anyhow::Result<Tier> {
        Ok(match s {
            "full" => Tier::Full,
            "reduced" => Tier::Reduced,
            "unconfined-demo" => Tier::UnconfinedDemo,
            _ => anyhow::bail!("unknown sandbox tier {s:?} (full, reduced, unconfined-demo)"),
        })
    }
}

/// A single refused access (FR-3.7, NFR-OBS-2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Denial {
    pub at_ms: u64,
    pub pid: u32,
    pub syscall: String,
    pub resource: String,
    pub rule: String,
    pub requirement: String,
    pub reason: String,
}

impl Denial {
    /// A denial that reveals hostile intent rather than an incidental probe:
    /// reaching for the user's home/credentials (FR-3.2) or the network
    /// (FR-3.4, unless a network exception is in effect). Heddle contained
    /// the attempt, but a build that made it is not trustworthy, so neither
    /// rebuilders nor clients accept its output (NFR-SEC-1: fail closed).
    /// Undeclared reads (FR-3.1) and restricted syscalls (FR-3.6) are logged
    /// only: benign toolchains trip them routinely.
    pub fn is_hostile(&self, allow_network: bool) -> bool {
        // Mirrored by loom_weave::eval::is_hostile_denial (Weave does not
        // depend on Heddle and sees only the requirement id).
        match self.requirement.as_str() {
            "FR-3.2" => true,
            "FR-3.4" => !allow_network,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunReport {
    pub exit_code: i32,
    pub tier: Tier,
    /// Human description of what enforced each property.
    pub layers: Vec<String>,
    /// Reasons assurance is below `Full` (NFR-MNT-3).
    pub reduced: Vec<String>,
    pub denials: Vec<Denial>,
    pub duration_ms: u64,
    pub timed_out: bool,
    /// Last part of the combined build output.
    pub log_tail: String,
    pub log_path: Option<std::path::PathBuf>,
}

impl RunReport {
    pub fn success(&self) -> bool {
        self.exit_code == 0 && !self.timed_out
    }
}
