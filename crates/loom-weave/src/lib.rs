//! Weave — the verification and policy engine (SRS §5.6–5.9, §5.11).
//!
//! Weave is ecosystem-agnostic and side-effect free: the client gathers
//! evidence (log view, attestations, continuity, advisories, build and
//! artifact facts) and Weave turns it into an explained [`eval::Decision`].

pub mod advisory;
pub mod continuity;
pub mod eval;
pub mod independence;
pub mod placement;
pub mod policy;

pub use eval::{evaluate, render, Decision, Evidence, Outcome, Status};
pub use policy::Policy;
