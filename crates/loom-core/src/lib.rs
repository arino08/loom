//! Shared primitives for every Loom subsystem.
//!
//! Nothing in this crate knows about the AUR, pacman or the kernel: it holds
//! the encodings and data model that Weave, Warp, Thread and Shuttle agree on
//! (NFR-MNT-1).

pub mod attest;
pub mod canon;
pub mod digest;
pub mod dsse;
pub mod duration;
pub mod ecosystem;
pub mod http;
pub mod journal;
pub mod keys;
pub mod time;
pub mod vercmp;

pub use digest::Digest;
