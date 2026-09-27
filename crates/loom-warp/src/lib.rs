//! Warp — the witnessed transparency log (SRS §5.5).
//!
//! * [`tree`]: an append-only RFC 6962 Merkle tree over canonical
//!   [`LogRecord`](loom_core::attest::LogRecord) leaves, built on the
//!   `tlog_tiles` port of Go's `sumdb/tlog` (no bespoke hashing, CON-5).
//! * [`notes`]: signed tree heads as C2SP checkpoints signed with
//!   c2sp.org/signed-note, plus witness cosignatures in the
//!   c2sp.org/tlog-cosignature v1 format.
//! * [`server`]: the log service (add, checkpoint, entries, proofs).
//! * [`witness`]: an independent witness implementing c2sp.org/tlog-witness:
//!   it cosigns a checkpoint only after verifying a consistency proof from the
//!   last checkpoint it cosigned (prevents split views, ADV-9).
//! * [`client`]: client-side verification (FR-5.5–5.7, NFR-SEC-5): witness
//!   threshold, persisted-head consistency, witness cross-checking and a
//!   locally verified mirror of all records.

pub mod client;
pub mod notes;
pub mod proof;
pub mod server;
pub mod tree;
pub mod witness;

pub use tlog_tiles::tlog::Hash;
