//! The Loom client library. The `loom` CLI is a thin layer over this.

pub mod audit;
pub mod config;
pub mod install;
pub mod pipeline;
pub mod state;

pub use config::{Config, Paths};
pub use pipeline::{Context, Loom, Mode, PackageRun};
