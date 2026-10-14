//! SmartWatch for Rust: the coupling-density engine of spec/SEMANTICS.md and the agent side
//! (a reporter and a command poller) that talk to the Python monitor over plain HTTP.
//!
//! - `json`: JSON reader and canonical writer
//! - `sha256`: SHA-256 (own implementation, no dependencies)
//! - `hashing`: FNV-1a 32/64 and mix64
//! - `hll`: HyperLogLog, p = 14
//! - `policy`: policy validation
//! - `engine`: add / flush / snapshot, density, grading, resets
//! - `calibrate`: percentile thresholds
//! - `audit`: audit chain verification
//! - `client`: HTTP client, `Reporter` and `CommandPoller` (plain HTTP)
pub mod audit;
pub mod calibrate;
pub mod client;
pub mod engine;
pub mod hashing;
pub mod hll;
pub mod json;
pub mod policy;
pub mod sha256;

pub use client::{Client, CommandPoller, Reporter};
pub use engine::{density_micro, Engine, EventError, Output, Snapshot};
pub use hll::HyperLogLog;
pub use policy::{Policy, PolicyError};
