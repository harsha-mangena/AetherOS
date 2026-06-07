//! # AetherOS Core
//!
//! Security-critical primitives for the AetherOS trusted execution kernel. This
//! crate is intentionally dependency-light and side-effect-free: it provides the
//! cryptographic and integrity foundations that the rest of the system — Python
//! orchestration, the governance layer, the UI — builds upon and trusts.
//!
//! ## Modules
//! - [`identity`]: cryptographic agent identities (Ed25519).
//! - [`lease`]: signed, scoped, time-bounded capability leases with budget slices.
//! - [`evidence`]: append-only, hash-chained, replayable evidence ledger.
//! - [`canonical`]: deterministic canonical JSON serialization + SHA-256 hashing,
//!   the reproducible byte representation shared with the Python bindings.
//! - [`policy`]: the integrity-critical policy evaluation core (deny-overrides).
//! - [`autonomy`]: earned-autonomy tier tracking from a governed track record.
//! - [`glob`]: minimal dependency-free glob matching for policy patterns.
//! - [`error`]: the crate-wide [`error::CoreError`] type.
//!
//! ## Design tenets
//! 1. **Deterministic crypto inputs.** Everything signed or hashed goes through
//!    [`canonical`], so Rust and Python agree byte-for-byte.
//! 2. **Tamper evidence over tamper resistance.** The ledger does not prevent edits;
//!    it makes any edit detectable via the hash chain.
//! 3. **Least privilege by construction.** Authority flows only through signed
//!    [`lease::CapabilityLease`]s, never ambient credentials.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod autonomy;
pub mod canonical;
pub mod error;
pub mod evidence;
pub mod glob;
pub mod identity;
pub mod lease;
pub mod policy;

pub use autonomy::AutonomyRecord;
pub use error::{CoreError, Result};
pub use evidence::{EvidenceEntry, EvidenceLedger, GENESIS_HASH};
pub use identity::{AgentDescriptor, AgentIdentity};
pub use lease::{Budget, BudgetLimit, CapabilityLease, LeaseBody};
pub use policy::{Effect, PolicyDecision, PolicyRequest, PolicyRule, PolicySet};

/// The semantic version of the core crate, surfaced for diagnostics and the UI.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
