//! Error types for the AetherOS core crate.
//!
//! All fallible operations in the core return [`CoreError`]. The variants are
//! deliberately coarse-grained and stable so that PyO3 bindings can map them to
//! Python exceptions without leaking internal representation details.

use thiserror::Error;

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, CoreError>;

/// Errors produced by AetherOS core primitives.
#[derive(Debug, Error)]
pub enum CoreError {
    /// A cryptographic signing or verification operation failed.
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    /// A signature did not verify against the expected key/message.
    #[error("signature verification failed")]
    InvalidSignature,

    /// Serialization to or from the canonical form failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// A capability lease was used past its expiry.
    #[error("capability lease expired at {expired_at}")]
    LeaseExpired {
        /// RFC3339 timestamp at which the lease expired.
        expired_at: String,
    },

    /// A capability lease has been explicitly revoked.
    #[error("capability lease {lease_id} has been revoked")]
    LeaseRevoked {
        /// Identifier of the revoked lease.
        lease_id: String,
    },

    /// A requested scope is not granted by the lease.
    #[error("scope '{scope}' is not granted by this lease")]
    ScopeNotGranted {
        /// The scope that was requested but not granted.
        scope: String,
    },

    /// The evidence ledger hash chain is broken at a given sequence number.
    #[error("evidence ledger integrity broken at sequence {seq}: {reason}")]
    LedgerIntegrity {
        /// Sequence number at which verification failed.
        seq: u64,
        /// Human-readable reason for the failure.
        reason: String,
    },

    /// An input value was malformed (bad hex, bad length, etc.).
    #[error("invalid input: {0}")]
    InvalidInput(String),
}
