//! Scoped capability leases.
//!
//! A capability lease is a signed, time-bounded grant of authority from an issuer
//! (typically the AetherOS control plane identity) to a subject agent. It is the
//! unit of least-privilege authorization in AetherOS: instead of inheriting broad
//! human or service credentials, an agent acts only within the scopes, budget, and
//! validity window of the leases it holds.
//!
//! Atom of thoughts:
//!   CapabilityLease = lease_id + subject_agent_id + issuer_agent_id
//!                   + scopes (set) + budget slice + issued_at + expires_at
//!                   + revoked flag + Ed25519 signature(issuer) over canonical body
//!
//! The signature binds every field of the lease *body* (everything except the
//! signature itself), so any tampering — widening scopes, raising the budget,
//! extending expiry — invalidates the lease.

use serde::{Deserialize, Serialize};

use crate::canonical::to_canonical_bytes;
use crate::error::{CoreError, Result};
use crate::identity::{verify_signature, AgentIdentity};

/// A monetary budget slice attached to a lease, in integer minor currency units
/// (e.g. cents) to avoid floating-point drift in financial enforcement.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Budget {
    /// ISO 4217 currency code, e.g. "USD".
    pub currency: String,
    /// Hard spending limit in minor units (cents).
    pub limit_minor: u64,
    /// Amount already spent against this lease, in minor units.
    pub spent_minor: u64,
}

impl Budget {
    /// Create a fresh budget with zero spent.
    pub fn new(currency: impl Into<String>, limit_minor: u64) -> Self {
        Self {
            currency: currency.into(),
            limit_minor,
            spent_minor: 0,
        }
    }

    /// Remaining spendable amount in minor units.
    pub fn remaining_minor(&self) -> u64 {
        self.limit_minor.saturating_sub(self.spent_minor)
    }

    /// Whether a charge of `amount_minor` would fit within the remaining budget.
    pub fn can_afford(&self, amount_minor: u64) -> bool {
        amount_minor <= self.remaining_minor()
    }
}

/// The signed body of a capability lease (everything covered by the signature).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaseBody {
    /// Unique lease identifier (UUIDv4).
    pub lease_id: String,
    /// Agent that holds and acts under this lease.
    pub subject_agent_id: String,
    /// Agent (control plane) that issued and signed this lease.
    pub issuer_agent_id: String,
    /// Granted scopes, e.g. "tool:slack.post", "s3:read:incident-logs".
    pub scopes: Vec<String>,
    /// Budget slice for this lease.
    pub budget: Budget,
    /// RFC3339 issuance timestamp.
    pub issued_at: String,
    /// RFC3339 expiry timestamp.
    pub expires_at: String,
}

/// A complete capability lease: a signed body plus mutable runtime state.
///
/// The `signature` and `issuer_public_key` cover only [`LeaseBody`]. The `revoked`
/// flag is runtime state managed by the control plane and is intentionally *not*
/// part of the signed body — revocation is enforced by the holder of the ledger,
/// not by the signature.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityLease {
    /// The signed lease body.
    pub body: LeaseBody,
    /// Issuer's Ed25519 public key (hex) used to verify `signature`.
    pub issuer_public_key: String,
    /// Ed25519 signature (hex) over the canonical bytes of `body`.
    pub signature: String,
    /// Runtime revocation flag (not signed).
    pub revoked: bool,
}

impl CapabilityLease {
    /// Issue and sign a new lease using the issuer identity's signing key.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        issuer: &AgentIdentity,
        subject_agent_id: impl Into<String>,
        scopes: Vec<String>,
        budget: Budget,
        issued_at: impl Into<String>,
        expires_at: impl Into<String>,
    ) -> Result<Self> {
        let mut scopes = scopes;
        scopes.sort();
        scopes.dedup();
        let body = LeaseBody {
            lease_id: uuid::Uuid::new_v4().to_string(),
            subject_agent_id: subject_agent_id.into(),
            issuer_agent_id: issuer.agent_id().to_string(),
            scopes,
            budget,
            issued_at: issued_at.into(),
            expires_at: expires_at.into(),
        };
        let bytes = to_canonical_bytes(&body)?;
        let signature = issuer.sign(&bytes);
        Ok(Self {
            body,
            issuer_public_key: issuer.public_key_hex(),
            signature,
            revoked: false,
        })
    }

    /// Verify the issuer's signature over the lease body.
    pub fn verify_signature(&self) -> Result<()> {
        let bytes = to_canonical_bytes(&self.body)?;
        verify_signature(&self.issuer_public_key, &bytes, &self.signature)
    }

    /// Mark the lease as revoked (runtime state).
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Whether the lease is expired relative to `now` (RFC3339 strings compared
    /// lexicographically; callers pass normalized UTC `Z` timestamps so lexical
    /// order matches chronological order).
    pub fn is_expired_at(&self, now_rfc3339: &str) -> bool {
        now_rfc3339 >= self.body.expires_at.as_str()
    }

    /// Whether a given scope is granted by this lease.
    pub fn grants_scope(&self, scope: &str) -> bool {
        self.body.scopes.iter().any(|s| s == scope)
    }

    /// Full authorization check for an action requiring `scope` and `cost_minor`,
    /// evaluated at `now_rfc3339`. Returns `Ok(())` only if the lease is valid,
    /// not revoked, not expired, grants the scope, and can afford the cost.
    pub fn authorize(&self, scope: &str, cost_minor: u64, now_rfc3339: &str) -> Result<()> {
        self.verify_signature()?;
        if self.revoked {
            return Err(CoreError::LeaseRevoked {
                lease_id: self.body.lease_id.clone(),
            });
        }
        if self.is_expired_at(now_rfc3339) {
            return Err(CoreError::LeaseExpired {
                expired_at: self.body.expires_at.clone(),
            });
        }
        if !self.grants_scope(scope) {
            return Err(CoreError::ScopeNotGranted {
                scope: scope.to_string(),
            });
        }
        if !self.body.budget.can_afford(cost_minor) {
            return Err(CoreError::InvalidInput(format!(
                "budget exceeded: requested {} minor, {} remaining",
                cost_minor,
                self.body.budget.remaining_minor()
            )));
        }
        Ok(())
    }

    /// Record a successful spend of `amount_minor` against the lease budget.
    ///
    /// This mutates runtime budget state; it must be preceded by a successful
    /// [`CapabilityLease::authorize`] for the same amount.
    pub fn record_spend(&mut self, amount_minor: u64) -> Result<()> {
        if !self.body.budget.can_afford(amount_minor) {
            return Err(CoreError::InvalidInput(
                "spend would exceed remaining budget".into(),
            ));
        }
        self.body.budget.spent_minor = self.body.budget.spent_minor.saturating_add(amount_minor);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentIdentity;

    fn issuer() -> AgentIdentity {
        AgentIdentity::generate("control-plane", "2026-06-07T00:00:00Z")
    }

    fn sample_lease(iss: &AgentIdentity) -> CapabilityLease {
        CapabilityLease::issue(
            iss,
            "subject-agent",
            vec!["tool:slack.post".into(), "s3:read:logs".into()],
            Budget::new("USD", 10_000),
            "2026-06-07T00:00:00Z",
            "2026-06-08T00:00:00Z",
        )
        .unwrap()
    }

    #[test]
    fn issued_lease_verifies() {
        let iss = issuer();
        let lease = sample_lease(&iss);
        assert!(lease.verify_signature().is_ok());
    }

    #[test]
    fn tampering_with_scopes_breaks_signature() {
        let iss = issuer();
        let mut lease = sample_lease(&iss);
        lease.body.scopes.push("admin:everything".into());
        assert!(lease.verify_signature().is_err());
    }

    #[test]
    fn tampering_with_budget_breaks_signature() {
        let iss = issuer();
        let mut lease = sample_lease(&iss);
        lease.body.budget.limit_minor = 1_000_000;
        assert!(lease.verify_signature().is_err());
    }

    #[test]
    fn authorize_happy_path() {
        let iss = issuer();
        let lease = sample_lease(&iss);
        assert!(lease
            .authorize("tool:slack.post", 500, "2026-06-07T12:00:00Z")
            .is_ok());
    }

    #[test]
    fn authorize_rejects_missing_scope() {
        let iss = issuer();
        let lease = sample_lease(&iss);
        let err = lease
            .authorize("admin:delete", 0, "2026-06-07T12:00:00Z")
            .unwrap_err();
        matches!(err, CoreError::ScopeNotGranted { .. });
    }

    #[test]
    fn authorize_rejects_expired() {
        let iss = issuer();
        let lease = sample_lease(&iss);
        assert!(lease
            .authorize("tool:slack.post", 0, "2026-06-09T00:00:00Z")
            .is_err());
    }

    #[test]
    fn authorize_rejects_revoked() {
        let iss = issuer();
        let mut lease = sample_lease(&iss);
        lease.revoke();
        assert!(lease
            .authorize("tool:slack.post", 0, "2026-06-07T12:00:00Z")
            .is_err());
    }

    #[test]
    fn authorize_rejects_over_budget() {
        let iss = issuer();
        let lease = sample_lease(&iss);
        assert!(lease
            .authorize("tool:slack.post", 20_000, "2026-06-07T12:00:00Z")
            .is_err());
    }

    #[test]
    fn record_spend_accumulates() {
        let iss = issuer();
        let mut lease = sample_lease(&iss);
        lease.record_spend(3_000).unwrap();
        lease.record_spend(2_000).unwrap();
        assert_eq!(lease.body.budget.spent_minor, 5_000);
        assert_eq!(lease.body.budget.remaining_minor(), 5_000);
        assert!(lease.record_spend(6_000).is_err());
    }
}
