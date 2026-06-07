//! Earned-autonomy tiers.
//!
//! AetherOS does not grant agents broad autonomy up front. An agent earns autonomy by
//! accumulating a track record of successful, governed runs, and loses it on
//! violations. The autonomy tier feeds the policy engine ([`crate::policy`]): higher
//! tiers can match rules that lower tiers cannot (e.g. auto-approving a class of
//! lower-impact actions a junior agent would have to escalate).
//!
//! This is governance *state*, so it lives in the Rust core where it cannot be forged
//! by the orchestration layer. The promotion/demotion policy is deliberately simple
//! and auditable:
//!
//!   - Start at `tier = 0` (most constrained).
//!   - Each successful run increments a success streak. When the streak reaches
//!     `promotion_threshold`, the tier rises by one (capped at `max_tier`) and the
//!     streak resets.
//!   - Any violation demotes the tier by one (floored at 0) and resets the streak.
//!
//! Research net / revalidation: this mirrors graduated-trust and "earned autonomy"
//! patterns in safety-critical automation and progressive-delivery systems — trust is
//! a function of demonstrated reliability, and it decays sharply on failure
//! (asymmetric: slow to earn, fast to lose), which is the conservative choice for
//! systems acting on production infrastructure.

use serde::{Deserialize, Serialize};

/// Default number of consecutive successful runs required to earn the next tier.
pub const DEFAULT_PROMOTION_THRESHOLD: u32 = 5;
/// Default maximum autonomy tier.
pub const DEFAULT_MAX_TIER: u8 = 3;

/// An agent's earned-autonomy record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutonomyRecord {
    /// The agent this record belongs to.
    pub agent_id: String,
    /// Current autonomy tier (0 = most constrained).
    pub tier: u8,
    /// Consecutive successful runs since the last promotion or demotion.
    pub success_streak: u32,
    /// Lifetime count of successful runs.
    pub total_successes: u64,
    /// Lifetime count of violations.
    pub total_violations: u64,
    /// Consecutive successful runs required to earn the next tier.
    pub promotion_threshold: u32,
    /// Maximum tier this agent can reach.
    pub max_tier: u8,
}

impl AutonomyRecord {
    /// Create a fresh record for an agent at tier 0 with default thresholds.
    pub fn new(agent_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            tier: 0,
            success_streak: 0,
            total_successes: 0,
            total_violations: 0,
            promotion_threshold: DEFAULT_PROMOTION_THRESHOLD,
            max_tier: DEFAULT_MAX_TIER,
        }
    }

    /// Create a record with explicit thresholds (config-driven).
    pub fn with_policy(
        agent_id: impl Into<String>,
        promotion_threshold: u32,
        max_tier: u8,
    ) -> Self {
        let mut r = Self::new(agent_id);
        r.promotion_threshold = promotion_threshold.max(1);
        r.max_tier = max_tier;
        r
    }

    /// Record a successful governed run. Returns true if this caused a promotion.
    pub fn record_success(&mut self) -> bool {
        self.total_successes = self.total_successes.saturating_add(1);
        self.success_streak = self.success_streak.saturating_add(1);
        if self.success_streak >= self.promotion_threshold && self.tier < self.max_tier {
            self.tier += 1;
            self.success_streak = 0;
            return true;
        }
        false
    }

    /// Record a violation. Returns true if this caused a demotion.
    pub fn record_violation(&mut self) -> bool {
        self.total_violations = self.total_violations.saturating_add(1);
        self.success_streak = 0;
        if self.tier > 0 {
            self.tier -= 1;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_tier_zero() {
        let r = AutonomyRecord::new("agent-1");
        assert_eq!(r.tier, 0);
        assert_eq!(r.success_streak, 0);
    }

    #[test]
    fn earns_tier_after_threshold() {
        let mut r = AutonomyRecord::with_policy("agent-1", 3, 3);
        assert!(!r.record_success());
        assert!(!r.record_success());
        assert!(r.record_success()); // third success -> promotion
        assert_eq!(r.tier, 1);
        assert_eq!(r.success_streak, 0);
        assert_eq!(r.total_successes, 3);
    }

    #[test]
    fn caps_at_max_tier() {
        let mut r = AutonomyRecord::with_policy("agent-1", 1, 2);
        r.record_success(); // -> tier 1
        r.record_success(); // -> tier 2
        let promoted = r.record_success(); // already at max
        assert!(!promoted);
        assert_eq!(r.tier, 2);
    }

    #[test]
    fn violation_demotes_and_resets_streak() {
        let mut r = AutonomyRecord::with_policy("agent-1", 2, 3);
        r.record_success();
        r.record_success(); // tier 1
        r.record_success(); // streak 1 at tier 1
        let demoted = r.record_violation();
        assert!(demoted);
        assert_eq!(r.tier, 0);
        assert_eq!(r.success_streak, 0);
        assert_eq!(r.total_violations, 1);
    }

    #[test]
    fn violation_at_tier_zero_does_not_underflow() {
        let mut r = AutonomyRecord::new("agent-1");
        let demoted = r.record_violation();
        assert!(!demoted);
        assert_eq!(r.tier, 0);
    }

    #[test]
    fn asymmetric_trust_slow_to_earn_fast_to_lose() {
        let mut r = AutonomyRecord::with_policy("agent-1", 5, 3);
        for _ in 0..15 {
            r.record_success();
        }
        assert_eq!(r.tier, 3); // 15 successes / 5 = 3 promotions
        r.record_violation();
        assert_eq!(r.tier, 2); // one violation drops a full tier
    }
}
