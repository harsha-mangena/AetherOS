//! Hybrid policy engine — critical evaluation core (Rust side).
//!
//! AetherOS governance must be *enforced*, not advisory. The integrity-critical part
//! of policy evaluation therefore lives in Rust: given a fully-resolved access request
//! and an ordered set of rules, compute a deterministic allow/deny decision with
//! deny-overrides semantics and report the deciding rule. Rule *authoring* and loading
//! from config live in Python; this core only evaluates.
//!
//! Atom of thoughts:
//!   PolicyRule = id + effect(allow|deny) + matchers(scope glob, tool glob,
//!                min_autonomy_tier, max_cost_minor) + priority
//!   Decision   = allow/deny + deciding_rule_id + reason
//!
//! Evaluation semantics (revalidated against enterprise authorization norms, à la
//! XACML / AWS IAM): default-deny; rules are considered in priority order (higher
//! priority first, ties broken by declaration order); an explicit `Deny` always wins
//! over an `Allow` regardless of priority (deny-overrides), so a high-priority allow
//! cannot escalate past a matching deny. This makes policy safe-by-default and
//! resistant to ordering mistakes in authored config.

use serde::{Deserialize, Serialize};

use crate::glob::glob_match;

/// The effect of a policy rule.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    /// Permit the request when the rule matches.
    Allow,
    /// Forbid the request when the rule matches (wins over any allow).
    Deny,
}

/// A single policy rule. A rule *matches* a request when every present matcher is
/// satisfied; absent matchers are wildcards.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRule {
    /// Stable rule identifier (for evidence and debugging).
    pub id: String,
    /// Allow or deny when this rule matches.
    pub effect: Effect,
    /// Glob matched against the request scope (e.g. "s3:read:*"). None = any.
    #[serde(default)]
    pub scope: Option<String>,
    /// Glob matched against the tool name (e.g. "slack_*"). None = any.
    #[serde(default)]
    pub tool: Option<String>,
    /// Minimum autonomy tier required for this rule to match. None = any.
    #[serde(default)]
    pub min_autonomy_tier: Option<u8>,
    /// Maximum cost (minor units) for this rule to match. None = any.
    #[serde(default)]
    pub max_cost_minor: Option<u64>,
    /// Higher priority is considered first (within the same effect class).
    #[serde(default)]
    pub priority: i32,
}

impl PolicyRule {
    /// Whether this rule matches the given request.
    pub fn matches(&self, req: &PolicyRequest) -> bool {
        if let Some(scope_glob) = &self.scope {
            if !glob_match(scope_glob, &req.scope) {
                return false;
            }
        }
        if let Some(tool_glob) = &self.tool {
            if !glob_match(tool_glob, &req.tool) {
                return false;
            }
        }
        if let Some(min_tier) = self.min_autonomy_tier {
            if req.autonomy_tier < min_tier {
                return false;
            }
        }
        if let Some(max_cost) = self.max_cost_minor {
            if req.cost_minor > max_cost {
                return false;
            }
        }
        true
    }
}

/// A fully-resolved access request to evaluate against policy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRequest {
    /// Capability scope being exercised, e.g. "infra:restart:checkout".
    pub scope: String,
    /// Tool being invoked, e.g. "service_restart".
    pub tool: String,
    /// The acting agent's current autonomy tier (0..=3).
    pub autonomy_tier: u8,
    /// Estimated cost of the action in minor units.
    pub cost_minor: u64,
    /// Whether the action is high-impact (mutates external systems).
    #[serde(default)]
    pub high_impact: bool,
}

/// The result of evaluating a request against a policy set.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDecision {
    /// Whether the action is allowed.
    pub allowed: bool,
    /// Whether a human approval gate is required even if allowed.
    pub requires_approval: bool,
    /// The id of the rule that decided the outcome, if any (else default-deny/allow).
    pub deciding_rule_id: Option<String>,
    /// Human-readable reason.
    pub reason: String,
}

/// An ordered policy set with a default effect.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct PolicySet {
    /// Default effect when no rule matches. Default is deny (safe-by-default).
    #[serde(default)]
    pub default_allow: bool,
    /// Whether high-impact actions require human approval regardless of allow.
    #[serde(default = "default_true")]
    pub require_approval_for_high_impact: bool,
    /// The rules.
    pub rules: Vec<PolicyRule>,
}

fn default_true() -> bool {
    true
}

impl PolicySet {
    /// Construct a policy set.
    pub fn new(rules: Vec<PolicyRule>, default_allow: bool) -> Self {
        Self {
            default_allow,
            require_approval_for_high_impact: true,
            rules,
        }
    }

    /// Evaluate a request with deny-overrides semantics.
    ///
    /// 1. Collect all matching rules.
    /// 2. If any matching rule is `Deny`, the request is denied (deny-overrides),
    ///    choosing the highest-priority deny as the deciding rule.
    /// 3. Otherwise, if any matching rule is `Allow`, the request is allowed,
    ///    choosing the highest-priority allow as the deciding rule.
    /// 4. Otherwise the default effect applies.
    pub fn evaluate(&self, req: &PolicyRequest) -> PolicyDecision {
        let matching: Vec<&PolicyRule> = self.rules.iter().filter(|r| r.matches(req)).collect();

        let pick_highest = |effect: Effect| -> Option<&PolicyRule> {
            matching
                .iter()
                .filter(|r| r.effect == effect)
                .copied()
                .max_by_key(|r| r.priority)
        };

        let requires_approval = self.require_approval_for_high_impact && req.high_impact;

        if let Some(deny) = pick_highest(Effect::Deny) {
            return PolicyDecision {
                allowed: false,
                requires_approval: false,
                deciding_rule_id: Some(deny.id.clone()),
                reason: format!("denied by rule '{}'", deny.id),
            };
        }
        if let Some(allow) = pick_highest(Effect::Allow) {
            return PolicyDecision {
                allowed: true,
                requires_approval,
                deciding_rule_id: Some(allow.id.clone()),
                reason: format!("allowed by rule '{}'", allow.id),
            };
        }
        PolicyDecision {
            allowed: self.default_allow,
            requires_approval: requires_approval && self.default_allow,
            deciding_rule_id: None,
            reason: if self.default_allow {
                "allowed by default policy".into()
            } else {
                "denied by default policy (no matching rule)".into()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(scope: &str, tool: &str, tier: u8, cost: u64, high: bool) -> PolicyRequest {
        PolicyRequest {
            scope: scope.into(),
            tool: tool.into(),
            autonomy_tier: tier,
            cost_minor: cost,
            high_impact: high,
        }
    }

    #[test]
    fn default_deny_when_no_rules() {
        let set = PolicySet::new(vec![], false);
        let d = set.evaluate(&req("s3:read:logs", "log_search", 1, 10, false));
        assert!(!d.allowed);
        assert!(d.deciding_rule_id.is_none());
    }

    #[test]
    fn allow_rule_permits() {
        let set = PolicySet::new(
            vec![PolicyRule {
                id: "allow-reads".into(),
                effect: Effect::Allow,
                scope: Some("s3:read:*".into()),
                tool: None,
                min_autonomy_tier: None,
                max_cost_minor: None,
                priority: 0,
            }],
            false,
        );
        let d = set.evaluate(&req("s3:read:logs", "log_search", 1, 10, false));
        assert!(d.allowed);
        assert_eq!(d.deciding_rule_id.as_deref(), Some("allow-reads"));
    }

    #[test]
    fn deny_overrides_allow_regardless_of_priority() {
        let set = PolicySet::new(
            vec![
                PolicyRule {
                    id: "allow-all".into(),
                    effect: Effect::Allow,
                    scope: Some("*".into()),
                    tool: None,
                    min_autonomy_tier: None,
                    max_cost_minor: None,
                    priority: 100,
                },
                PolicyRule {
                    id: "deny-prod-delete".into(),
                    effect: Effect::Deny,
                    scope: Some("*:delete:*".into()),
                    tool: None,
                    min_autonomy_tier: None,
                    max_cost_minor: None,
                    priority: 1,
                },
            ],
            false,
        );
        let d = set.evaluate(&req("db:delete:prod", "dropper", 3, 0, true));
        assert!(!d.allowed);
        assert_eq!(d.deciding_rule_id.as_deref(), Some("deny-prod-delete"));
    }

    #[test]
    fn autonomy_tier_gates_rule() {
        let set = PolicySet::new(
            vec![PolicyRule {
                id: "allow-restart-high-tier".into(),
                effect: Effect::Allow,
                scope: Some("infra:restart:*".into()),
                tool: None,
                min_autonomy_tier: Some(2),
                max_cost_minor: None,
                priority: 0,
            }],
            false,
        );
        // Tier 1 agent: rule does not match -> default deny.
        assert!(
            !set.evaluate(&req("infra:restart:web", "service_restart", 1, 5, true))
                .allowed
        );
        // Tier 2 agent: rule matches -> allow.
        assert!(
            set.evaluate(&req("infra:restart:web", "service_restart", 2, 5, true))
                .allowed
        );
    }

    #[test]
    fn cost_ceiling_gates_rule() {
        let set = PolicySet::new(
            vec![PolicyRule {
                id: "allow-cheap".into(),
                effect: Effect::Allow,
                scope: Some("*".into()),
                tool: None,
                min_autonomy_tier: None,
                max_cost_minor: Some(100),
                priority: 0,
            }],
            false,
        );
        assert!(set.evaluate(&req("x", "y", 1, 50, false)).allowed);
        assert!(!set.evaluate(&req("x", "y", 1, 500, false)).allowed);
    }

    #[test]
    fn high_impact_requires_approval_even_when_allowed() {
        let set = PolicySet::new(
            vec![PolicyRule {
                id: "allow-all".into(),
                effect: Effect::Allow,
                scope: Some("*".into()),
                tool: None,
                min_autonomy_tier: None,
                max_cost_minor: None,
                priority: 0,
            }],
            false,
        );
        let d = set.evaluate(&req("infra:restart:web", "service_restart", 3, 5, true));
        assert!(d.allowed);
        assert!(d.requires_approval);
    }
}
