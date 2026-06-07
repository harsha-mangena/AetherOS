//! Agent constitutions — supreme, inviolable governance rules (Rust core).
//!
//! Phase 7. A *constitution* sits **above** the policy engine in the governance
//! hierarchy. Where [`crate::policy`] answers "is this specific action permitted by the
//! authored rule set?", a constitution answers "does this action violate an inviolable
//! principle that no policy, no autonomy tier, and no human convenience may override?".
//! Constitutional articles are the deny-of-last-resort: they are evaluated *before*
//! policy, and a constitutional `Forbid` is absolute — it cannot be overridden by any
//! allow rule, escalated past by a high autonomy tier, or waived by configuration. This
//! is precisely why the constitution lives in the Rust trust core and not in Python.
//!
//! Atom of thoughts:
//!   Article      = id + principle(text) + matcher(scope glob, tool glob, high_impact,
//!                  min_cost_minor) + verdict(Forbid | RequireApproval)
//!   Constitution = ordered set of Articles + version
//!   Judgment     = permitted | requires_approval + violated_article_id + principle
//!
//! Evaluation semantics (revalidated against constitutional-AI literature and
//! defense-in-depth authorization design): a constitution is checked first; if any
//! article with verdict `Forbid` matches, the action is categorically refused (the
//! strictest matching forbid is reported); else if any `RequireApproval` article
//! matches, the action is permitted only behind a human gate; else the constitution is
//! silent and the action passes through to ordinary policy evaluation. A constitution
//! never *grants* authority — it can only forbid or escalate — so layering it above
//! policy can only ever tighten, never loosen, the system's behaviour.

use serde::{Deserialize, Serialize};

use crate::glob::glob_match;

/// The verdict an article renders when it matches an action.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Categorically forbid the action. Absolute; nothing overrides it.
    Forbid,
    /// Permit only behind a mandatory human approval gate.
    RequireApproval,
}

/// A single constitutional article: an inviolable principle plus the actions it governs.
///
/// An article *matches* an action when every present matcher is satisfied; absent
/// matchers are wildcards. Unlike policy rules, articles carry no priority and no
/// allow effect — the constitution is a one-way ratchet toward stricter behaviour.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Article {
    /// Stable article identifier (cited in evidence when violated).
    pub id: String,
    /// Human-readable statement of the principle (e.g. "Never delete production data
    /// without explicit human approval").
    pub principle: String,
    /// The verdict rendered when this article matches.
    pub verdict: Verdict,
    /// Glob matched against the action scope. None = any.
    #[serde(default)]
    pub scope: Option<String>,
    /// Glob matched against the tool name. None = any.
    #[serde(default)]
    pub tool: Option<String>,
    /// If set, the article only matches actions whose `high_impact` equals this value.
    #[serde(default)]
    pub high_impact: Option<bool>,
    /// If set, the article only matches actions costing at least this many minor units.
    #[serde(default)]
    pub min_cost_minor: Option<u64>,
}

impl Article {
    /// Whether this article governs the given action.
    pub fn matches(&self, action: &ActionContext) -> bool {
        if let Some(scope_glob) = &self.scope {
            if !glob_match(scope_glob, &action.scope) {
                return false;
            }
        }
        if let Some(tool_glob) = &self.tool {
            if !glob_match(tool_glob, &action.tool) {
                return false;
            }
        }
        if let Some(hi) = self.high_impact {
            if action.high_impact != hi {
                return false;
            }
        }
        if let Some(min_cost) = self.min_cost_minor {
            if action.cost_minor < min_cost {
                return false;
            }
        }
        true
    }
}

/// The action a constitution is asked to judge.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionContext {
    /// Capability scope being exercised, e.g. "db:delete:prod".
    pub scope: String,
    /// Tool being invoked, e.g. "dropper".
    pub tool: String,
    /// The acting agent's current autonomy tier. Recorded for evidence only — it does
    /// **not** exempt the action from any article (tier cannot buy past a forbid).
    pub autonomy_tier: u8,
    /// Estimated cost of the action in minor units.
    pub cost_minor: u64,
    /// Whether the action mutates external systems.
    #[serde(default)]
    pub high_impact: bool,
}

/// The constitution's ruling on an action.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Judgment {
    /// Whether the action may proceed at all (false only when an article forbids it).
    pub permitted: bool,
    /// Whether the action, even if permitted, must pass a human approval gate.
    pub requires_approval: bool,
    /// The id of the article that decided the outcome, if any.
    pub article_id: Option<String>,
    /// The principle cited, if an article matched.
    pub principle: Option<String>,
    /// Human-readable explanation.
    pub reason: String,
}

impl Judgment {
    /// A clean pass: the constitution had nothing to say about this action.
    fn silent() -> Self {
        Self {
            permitted: true,
            requires_approval: false,
            article_id: None,
            principle: None,
            reason: "no constitutional article applies".into(),
        }
    }
}

/// An ordered, versioned set of constitutional articles.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Constitution {
    /// A stable version label for this constitution (cited in evidence).
    #[serde(default)]
    pub version: String,
    /// The articles, evaluated in declaration order for tie-reporting.
    pub articles: Vec<Article>,
}

impl Constitution {
    /// Construct a constitution from a version label and a set of articles.
    pub fn new(version: impl Into<String>, articles: Vec<Article>) -> Self {
        Self {
            version: version.into(),
            articles,
        }
    }

    /// Judge an action against the constitution.
    ///
    /// 1. If any matching article is `Forbid`, the action is categorically refused
    ///    (the first such article in declaration order is cited). This is absolute.
    /// 2. Otherwise, if any matching article is `RequireApproval`, the action is
    ///    permitted but flagged as requiring a human gate.
    /// 3. Otherwise the constitution is silent and the action proceeds to policy.
    pub fn judge(&self, action: &ActionContext) -> Judgment {
        // Forbid takes absolute precedence — scan for it first.
        if let Some(article) = self
            .articles
            .iter()
            .find(|a| a.verdict == Verdict::Forbid && a.matches(action))
        {
            return Judgment {
                permitted: false,
                requires_approval: false,
                article_id: Some(article.id.clone()),
                principle: Some(article.principle.clone()),
                reason: format!(
                    "forbidden by constitutional article '{}': {}",
                    article.id, article.principle
                ),
            };
        }
        if let Some(article) = self
            .articles
            .iter()
            .find(|a| a.verdict == Verdict::RequireApproval && a.matches(action))
        {
            return Judgment {
                permitted: true,
                requires_approval: true,
                article_id: Some(article.id.clone()),
                principle: Some(article.principle.clone()),
                reason: format!(
                    "approval required by constitutional article '{}': {}",
                    article.id, article.principle
                ),
            };
        }
        Judgment::silent()
    }

    /// The number of articles in the constitution.
    pub fn len(&self) -> usize {
        self.articles.len()
    }

    /// Whether the constitution has no articles.
    pub fn is_empty(&self) -> bool {
        self.articles.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn forbid(id: &str, scope: &str) -> Article {
        Article {
            id: id.into(),
            principle: format!("principle for {id}"),
            verdict: Verdict::Forbid,
            scope: Some(scope.into()),
            tool: None,
            high_impact: None,
            min_cost_minor: None,
        }
    }

    fn action(scope: &str, tool: &str, tier: u8, cost: u64, high: bool) -> ActionContext {
        ActionContext {
            scope: scope.into(),
            tool: tool.into(),
            autonomy_tier: tier,
            cost_minor: cost,
            high_impact: high,
        }
    }

    #[test]
    fn silent_when_no_article_matches() {
        let c = Constitution::new("v1", vec![forbid("no-prod-delete", "db:delete:prod")]);
        let j = c.judge(&action("s3:read:logs", "log_search", 1, 5, false));
        assert!(j.permitted);
        assert!(!j.requires_approval);
        assert!(j.article_id.is_none());
    }

    #[test]
    fn forbid_is_absolute_even_at_max_tier() {
        let c = Constitution::new("v1", vec![forbid("no-prod-delete", "db:delete:*")]);
        // A maximally-autonomous agent still cannot pass a constitutional forbid.
        let j = c.judge(&action("db:delete:prod", "dropper", 3, 0, true));
        assert!(!j.permitted);
        assert_eq!(j.article_id.as_deref(), Some("no-prod-delete"));
        assert!(j.principle.is_some());
    }

    #[test]
    fn forbid_wins_over_require_approval() {
        // Even if an approval article also matches, a matching forbid is supreme.
        let c = Constitution::new(
            "v1",
            vec![
                Article {
                    id: "approve-high-impact".into(),
                    principle: "high-impact needs a human".into(),
                    verdict: Verdict::RequireApproval,
                    scope: Some("*".into()),
                    tool: None,
                    high_impact: Some(true),
                    min_cost_minor: None,
                },
                forbid("no-prod-delete", "db:delete:prod"),
            ],
        );
        let j = c.judge(&action("db:delete:prod", "dropper", 3, 100, true));
        assert!(!j.permitted);
        assert_eq!(j.article_id.as_deref(), Some("no-prod-delete"));
    }

    #[test]
    fn require_approval_permits_behind_gate() {
        let c = Constitution::new(
            "v1",
            vec![Article {
                id: "approve-high-impact".into(),
                principle: "high-impact needs a human".into(),
                verdict: Verdict::RequireApproval,
                scope: Some("*".into()),
                tool: None,
                high_impact: Some(true),
                min_cost_minor: None,
            }],
        );
        let j = c.judge(&action("infra:restart:web", "service_restart", 2, 5, true));
        assert!(j.permitted);
        assert!(j.requires_approval);
        assert_eq!(j.article_id.as_deref(), Some("approve-high-impact"));
    }

    #[test]
    fn cost_floor_gates_article() {
        let c = Constitution::new(
            "v1",
            vec![Article {
                id: "approve-expensive".into(),
                principle: "large spend needs a human".into(),
                verdict: Verdict::RequireApproval,
                scope: Some("*".into()),
                tool: None,
                high_impact: None,
                min_cost_minor: Some(1000),
            }],
        );
        // Below the floor: silent.
        assert!(!c.judge(&action("x", "y", 1, 500, false)).requires_approval);
        // At/above the floor: approval required.
        assert!(c.judge(&action("x", "y", 1, 1000, false)).requires_approval);
    }

    #[test]
    fn first_matching_forbid_is_cited() {
        let c = Constitution::new(
            "v1",
            vec![
                forbid("article-a", "db:delete:*"),
                forbid("article-b", "db:delete:prod"),
            ],
        );
        let j = c.judge(&action("db:delete:prod", "dropper", 0, 0, true));
        assert!(!j.permitted);
        // Declaration order decides the citation.
        assert_eq!(j.article_id.as_deref(), Some("article-a"));
    }

    #[test]
    fn empty_constitution_is_always_silent() {
        let c = Constitution::default();
        assert!(c.is_empty());
        assert!(c.judge(&action("anything", "any", 3, 9999, true)).permitted);
    }
}
