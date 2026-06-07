//! Tamper-evident evidence ledger.
//!
//! The evidence ledger is AetherOS's append-only, hash-chained record of everything
//! that agents plan, access, change, and spend. It is the audit substrate that makes
//! autonomous work accountable and replayable.
//!
//! Atom of thoughts:
//!   EvidenceEntry = seq + timestamp + actor + event_type + payload(JSON)
//!                 + prev_hash + entry_hash
//!   entry_hash = SHA-256( prev_hash_bytes || canonical(entry_without_hash) )
//!
//! Chain-of-thoughts (verification):
//!   genesis prev_hash = 64 zero hex chars
//!   for each entry: recompute entry_hash from prev_hash + canonical content;
//!   it must equal the stored entry_hash, and the next entry's prev_hash must equal
//!   this entry's entry_hash. Any insertion, deletion, reordering, or field edit
//!   breaks the chain and is detected.

use serde::{Deserialize, Serialize};

use crate::canonical::{sha256_chain_hex, to_canonical_bytes};
use crate::error::{CoreError, Result};

/// The all-zero genesis hash that precedes the first entry.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The content of an evidence entry that is fed into the hash (excludes `entry_hash`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceContent {
    /// Monotonic sequence number, starting at 0.
    pub seq: u64,
    /// RFC3339 timestamp of the event.
    pub timestamp: String,
    /// Identifier of the actor responsible (agent_id, "control-plane", "human:<id>").
    pub actor: String,
    /// Event type, e.g. "intent.submitted", "lease.issued", "tool.invoked",
    /// "budget.charged", "approval.granted", "policy.denied".
    pub event_type: String,
    /// Arbitrary structured payload describing the event.
    pub payload: serde_json::Value,
    /// Hash of the previous entry (or [`GENESIS_HASH`] for seq 0).
    pub prev_hash: String,
}

/// A complete, hashed evidence entry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceEntry {
    /// The hashed content.
    #[serde(flatten)]
    pub content: EvidenceContent,
    /// SHA-256 chain hash over (prev_hash || canonical(content)).
    pub entry_hash: String,
}

impl EvidenceEntry {
    /// Recompute the expected hash for this entry's content and prev_hash.
    fn compute_hash(content: &EvidenceContent) -> Result<String> {
        let prev_bytes = hex::decode(&content.prev_hash)
            .map_err(|e| CoreError::InvalidInput(format!("prev_hash hex: {e}")))?;
        let content_bytes = to_canonical_bytes(content)?;
        Ok(sha256_chain_hex(&prev_bytes, &content_bytes))
    }
}

/// An append-only, hash-chained ledger of evidence entries.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EvidenceLedger {
    entries: Vec<EvidenceEntry>,
}

impl EvidenceLedger {
    /// Create an empty ledger.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Number of entries recorded.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the ledger has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The hash of the most recent entry, or [`GENESIS_HASH`] if empty. This is the
    /// "head" that the next entry will chain from.
    pub fn head_hash(&self) -> String {
        self.entries
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap_or_else(|| GENESIS_HASH.to_string())
    }

    /// Append a new evidence event, chaining it to the current head.
    ///
    /// Returns the sequence number and hash of the new entry.
    pub fn append(
        &mut self,
        timestamp: impl Into<String>,
        actor: impl Into<String>,
        event_type: impl Into<String>,
        payload: serde_json::Value,
    ) -> Result<(u64, String)> {
        let seq = self.entries.len() as u64;
        let prev_hash = self.head_hash();
        let content = EvidenceContent {
            seq,
            timestamp: timestamp.into(),
            actor: actor.into(),
            event_type: event_type.into(),
            payload,
            prev_hash,
        };
        let entry_hash = EvidenceEntry::compute_hash(&content)?;
        let entry = EvidenceEntry {
            content,
            entry_hash: entry_hash.clone(),
        };
        self.entries.push(entry);
        Ok((seq, entry_hash))
    }

    /// Borrow all entries in order.
    pub fn entries(&self) -> &[EvidenceEntry] {
        &self.entries
    }

    /// Verify the entire hash chain from genesis to head.
    ///
    /// Detects any tampering: edited fields, reordering, insertion, or deletion.
    pub fn verify(&self) -> Result<()> {
        let mut expected_prev = GENESIS_HASH.to_string();
        for (i, entry) in self.entries.iter().enumerate() {
            let seq = i as u64;
            if entry.content.seq != seq {
                return Err(CoreError::LedgerIntegrity {
                    seq,
                    reason: format!(
                        "sequence mismatch: entry declares {}, expected {}",
                        entry.content.seq, seq
                    ),
                });
            }
            if entry.content.prev_hash != expected_prev {
                return Err(CoreError::LedgerIntegrity {
                    seq,
                    reason: "prev_hash does not match previous entry's hash".into(),
                });
            }
            let recomputed = EvidenceEntry::compute_hash(&entry.content)?;
            if recomputed != entry.entry_hash {
                return Err(CoreError::LedgerIntegrity {
                    seq,
                    reason: "entry_hash does not match recomputed content hash".into(),
                });
            }
            expected_prev = entry.entry_hash.clone();
        }
        Ok(())
    }

    /// Replay the ledger, returning a chronological list of (seq, event_type, actor)
    /// tuples. Verification is performed first; replay on a broken ledger errors.
    pub fn replay_summary(&self) -> Result<Vec<(u64, String, String)>> {
        self.verify()?;
        Ok(self
            .entries
            .iter()
            .map(|e| {
                (
                    e.content.seq,
                    e.content.event_type.clone(),
                    e.content.actor.clone(),
                )
            })
            .collect())
    }

    /// Serialize the whole ledger to a JSON string (for persistence).
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| CoreError::Serialization(e.to_string()))
    }

    /// Load a ledger from a JSON string and verify its integrity.
    pub fn from_json(json: &str) -> Result<Self> {
        let ledger: EvidenceLedger =
            serde_json::from_str(json).map_err(|e| CoreError::Serialization(e.to_string()))?;
        ledger.verify()?;
        Ok(ledger)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn populated() -> EvidenceLedger {
        let mut l = EvidenceLedger::new();
        l.append(
            "2026-06-07T00:00:00Z",
            "human:vamsi",
            "intent.submitted",
            json!({"intent": "investigate prod incident 4821"}),
        )
        .unwrap();
        l.append(
            "2026-06-07T00:00:01Z",
            "control-plane",
            "lease.issued",
            json!({"scopes": ["s3:read:logs"], "budget_minor": 10000}),
        )
        .unwrap();
        l.append(
            "2026-06-07T00:00:02Z",
            "agent:investigator",
            "tool.invoked",
            json!({"tool": "log_search", "cost_minor": 12}),
        )
        .unwrap();
        l
    }

    #[test]
    fn genesis_head_is_zero() {
        let l = EvidenceLedger::new();
        assert_eq!(l.head_hash(), GENESIS_HASH);
        assert!(l.is_empty());
    }

    #[test]
    fn append_chains_and_verifies() {
        let l = populated();
        assert_eq!(l.len(), 3);
        assert!(l.verify().is_ok());
        assert_eq!(l.entries()[0].content.prev_hash, GENESIS_HASH);
        assert_eq!(l.entries()[1].content.prev_hash, l.entries()[0].entry_hash);
        assert_eq!(l.entries()[2].content.prev_hash, l.entries()[1].entry_hash);
    }

    #[test]
    fn tampering_payload_breaks_chain() {
        let mut l = populated();
        l.entries[1].content.payload = json!({"scopes": ["admin:all"]});
        assert!(l.verify().is_err());
    }

    #[test]
    fn deleting_entry_breaks_chain() {
        let mut l = populated();
        l.entries.remove(1);
        assert!(l.verify().is_err());
    }

    #[test]
    fn reordering_breaks_chain() {
        let mut l = populated();
        l.entries.swap(0, 1);
        assert!(l.verify().is_err());
    }

    #[test]
    fn replay_summary_is_chronological() {
        let l = populated();
        let summary = l.replay_summary().unwrap();
        assert_eq!(summary.len(), 3);
        assert_eq!(summary[0].1, "intent.submitted");
        assert_eq!(summary[2].1, "tool.invoked");
    }

    #[test]
    fn json_roundtrip_preserves_and_verifies() {
        let l = populated();
        let json = l.to_json().unwrap();
        let restored = EvidenceLedger::from_json(&json).unwrap();
        assert_eq!(restored.len(), 3);
        assert!(restored.verify().is_ok());
    }

    #[test]
    fn from_json_rejects_tampered_ledger() {
        let mut l = populated();
        l.entries[2].entry_hash = "deadbeef".repeat(8);
        let json = serde_json::to_string(&l).unwrap();
        assert!(EvidenceLedger::from_json(&json).is_err());
    }
}
