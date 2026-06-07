//! Merkle transparency log over the evidence ledger (RFC 6962 / RFC 9162).
//!
//! The evidence ledger ([`crate::evidence`]) is tamper-evident to anyone holding the whole
//! ledger: recompute the hash chain and any edit is detected. But an enterprise auditor,
//! a regulator, or a peer AetherOS instance should be able to verify a *single* fact —
//! "entry N is included in the log whose head you signed" — without being shipped the
//! entire ledger, and to verify it against a short, signed commitment rather than trusting
//! the running system. That is exactly what a Merkle transparency log provides.
//!
//! Atom of thoughts:
//!   leaf hash      = SHA-256(0x00 || entry_hash_bytes)            (RFC 6962 §2.1)
//!   interior node  = SHA-256(0x01 || left || right)
//!   tree head      = the root hash over all current leaves
//!   STH            = (tree_size, root_hash, timestamp) signed by the log's Ed25519 key
//!   inclusion proof= the sibling hashes on the path from a leaf to the root
//!   consistency    = the minimal hashes proving an old root is a prefix of a new root
//!
//! Research net:
//!   - RFC 6962 "Certificate Transparency" — leaf/node domain separation (0x00 / 0x01),
//!     the inclusion-proof and consistency-proof algorithms (MTH, PATH, PROOF, SUBPROOF).
//!   - RFC 9162 "Certificate Transparency 2.0" — signed tree heads as the public commitment.
//!   - Crosby & Wallach, "Efficient Data Structures for Tamper-Evident Logging" (USENIX
//!     Security 2009) — the history-tree formulation these proofs descend from.
//!
//! Design tenets reused from the crate: deterministic hashing via [`crate::canonical`],
//! tamper *evidence* over tamper resistance, and authority that flows only through signed
//! artifacts (here, the STH is signed by an [`crate::identity::AgentIdentity`]).
//!
//! This module is pure and side-effect-free: it builds a tree from leaf hashes, emits
//! proofs, and verifies them. Signing/verifying the STH reuses the identity module so the
//! same Ed25519 key material governs leases, the constitution marketplace, and the log.

use serde::{Deserialize, Serialize};

use crate::canonical::{sha256_bytes, to_canonical_bytes};
use crate::error::{CoreError, Result};

/// Domain-separation prefix for leaf hashing (RFC 6962 §2.1).
const LEAF_PREFIX: u8 = 0x00;
/// Domain-separation prefix for interior-node hashing (RFC 6962 §2.1).
const NODE_PREFIX: u8 = 0x01;

/// Hash of an empty tree: SHA-256 of the empty string (RFC 6962 §2.1).
fn empty_root() -> [u8; 32] {
    sha256_bytes(b"")
}

/// Compute the RFC 6962 leaf hash for a leaf's raw bytes.
fn hash_leaf(leaf: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + leaf.len());
    buf.push(LEAF_PREFIX);
    buf.extend_from_slice(leaf);
    sha256_bytes(&buf)
}

/// Compute the RFC 6962 interior-node hash from its two child hashes.
fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + 64);
    buf.push(NODE_PREFIX);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    sha256_bytes(&buf)
}

/// The largest power of two strictly less than `n` (RFC 6962's `k` split point).
fn largest_power_of_two_below(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// The Merkle Tree Hash (MTH) of a slice of already-computed leaf hashes (RFC 6962 §2.1).
fn merkle_tree_hash(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = largest_power_of_two_below(n);
            let left = merkle_tree_hash(&leaves[..k]);
            let right = merkle_tree_hash(&leaves[k..]);
            hash_node(&left, &right)
        }
    }
}

/// An inclusion proof: the audit path proving a leaf is committed under a root.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InclusionProof {
    /// Zero-based index of the leaf within the tree.
    pub leaf_index: u64,
    /// Total number of leaves the proof is relative to.
    pub tree_size: u64,
    /// Sibling hashes from the leaf up to the root, lowercase hex, leaf-side first.
    pub audit_path: Vec<String>,
}

/// A consistency proof: that an old tree is a prefix of a newer tree (append-only).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsistencyProof {
    /// Size of the older tree.
    pub first_size: u64,
    /// Size of the newer tree.
    pub second_size: u64,
    /// The minimal node hashes proving consistency, lowercase hex.
    pub proof: Vec<String>,
}

/// The content of a signed tree head (the part that is hashed and signed).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TreeHeadContent {
    /// Number of leaves committed.
    pub tree_size: u64,
    /// Merkle root hash, lowercase hex.
    pub root_hash: String,
    /// RFC3339 timestamp the head was produced.
    pub timestamp: String,
}

/// A Signed Tree Head: the log's public, signed commitment to its current state.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedTreeHead {
    /// The signed content.
    pub content: TreeHeadContent,
    /// Ed25519 public key of the log signer, lowercase hex.
    pub signer_public_key: String,
    /// Ed25519 signature over the canonical bytes of `content`, lowercase hex.
    pub signature: String,
}

impl SignedTreeHead {
    /// Verify the STH signature against its embedded signer public key.
    pub fn verify(&self) -> Result<()> {
        let bytes = to_canonical_bytes(&self.content)?;
        crate::identity::verify_signature(&self.signer_public_key, &bytes, &self.signature)
    }
}

/// A Merkle transparency log built from evidence leaf hashes.
///
/// Leaves are the `entry_hash` values of the evidence ledger, in order. The log never
/// mutates leaves; it only appends, so an old signed root is always a prefix of a new one
/// — which the consistency proof makes checkable.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TransparencyLog {
    /// Raw leaf hashes (the RFC 6962 leaf hash of each evidence entry hash).
    leaves: Vec<[u8; 32]>,
}

impl TransparencyLog {
    /// Create an empty log.
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Build a log from the evidence ledger's entry hashes (hex), in order.
    ///
    /// Each `entry_hash` is decoded to bytes and run through the RFC 6962 leaf hash, so the
    /// log commits to the exact tamper-evident hash the ledger already computed.
    pub fn from_entry_hashes(entry_hashes: &[String]) -> Result<Self> {
        let mut log = Self::new();
        for h in entry_hashes {
            log.append_entry_hash(h)?;
        }
        Ok(log)
    }

    /// Append one evidence entry hash (hex) as a new leaf.
    pub fn append_entry_hash(&mut self, entry_hash_hex: &str) -> Result<()> {
        let raw = hex::decode(entry_hash_hex)
            .map_err(|e| CoreError::InvalidInput(format!("entry_hash hex: {e}")))?;
        self.leaves.push(hash_leaf(&raw));
        Ok(())
    }

    /// Number of leaves.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// The current Merkle root hash, lowercase hex.
    pub fn root_hash(&self) -> String {
        hex::encode(merkle_tree_hash(&self.leaves))
    }

    /// Produce a signed tree head over the current root using the given identity.
    pub fn signed_tree_head(
        &self,
        signer: &crate::identity::AgentIdentity,
        timestamp: impl Into<String>,
    ) -> Result<SignedTreeHead> {
        let content = TreeHeadContent {
            tree_size: self.leaves.len() as u64,
            root_hash: self.root_hash(),
            timestamp: timestamp.into(),
        };
        let bytes = to_canonical_bytes(&content)?;
        let signature = signer.sign(&bytes);
        Ok(SignedTreeHead {
            content,
            signer_public_key: signer.public_key_hex(),
            signature,
        })
    }

    /// Build an inclusion proof for the leaf at `index` against the current tree.
    pub fn inclusion_proof(&self, index: usize) -> Result<InclusionProof> {
        let n = self.leaves.len();
        if index >= n {
            return Err(CoreError::InvalidInput(format!(
                "leaf index {index} out of range for tree of size {n}"
            )));
        }
        let path = Self::audit_path(index, &self.leaves);
        Ok(InclusionProof {
            leaf_index: index as u64,
            tree_size: n as u64,
            audit_path: path.into_iter().map(hex::encode).collect(),
        })
    }

    /// RFC 6962 PATH(m, D[0:n]): sibling hashes from leaf m up to the root.
    fn audit_path(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
        let n = leaves.len();
        if n <= 1 {
            return Vec::new();
        }
        let k = largest_power_of_two_below(n);
        if m < k {
            let mut path = Self::audit_path(m, &leaves[..k]);
            path.push(merkle_tree_hash(&leaves[k..]));
            path
        } else {
            let mut path = Self::audit_path(m - k, &leaves[k..]);
            path.push(merkle_tree_hash(&leaves[..k]));
            path
        }
    }

    /// Build a consistency proof between tree sizes `first` and the current size.
    pub fn consistency_proof(&self, first: usize) -> Result<ConsistencyProof> {
        let n = self.leaves.len();
        if first == 0 || first > n {
            return Err(CoreError::InvalidInput(format!(
                "consistency first size {first} invalid for tree of size {n}"
            )));
        }
        let proof = Self::subproof(first, &self.leaves, true);
        Ok(ConsistencyProof {
            first_size: first as u64,
            second_size: n as u64,
            proof: proof.into_iter().map(hex::encode).collect(),
        })
    }

    /// RFC 6962 SUBPROOF(m, D[0:n], b).
    fn subproof(m: usize, leaves: &[[u8; 32]], b: bool) -> Vec<[u8; 32]> {
        let n = leaves.len();
        if m == n {
            if b {
                return Vec::new();
            }
            return vec![merkle_tree_hash(leaves)];
        }
        let k = largest_power_of_two_below(n);
        if m <= k {
            let mut proof = Self::subproof(m, &leaves[..k], b);
            proof.push(merkle_tree_hash(&leaves[k..]));
            proof
        } else {
            let mut proof = Self::subproof(m - k, &leaves[k..], false);
            proof.push(merkle_tree_hash(&leaves[..k]));
            proof
        }
    }
}

/// Verify an inclusion proof: that `entry_hash` is the leaf at the proof's index under
/// `root_hash_hex`. Recomputes the root from the leaf and the audit path (RFC 6962 §2.1.1).
pub fn verify_inclusion(
    proof: &InclusionProof,
    entry_hash_hex: &str,
    root_hash_hex: &str,
) -> Result<()> {
    let raw = hex::decode(entry_hash_hex)
        .map_err(|e| CoreError::InvalidInput(format!("entry_hash hex: {e}")))?;
    let mut computed = hash_leaf(&raw);

    let mut index = proof.leaf_index;
    let mut last_node = proof
        .tree_size
        .checked_sub(1)
        .ok_or_else(|| CoreError::InvalidInput("tree_size must be >= 1".into()))?;

    for sib_hex in &proof.audit_path {
        let sib = decode_32(sib_hex)?;
        if index % 2 == 1 || index == last_node {
            // We are a right child (or the rightmost node at this level): sibling is left.
            computed = hash_node(&sib, &computed);
            if index % 2 == 0 {
                // climbed via the rightmost-node rule; keep dividing until odd.
                while index % 2 == 0 {
                    index /= 2;
                    last_node /= 2;
                }
            }
        } else {
            // Left child: sibling is right.
            computed = hash_node(&computed, &sib);
        }
        index /= 2;
        last_node /= 2;
    }

    if index != 0 {
        return Err(CoreError::InvalidInput(
            "audit path did not reach the root".into(),
        ));
    }
    let expected = decode_32(root_hash_hex)?;
    if computed == expected {
        Ok(())
    } else {
        Err(CoreError::LedgerIntegrity {
            seq: proof.leaf_index,
            reason: "inclusion proof does not reconstruct the signed root".into(),
        })
    }
}

/// Verify a consistency proof between `first_root` and `second_root` (RFC 6962 §2.1.2).
pub fn verify_consistency(
    proof: &ConsistencyProof,
    first_root_hex: &str,
    second_root_hex: &str,
) -> Result<()> {
    let first_root = decode_32(first_root_hex)?;
    let second_root = decode_32(second_root_hex)?;
    let m = proof.first_size as usize;
    let n = proof.second_size as usize;
    if m == 0 || m > n {
        return Err(CoreError::InvalidInput("invalid consistency sizes".into()));
    }
    if m == n {
        // Equal trees: the proof is empty and both roots must match.
        if proof.proof.is_empty() && first_root == second_root {
            return Ok(());
        }
        return Err(CoreError::LedgerIntegrity {
            seq: m as u64,
            reason: "equal-size consistency requires identical roots".into(),
        });
    }

    let mut nodes: Vec<[u8; 32]> = proof
        .proof
        .iter()
        .map(|h| decode_32(h))
        .collect::<Result<_>>()?;

    // RFC 6962 verification: if m is a power of two, the first root is implied and
    // prepended; otherwise the proof's first element is the seed for both computations.
    let m_is_pow2 = m & (m - 1) == 0;
    if m_is_pow2 {
        nodes.insert(0, first_root);
    }
    if nodes.is_empty() {
        return Err(CoreError::InvalidInput("empty consistency proof".into()));
    }

    let mut fn_ = m - 1;
    let mut sn = n - 1;
    while fn_ % 2 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }

    let mut iter = nodes.iter();
    let seed = *iter.next().unwrap();
    let mut fr = seed;
    let mut sr = seed;

    for node in iter {
        if fn_ % 2 == 1 || fn_ == sn {
            fr = hash_node(node, &fr);
            sr = hash_node(node, &sr);
            while fn_ % 2 == 0 && fn_ != 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            sr = hash_node(&sr, node);
        }
        fn_ >>= 1;
        sn >>= 1;
    }

    if fr == first_root && sr == second_root {
        Ok(())
    } else {
        Err(CoreError::LedgerIntegrity {
            seq: m as u64,
            reason: "consistency proof does not connect the two signed roots".into(),
        })
    }
}

fn decode_32(hex_str: &str) -> Result<[u8; 32]> {
    let raw =
        hex::decode(hex_str).map_err(|e| CoreError::InvalidInput(format!("hash hex: {e}")))?;
    raw.try_into()
        .map_err(|_| CoreError::InvalidInput("hash must be 32 bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentIdentity;

    fn leaves_hex(n: usize) -> Vec<String> {
        // Deterministic distinct "entry hashes".
        (0..n)
            .map(|i| crate::canonical::sha256_hex(format!("entry-{i}").as_bytes()))
            .collect()
    }

    fn log_of(n: usize) -> (TransparencyLog, Vec<String>) {
        let hashes = leaves_hex(n);
        (TransparencyLog::from_entry_hashes(&hashes).unwrap(), hashes)
    }

    #[test]
    fn empty_and_single_roots() {
        let empty = TransparencyLog::new();
        assert_eq!(empty.root_hash(), hex::encode(empty_root()));
        let (one, h) = log_of(1);
        assert_eq!(
            one.root_hash(),
            hex::encode(hash_leaf(&hex::decode(&h[0]).unwrap()))
        );
    }

    #[test]
    fn inclusion_proof_roundtrips_for_every_leaf() {
        for size in 1..=33usize {
            let (log, hashes) = log_of(size);
            let root = log.root_hash();
            for (i, leaf_hash) in hashes.iter().enumerate().take(size) {
                let proof = log.inclusion_proof(i).unwrap();
                verify_inclusion(&proof, leaf_hash, &root)
                    .unwrap_or_else(|e| panic!("size {size} leaf {i}: {e:?}"));
            }
        }
    }

    #[test]
    fn inclusion_proof_rejects_wrong_leaf() {
        let (log, hashes) = log_of(8);
        let root = log.root_hash();
        let proof = log.inclusion_proof(3).unwrap();
        // A different leaf's hash must not verify against leaf 3's proof.
        assert!(verify_inclusion(&proof, &hashes[4], &root).is_err());
    }

    #[test]
    fn inclusion_proof_rejects_forged_root() {
        let (log, hashes) = log_of(8);
        let proof = log.inclusion_proof(2).unwrap();
        let forged = crate::canonical::sha256_hex(b"not-the-root");
        assert!(verify_inclusion(&proof, &hashes[2], &forged).is_err());
    }

    #[test]
    fn inclusion_proof_rejects_tampered_path() {
        let (log, hashes) = log_of(8);
        let root = log.root_hash();
        let mut proof = log.inclusion_proof(5).unwrap();
        if let Some(first) = proof.audit_path.first_mut() {
            *first = crate::canonical::sha256_hex(b"tampered-sibling");
        }
        assert!(verify_inclusion(&proof, &hashes[5], &root).is_err());
    }

    #[test]
    fn consistency_proof_roundtrips() {
        for n in 2..=24usize {
            let (log_n, hashes) = log_of(n);
            let second_root = log_n.root_hash();
            for m in 1..n {
                let first_root = TransparencyLog::from_entry_hashes(&hashes[..m])
                    .unwrap()
                    .root_hash();
                let proof = log_n.consistency_proof(m).unwrap();
                verify_consistency(&proof, &first_root, &second_root)
                    .unwrap_or_else(|e| panic!("n {n} m {m}: {e:?}"));
            }
        }
    }

    #[test]
    fn consistency_proof_rejects_non_prefix() {
        // Build two logs that diverge: the "old" root is NOT a prefix of the new tree.
        let (log_new, _) = log_of(8);
        let second_root = log_new.root_hash();
        let bogus_old_root = crate::canonical::sha256_hex(b"divergent-history");
        let proof = log_new.consistency_proof(4).unwrap();
        assert!(verify_consistency(&proof, &bogus_old_root, &second_root).is_err());
    }

    #[test]
    fn signed_tree_head_verifies_and_detects_tampering() {
        let (log, _) = log_of(10);
        let id = AgentIdentity::generate("log-signer", "2026-06-07T00:00:00Z");
        let sth = log.signed_tree_head(&id, "2026-06-07T00:00:05Z").unwrap();
        assert!(sth.verify().is_ok());
        assert_eq!(sth.content.tree_size, 10);

        // Tamper with the committed root: signature must no longer verify.
        let mut tampered = sth.clone();
        tampered.content.root_hash = crate::canonical::sha256_hex(b"swapped-root");
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn root_matches_known_two_leaf_construction() {
        // For two leaves, root = node(leaf(h0), leaf(h1)).
        let (log, hashes) = log_of(2);
        let l0 = hash_leaf(&hex::decode(&hashes[0]).unwrap());
        let l1 = hash_leaf(&hex::decode(&hashes[1]).unwrap());
        assert_eq!(log.root_hash(), hex::encode(hash_node(&l0, &l1)));
    }
}
