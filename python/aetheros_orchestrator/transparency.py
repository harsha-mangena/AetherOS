"""Transparency log — Python authoring over the Rust RFC 6962 Merkle log.

Phase 8. The evidence ledger is tamper-evident to anyone holding the whole chain. The
transparency log turns that into something an external party can verify cheaply and against
a signed commitment: a Merkle tree over the ledger's entry hashes, a Signed Tree Head (STH)
the log operator signs with its agent identity, and inclusion/consistency proofs.

Authoring and wiring live here; the RFC 6962 hashing, proof generation, and proof
verification live in the Rust core (`aether_core::transparency`) where they are fixed and
auditable. This wrapper never re-implements any cryptography — it only marshals the
ledger's entry hashes in, and proofs/STHs out.

Composition contract: the log is a pure projection over the ledger. It can attest to what
the ledger already records but can never assert inclusion of an entry the ledger does not
contain — a forged inclusion proof fails verification against the signed root, and a
divergent history fails the consistency check.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

from aetheros import _aether_native as _native  # type: ignore

if TYPE_CHECKING:
    from aetheros import AgentIdentity, EvidenceLedger


@dataclass
class SignedTreeHead:
    """The log's signed commitment to its current state."""

    tree_size: int
    root_hash: str
    timestamp: str
    signer_public_key: str
    signature: str

    def to_dict(self) -> dict:
        return {
            "tree_size": self.tree_size,
            "root_hash": self.root_hash,
            "timestamp": self.timestamp,
            "signer_public_key": self.signer_public_key,
            "signature": self.signature,
        }


@dataclass
class InclusionProof:
    """An audit path proving one evidence entry is committed under a signed root."""

    leaf_index: int
    tree_size: int
    audit_path: list[str]
    entry_hash: str

    def to_dict(self) -> dict:
        return {
            "leaf_index": self.leaf_index,
            "tree_size": self.tree_size,
            "audit_path": self.audit_path,
            "entry_hash": self.entry_hash,
        }


class TransparencyLog:
    """Config-free, Rust-evaluated Merkle transparency log over an evidence ledger."""

    def __init__(self, entry_hashes: list[str]) -> None:
        self._entry_hashes = list(entry_hashes)
        self._log = _native.TransparencyLog.from_entry_hashes(json.dumps(self._entry_hashes))

    @classmethod
    def from_ledger(cls, ledger: "EvidenceLedger") -> "TransparencyLog":
        """Build a transparency log from an evidence ledger's entry hashes, in order."""
        return cls([entry.entry_hash for entry in ledger.entries()])

    @property
    def size(self) -> int:
        return self._log.len

    @property
    def root_hash(self) -> str:
        return self._log.root_hash

    def signed_tree_head(self, signer: "AgentIdentity", timestamp: str) -> SignedTreeHead:
        """Sign the current Merkle root into an STH using the signer's identity."""
        raw = self._log.signed_tree_head(signer._native, timestamp)
        data = json.loads(raw)
        content = data["content"]
        return SignedTreeHead(
            tree_size=content["tree_size"],
            root_hash=content["root_hash"],
            timestamp=content["timestamp"],
            signer_public_key=data["signer_public_key"],
            signature=data["signature"],
        )

    def inclusion_proof(self, index: int) -> InclusionProof:
        """Produce an inclusion proof for the evidence entry at `index`."""
        if index < 0 or index >= len(self._entry_hashes):
            raise IndexError(f"leaf index {index} out of range for log of size {self.size}")
        raw = self._log.inclusion_proof(index)
        data = json.loads(raw)
        return InclusionProof(
            leaf_index=data["leaf_index"],
            tree_size=data["tree_size"],
            audit_path=data["audit_path"],
            entry_hash=self._entry_hashes[index],
        )

    def consistency_proof(self, first_size: int) -> dict:
        """Produce a consistency proof from an earlier tree size to the current size."""
        raw = self._log.consistency_proof(first_size)
        return json.loads(raw)


def verify_inclusion(proof: InclusionProof | dict, entry_hash: str, root_hash: str) -> bool:
    """Verify that `entry_hash` is committed at the proof's index under `root_hash`."""
    proof_dict = proof.to_dict() if isinstance(proof, InclusionProof) else dict(proof)
    # The native verifier consumes only index/tree_size/audit_path.
    payload = {
        "leaf_index": proof_dict["leaf_index"],
        "tree_size": proof_dict["tree_size"],
        "audit_path": proof_dict["audit_path"],
    }
    return bool(_native.verify_inclusion(json.dumps(payload), entry_hash, root_hash))


def verify_consistency(proof: dict, first_root: str, second_root: str) -> bool:
    """Verify a consistency proof connecting two signed roots (append-only)."""
    return bool(_native.verify_consistency(json.dumps(proof), first_root, second_root))


def verify_signed_tree_head(sth: SignedTreeHead | dict) -> bool:
    """Verify an STH's Ed25519 signature over its canonical (tree_size, root, timestamp)."""
    from aetheros import verify_signature

    data = sth.to_dict() if isinstance(sth, SignedTreeHead) else dict(sth)
    # Reconstruct the exact canonical bytes the core signed: the TreeHeadContent object.
    content = {
        "root_hash": data["root_hash"],
        "timestamp": data["timestamp"],
        "tree_size": data["tree_size"],
    }
    canonical = json.dumps(content, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return verify_signature(data["signer_public_key"], canonical, data["signature"])
