"""Witness cosigning — defeating split-view (equivocation) attacks on the log.

Phase 9b. A consistency proof shows a single observer that the log grew append-only between
two roots *it* saw. It does **not** stop a malicious or compromised log from presenting two
different, each-internally-consistent histories to two different auditors — a split view, or
equivocation. Each auditor's proofs pass; only by comparing notes would they catch the fork.

The deployed defense (RFC 6962 §7.2 gossip, hardened by the Sigsum and IETF/C2SP
``tlog-witness`` designs) is *witness cosigning*. A set of independent witnesses each tracks
the last tree head it endorsed for a given log. To cosign a new tree head a witness demands a
consistency proof from its own last-seen root to the new one, verifies the new head's own
signature, and only then adds its signature over the *same canonical tree-head bytes the log
signed*. A tree head carrying K independent witness cosignatures is a cryptographic promise
that the log showed one and the same append-only history to all K witnesses: it cannot have
equivocated without at least one honest witness refusing to cosign and exposing the fork.

This layer is pure orchestration over primitives already fixed and cross-language-verified in
the Rust core — Ed25519 sign/verify, consistency-proof verification, and the canonical STH
byte reconstruction. It introduces no new cryptography; it encodes *policy over proofs*. That
keeps the Rust trust core minimal (it owns proofs) while the witness owns the gossip protocol
over them, mirroring how :mod:`transparency` layered authoring above the core.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .transparency import (
    SignedTreeHead,
    verify_consistency,
    verify_signed_tree_head,
)

if TYPE_CHECKING:
    from aetheros import AgentIdentity


def _canonical_tree_head_bytes(sth: SignedTreeHead | dict) -> bytes:
    """The exact bytes the log signed for a tree head — what a witness re-signs.

    Identical reconstruction to :func:`transparency.verify_signed_tree_head`, so a witness
    cosignature is verifiable by the same :func:`verify_signature` against the witness key.
    """
    data = sth.to_dict() if isinstance(sth, SignedTreeHead) else dict(sth)
    content = {
        "root_hash": data["root_hash"],
        "timestamp": data["timestamp"],
        "tree_size": data["tree_size"],
    }
    return json.dumps(content, separators=(",", ":"), sort_keys=True).encode("utf-8")


class WitnessRefusal(Exception):
    """Raised when a witness refuses to cosign — the honest signal of equivocation/forgery.

    Carries a machine-readable ``reason`` so a registry can distinguish a benign decline
    (e.g. stale tree head) from evidence of an actual split view.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass
class Cosignature:
    """One witness's endorsement of a specific tree head."""

    witness_id: str
    witness_public_key: str
    tree_size: int
    root_hash: str
    signature: str

    def to_dict(self) -> dict:
        return {
            "witness_id": self.witness_id,
            "witness_public_key": self.witness_public_key,
            "tree_size": self.tree_size,
            "root_hash": self.root_hash,
            "signature": self.signature,
        }


@dataclass
class CosignedTreeHead:
    """An STH plus the independent witness cosignatures gathered over it."""

    signed_tree_head: dict
    cosignatures: list[Cosignature] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "signed_tree_head": dict(self.signed_tree_head),
            "cosignatures": [c.to_dict() for c in self.cosignatures],
        }


class Witness:
    """An independent observer that cosigns tree heads only along a consistent history.

    A witness is single-log-scoped per ``log_id``: it remembers the last tree head it endorsed
    for each log and will only advance to a new head that is provably consistent with it.
    """

    def __init__(self, identity: "AgentIdentity") -> None:
        self._identity = identity
        # log_id -> last (tree_size, root_hash) this witness cosigned.
        self._last_seen: dict[str, tuple[int, str]] = {}

    @property
    def witness_id(self) -> str:
        return self._identity.agent_id

    @property
    def public_key(self) -> str:
        return self._identity.public_key

    def last_seen(self, log_id: str) -> tuple[int, str] | None:
        return self._last_seen.get(log_id)

    def cosign(
        self,
        log_id: str,
        new_sth: SignedTreeHead | dict,
        consistency_proof: dict | None = None,
    ) -> Cosignature:
        """Endorse ``new_sth`` for ``log_id`` iff it is genuine and append-only consistent.

        Steps, in order, each a hard gate:
          1. The new tree head must carry a valid log signature over its own canonical bytes.
          2. If this witness has endorsed an earlier head for this log, the caller must supply
             a consistency proof, and it must verify from the witness's *retained* root to the
             new root. The witness never trusts the server's claim of the old root — it checks
             against the root it itself holds, which is what defeats a split view.
          3. A non-advancing tree head (size strictly less than last seen) is rejected as a
             rollback. An identical re-presentation (same size, same root) is re-endorsed
             idempotently; same size with a *different* root is equivocation and is refused.

        On success the witness advances its last-seen pointer and returns its cosignature.
        Refusal raises :class:`WitnessRefusal` — the protocol's evidence of misbehavior.
        """
        data = new_sth.to_dict() if isinstance(new_sth, SignedTreeHead) else dict(new_sth)
        new_size = data["tree_size"]
        new_root = data["root_hash"]

        # 1. Authenticity of the new head.
        if not verify_signed_tree_head(data):
            raise WitnessRefusal("invalid_sth_signature",
                                  f"log signature does not verify for size {new_size}")

        prior = self._last_seen.get(log_id)
        if prior is not None:
            prior_size, prior_root = prior

            # 3a. Rollback: the log shrank.
            if new_size < prior_size:
                raise WitnessRefusal(
                    "rollback",
                    f"new size {new_size} < last cosigned size {prior_size}",
                )

            # 3b. Same size: must be the same root, else the log equivocated.
            if new_size == prior_size:
                if new_root != prior_root:
                    raise WitnessRefusal(
                        "equivocation",
                        f"size {new_size} presented with divergent root "
                        f"{new_root[:16]}… vs retained {prior_root[:16]}…",
                    )
                # Idempotent re-endorsement of the identical head.
                return self._sign(data)

            # 3c. Growth: demand and verify a consistency proof against the RETAINED root.
            if consistency_proof is None:
                raise WitnessRefusal(
                    "missing_consistency_proof",
                    f"growth {prior_size}->{new_size} requires a consistency proof",
                )
            if not verify_consistency(consistency_proof, prior_root, new_root):
                raise WitnessRefusal(
                    "inconsistent",
                    f"consistency proof {prior_size}->{new_size} fails against "
                    f"retained root {prior_root[:16]}…",
                )

        # First sighting (prior is None) or verified growth: advance and sign.
        cosig = self._sign(data)
        self._last_seen[log_id] = (new_size, new_root)
        return cosig

    def _sign(self, data: dict) -> Cosignature:
        canonical = _canonical_tree_head_bytes(data)
        signature = self._identity.sign(canonical)
        return Cosignature(
            witness_id=self.witness_id,
            witness_public_key=self.public_key,
            tree_size=data["tree_size"],
            root_hash=data["root_hash"],
            signature=signature,
        )


def verify_cosignature(cosig: Cosignature | dict, sth: SignedTreeHead | dict) -> bool:
    """Verify one witness cosignature binds the witness's key to this tree head."""
    from aetheros import verify_signature

    c = cosig.to_dict() if isinstance(cosig, Cosignature) else dict(cosig)
    head = sth.to_dict() if isinstance(sth, SignedTreeHead) else dict(sth)
    # The cosignature must be over the *same* tree head, not merely a well-formed signature.
    if c["tree_size"] != head["tree_size"] or c["root_hash"] != head["root_hash"]:
        return False
    canonical = _canonical_tree_head_bytes(head)
    return verify_signature(c["witness_public_key"], canonical, c["signature"])


class WitnessRegistry:
    """A panel of independent witnesses that gossip a single log's tree heads.

    Aggregating K honest, independent witnesses raises the bar for a split view from "fool one
    auditor" to "fool every witness simultaneously without any refusing" — which an
    append-only log cannot do. The registry exposes a threshold: a tree head is *publicly
    trustworthy* once at least ``threshold`` distinct witnesses have cosigned it.
    """

    def __init__(self, witnesses: list[Witness], threshold: int | None = None) -> None:
        if not witnesses:
            raise ValueError("a witness registry needs at least one witness")
        # Distinct witnesses only — duplicate keys cannot manufacture independence.
        seen: set[str] = set()
        unique: list[Witness] = []
        for w in witnesses:
            if w.public_key in seen:
                continue
            seen.add(w.public_key)
            unique.append(w)
        self._witnesses = unique
        n = len(unique)
        # Default to a strict majority — the smallest panel that no single equivocation fools.
        self._threshold = threshold if threshold is not None else (n // 2 + 1)
        if not (1 <= self._threshold <= n):
            raise ValueError(
                f"threshold {self._threshold} outside [1, {n}] for {n} witnesses"
            )

    @property
    def threshold(self) -> int:
        return self._threshold

    @property
    def size(self) -> int:
        return len(self._witnesses)

    def cosign(
        self,
        log_id: str,
        new_sth: SignedTreeHead | dict,
        consistency_proof: dict | None = None,
    ) -> CosignedTreeHead:
        """Gather cosignatures from every witness that does not refuse.

        Honest refusals (rollback/equivocation/inconsistency) are *not* fatal here — they are
        exactly the signal the panel exists to surface. The caller decides, via
        :meth:`is_trustworthy`, whether enough independent witnesses endorsed the head.
        """
        head = new_sth.to_dict() if isinstance(new_sth, SignedTreeHead) else dict(new_sth)
        cosigs: list[Cosignature] = []
        for w in self._witnesses:
            try:
                cosigs.append(w.cosign(log_id, head, consistency_proof))
            except WitnessRefusal:
                # An honest witness declining is evidence, not an error. Omit its signature.
                continue
        return CosignedTreeHead(signed_tree_head=head, cosignatures=cosigs)

    def is_trustworthy(self, cosigned: CosignedTreeHead) -> bool:
        """True iff at least ``threshold`` distinct, valid witness cosignatures are present.

        Every cosignature is re-verified against the embedded tree head and counted at most
        once per witness key — so a forged or duplicated cosignature cannot reach quorum.
        """
        head = cosigned.signed_tree_head
        if not verify_signed_tree_head(head):
            return False
        known = {w.public_key for w in self._witnesses}
        valid_keys: set[str] = set()
        for c in cosigned.cosignatures:
            cd = c.to_dict() if isinstance(c, Cosignature) else dict(c)
            key = cd["witness_public_key"]
            if key not in known:
                continue  # not a member of this panel
            if verify_cosignature(cd, head):
                valid_keys.add(key)
        return len(valid_keys) >= self._threshold
