"""Agent identity — Python wrapper over the native Ed25519 identity."""

from __future__ import annotations

import json

from pydantic import BaseModel, Field

from . import _aether_native as _native
from .time_utils import now_rfc3339


class AgentDescriptor(BaseModel):
    """Shareable public view of an agent identity (no secret material)."""

    agent_id: str = Field(..., description="Stable agent identifier (UUIDv4).")
    display_name: str
    created_at: str = Field(..., description="RFC3339 creation timestamp.")
    public_key: str = Field(..., description="Ed25519 public key, hex.")
    fingerprint: str = Field(..., description="First 16 bytes of SHA-256(pubkey), hex.")


class AgentIdentity:
    """A cryptographic identity for an AetherOS agent.

    Wraps the native identity. The private signing key lives in Rust and is never
    materialized in Python except as an explicitly exported secret seed.
    """

    def __init__(self, native: "_native.AgentIdentity") -> None:
        self._native = native

    @classmethod
    def generate(cls, display_name: str, created_at: str | None = None) -> "AgentIdentity":
        """Generate a new identity with a fresh keypair."""
        return cls(_native.AgentIdentity.generate(display_name, created_at or now_rfc3339()))

    @classmethod
    def from_seed_hex(
        cls,
        agent_id: str,
        display_name: str,
        created_at: str,
        seed_hex: str,
    ) -> "AgentIdentity":
        """Restore an identity from a persisted 32-byte secret seed (hex)."""
        return cls(
            _native.AgentIdentity.from_seed_hex(agent_id, display_name, created_at, seed_hex)
        )

    @property
    def agent_id(self) -> str:
        return self._native.agent_id

    @property
    def display_name(self) -> str:
        return self._native.display_name

    @property
    def created_at(self) -> str:
        return self._native.created_at

    @property
    def public_key(self) -> str:
        return self._native.public_key

    @property
    def fingerprint(self) -> str:
        return self._native.fingerprint

    def secret_seed_hex(self) -> str:
        """Export the secret seed (hex). Store in a secret manager; never log."""
        return self._native.secret_seed_hex()

    def sign(self, message: bytes) -> str:
        """Sign message bytes, returning an Ed25519 signature as hex."""
        return self._native.sign(message)

    def descriptor(self) -> AgentDescriptor:
        """Return the shareable public descriptor as a validated Pydantic model."""
        return AgentDescriptor.model_validate(json.loads(self._native.descriptor_json()))

    def __repr__(self) -> str:
        return f"AgentIdentity(agent_id={self.agent_id!r}, name={self.display_name!r})"


def verify_signature(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    """Verify an Ed25519 signature (hex) over `message` against a public key (hex)."""
    return bool(_native.verify_signature(public_key_hex, message, signature_hex))
