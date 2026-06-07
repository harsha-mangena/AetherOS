"""Config-driven design for AetherOS (zero-hardcoding principle).

All tunable behavior is loaded from `config/default.yaml`, validated by Pydantic
models, and overridable via environment variables prefixed `AETHER__` with double
underscores marking nesting (e.g. `AETHER__GOVERNANCE__DEFAULT_BUDGET_MINOR=50000`).
Code reads typed config objects rather than embedding constants.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

ENV_PREFIX = "AETHER__"


class CoreConfig(BaseModel):
    default_currency: str = "USD"
    ledger_hash: str = "sha256"


class IdentityConfig(BaseModel):
    timezone: str = "UTC"


class GovernanceConfig(BaseModel):
    default_lease_ttl_seconds: int = 3600
    default_budget_minor: int = 10_000
    require_human_approval: bool = True
    high_impact_scopes: list[str] = Field(default_factory=list)


class MemoryConfig(BaseModel):
    ephemeral_max_entries: int = 200
    durable_namespace: str = "org"


class EvidenceConfig(BaseModel):
    ledger_path: str = "data/evidence.ledger"


class OrchestrationConfig(BaseModel):
    max_plan_steps: int = 25
    default_model: str = "configured-by-runtime"


class AetherConfig(BaseModel):
    """Top-level validated configuration for AetherOS."""

    core: CoreConfig = Field(default_factory=CoreConfig)
    identity: IdentityConfig = Field(default_factory=IdentityConfig)
    governance: GovernanceConfig = Field(default_factory=GovernanceConfig)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)
    orchestration: OrchestrationConfig = Field(default_factory=OrchestrationConfig)


def _default_config_path() -> Path:
    """Locate `config/default.yaml` by walking up from this file."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "config" / "default.yaml"
        if candidate.exists():
            return candidate
    raise FileNotFoundError("config/default.yaml not found in any parent directory")


def _coerce(value: str) -> Any:
    """Coerce an environment string into bool/int/float/str."""
    low = value.lower()
    if low in ("true", "false"):
        return low == "true"
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def _apply_env_overrides(data: dict[str, Any]) -> dict[str, Any]:
    """Apply AETHER__SECTION__KEY environment overrides onto a config dict."""
    for env_key, env_val in os.environ.items():
        if not env_key.startswith(ENV_PREFIX):
            continue
        path = env_key[len(ENV_PREFIX) :].lower().split("__")
        cursor = data
        for part in path[:-1]:
            cursor = cursor.setdefault(part, {})
            if not isinstance(cursor, dict):
                break
        else:
            cursor[path[-1]] = _coerce(env_val)
    return data


def load_config(path: str | Path | None = None) -> AetherConfig:
    """Load and validate AetherOS configuration.

    Reads `config/default.yaml` (or `path`), applies environment overrides, and
    returns a validated `AetherConfig`.
    """
    config_path = Path(path) if path else _default_config_path()
    with open(config_path, "r", encoding="utf-8") as fh:
        data: dict[str, Any] = yaml.safe_load(fh) or {}
    data = _apply_env_overrides(data)
    return AetherConfig.model_validate(data)
