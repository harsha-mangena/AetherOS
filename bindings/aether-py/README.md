# AetherOS Core (Python bindings)

Python bindings and Pydantic models for the AetherOS Rust core primitives:
cryptographic agent identity, scoped capability leases, and the tamper-evident
evidence ledger.

The heavy lifting (Ed25519 signing, SHA-256 hash chaining, canonical serialization)
happens in Rust via `aether-core` and is exposed through a PyO3 extension module
(`aetheros._aether_native`). The pure-Python layer adds ergonomic Pydantic models
and typed wrappers.

## Build (development)

```bash
maturin develop --release
```

## Usage

```python
from aetheros import AgentIdentity, EvidenceLedger

control_plane = AgentIdentity.generate("control-plane")
ledger = EvidenceLedger()
ledger.append("control-plane", "lease.issued", {"scope": "s3:read"})
assert ledger.verify()
```
