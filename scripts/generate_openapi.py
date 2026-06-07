#!/usr/bin/env python
"""Generate or verify the committed OpenAPI schema for AetherOS.

Usage:
    python scripts/generate_openapi.py           # regenerate docs/openapi.json
    python scripts/generate_openapi.py --check   # fail if docs/openapi.json is stale

Standards:
    OpenAPI Specification v3.1.0 (OAI 2023) — machine-readable REST API contract.
    FastAPI auto-generates OpenAPI 3.1 JSON via app.openapi(). The committed spec
    is the source of truth for all API consumers and SDK generators.

    Semantic Versioning 2.0.0 (semver.org): API version 1.0.0 after 23 phases of
    stable, backward-compatible additions.
"""
import argparse
import json
import sys
from pathlib import Path

# Ensure the package is importable from the repo root.
repo_root = Path(__file__).parent.parent
sys.path.insert(0, str(repo_root / "python"))

from aetheros_orchestrator.api import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate or check the AetherOS OpenAPI spec.")
    parser.add_argument("--check", action="store_true", help="Fail if the committed spec is stale.")
    args = parser.parse_args()

    app = create_app()
    schema = app.openapi()
    generated = json.dumps(schema, indent=2, sort_keys=True)

    out_path = repo_root / "docs" / "openapi.json"

    if args.check:
        if not out_path.exists():
            print(f"ERROR: {out_path} does not exist. Run: python scripts/generate_openapi.py", file=sys.stderr)
            sys.exit(1)
        committed = json.dumps(json.loads(out_path.read_text()), indent=2, sort_keys=True)
        if generated != committed:
            print(
                f"ERROR: docs/openapi.json is stale.\n"
                f"Run: python scripts/generate_openapi.py\n"
                f"Then commit the updated file.",
                file=sys.stderr,
            )
            sys.exit(1)
        print("OK: docs/openapi.json matches the live app schema.")
    else:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(generated + "\n")
        print(f"Written: {out_path}")


if __name__ == "__main__":
    main()
