# Makefile for AetherOS hybrid development.
#
# Assumes a Python virtualenv at .venv and a Rust toolchain on PATH
# (source $HOME/.cargo/env if cargo is not found).

VENV := .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/uv pip
MATURIN := $(VENV)/bin/maturin

.PHONY: setup venv deps build test test-rust test-py fmt fmt-check lint spec check-spec clean

## Full setup: venv, dependencies, native extension.
setup: venv deps build

venv:
	uv venv --python python3.12 $(VENV)

deps:
	$(PIP) install maturin \
		"pydantic>=2.7,<3" pyyaml "pytest>=8" \
		"langgraph>=0.2" "mcp>=1.0" \
		"fastapi>=0.110" "uvicorn>=0.27" "httpx>=0.27" \
		"cryptography>=42" "PyJWT>=2.8" \
		"opentelemetry-sdk>=1.24" "opentelemetry-exporter-prometheus>=0.45b0" \
		"prometheus_client>=0.20"
	cd bindings/aether-py && ../../$(MATURIN) develop --release
	$(PIP) install -e python/ --no-deps

## Build the Rust core and the PyO3 extension (into the venv).
build:
	cargo build -p aether-core
	cd bindings/aether-py && ../../$(MATURIN) develop --release

## Run all tests (Rust core + Python).
test: test-rust test-py

test-rust:
	cargo test -p aether-core

test-py:
	$(PY) -m pytest python/tests/ bindings/aether-py/tests/ -q

## Formatting and linting.
fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

lint:
	cargo clippy -p aether-core -- -D warnings

## OpenAPI spec generation and drift check.
spec:
	$(PY) scripts/generate_openapi.py

check-spec:
	$(PY) scripts/generate_openapi.py --check

clean:
	cargo clean
	rm -rf $(VENV)
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
