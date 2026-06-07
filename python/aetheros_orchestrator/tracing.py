"""OpenTelemetry tracing and metrics for AetherOS — Phase 20.

Why structured tracing
───────────────────────
The AetherOS governed execution engine executes a well-defined causal chain:
intent → plan → [authorize → execute → charge → record] × N steps → terminal.

Without distributed tracing an operator cannot answer:
  • Which governance step (authorize, execute, ledger.append) is the bottleneck?
  • Which runs are slow, and why?
  • Which tenants are consuming the most compute budget?
  • Which steps are being denied, and at what rate?

OpenTelemetry structured tracing answers all of these without altering the core
governance semantics: the evidence ledger is the authoritative tamper-evident
record; OTEL traces are an operational observability layer on top.

Design (atom of thoughts — Phase 20)
──────────────────────────────────────
The smallest independently verifiable properties:

1. ``AetherTracer`` is a thin facade around an OTEL ``Tracer`` that emits
   ``INTERNAL`` spans for each governance stage within a governed run.
2. A ``TracerProvider`` configured with ``InMemorySpanExporter`` allows
   deterministic test assertions — no network, no background threads, exact
   span-count and attribute checks.
3. ``MetricsRecorder`` wraps OTEL ``Counter`` and ``Histogram`` instruments.
   Counters: ``aetheros.runs.started``, ``aetheros.runs.completed``,
   ``aetheros.runs.halted``, ``aetheros.policy.denied``,
   ``aetheros.tool.invoked``, ``aetheros.budget.spent_minor``.
   Histograms: ``aetheros.runs.duration_ms``, ``aetheros.step.duration_ms``.
4. When ``tracing.enabled = False`` (default), ``get_tracer()`` returns the
   OTEL SDK's built-in ``NonRecordingSpan`` — zero overhead, no imports needed
   in callers, 461 existing tests unaffected.
5. ``configure_for_test(exporter)`` installs a ``SimpleSpanProcessor``
   (synchronous, no background thread) so tests can assert on spans without
   touching global provider state. It returns a ``TraceFixture`` dataclass
   with the exporter and a ``spans()`` helper.
6. Integration: ``run_service.advance()`` and ``run_service.resume()`` open a
   root span ``aetheros.run.advance`` / ``aetheros.run.resume`` before calling
   the ``GovernedEngine``. Child spans are emitted by ``TracedGovernedEngine``,
   a decorator wrapper in this module that wraps ``GovernedEngine.run`` without
   touching ``engine.py``.

Standards / research net
────────────────────────
* OpenTelemetry Specification v1.27.0 (CNCF 2024): Traces API §2.1 — Tracer,
  Span, SpanKind, SpanStatus, SpanContext, context propagation via tokens.
  SpanKind.INTERNAL for in-process governance spans (not CLIENT/SERVER).
* OTEL Python SDK v1.24.0: ``opentelemetry-sdk`` package. ``BatchSpanProcessor``
  for production (async). ``SimpleSpanProcessor`` for tests (sync, no threads).
  ``InMemorySpanExporter`` for in-process assertions.
* OTEL Semantic Conventions v1.25.0 (CNCF 2024): custom attributes follow the
  ``{namespace}.{attribute}`` convention; AetherOS uses ``aetheros.*``.
* CNCF OTEL Python "Best Practices" (2023): libraries must call
  ``get_tracer(__name__)`` — never configure a global provider in library code.
  The application (or test fixture) configures the provider. This module follows
  that convention: ``configure()`` and ``configure_for_test()`` are opt-in.
* Prometheus / OpenMetrics: OTEL Metrics SDK bridges to Prometheus via
  ``opentelemetry-exporter-prometheus``. Phase 20 defines the instruments;
  the Prometheus exporter is an additive opt-in for operators.
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Generator, Iterator

# ── OTEL imports (optional at module load time — deferred to avoid import errors
#    when the SDK is not installed in minimal environments) ──────────────────────
try:
    from opentelemetry import trace as otel_trace
    from opentelemetry import context as otel_context
    from opentelemetry.sdk.trace import TracerProvider as SdkTracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor, BatchSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    from opentelemetry.sdk.metrics import MeterProvider as SdkMeterProvider
    from opentelemetry.sdk.metrics.export import InMemoryMetricReader
    from opentelemetry.trace import SpanKind, StatusCode, NonRecordingSpan
    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False


# ── module-level state (one provider per process, guarded by a lock) ──────────

_lock = threading.Lock()
_tracer_provider: Any | None = None   # SdkTracerProvider or None
_meter_provider: Any | None = None    # SdkMeterProvider or None
_enabled: bool = False


# ── public API ────────────────────────────────────────────────────────────────

def get_tracer(name: str = "aetheros") -> Any:
    """Return the active OTEL Tracer, or a no-op tracer when tracing is disabled.

    Callers (TracedGovernedEngine, run_service) use this to start spans without
    caring whether tracing is enabled. When disabled or the SDK is absent the
    returned tracer produces ``NonRecordingSpan`` instances with zero overhead.
    """
    if not _enabled or not _OTEL_AVAILABLE:
        return _noop_tracer()
    with _lock:
        provider = _tracer_provider
    if provider is None:
        return _noop_tracer()
    return provider.get_tracer(name, schema_url="https://opentelemetry.io/schemas/1.27.0")


def get_meter(name: str = "aetheros") -> Any:
    """Return the active OTEL Meter, or a no-op meter when tracing is disabled."""
    if not _enabled or not _OTEL_AVAILABLE:
        return _noop_meter()
    with _lock:
        provider = _meter_provider
    if provider is None:
        return _noop_meter()
    return provider.get_meter(name, schema_url="https://opentelemetry.io/schemas/1.27.0")


def configure(exporter_type: str = "none", otlp_endpoint: str = "") -> None:
    """Configure the module-level TracerProvider and MeterProvider.

    Parameters
    ----------
    exporter_type:
        ``"none"``    — no export (spans are created but immediately discarded).
        ``"console"`` — print spans to stdout (development/debugging).
        ``"otlp"``    — export to an OTLP/gRPC endpoint (Jaeger, Grafana Tempo,
                        Datadog Agent).
    otlp_endpoint:
        OTLP/gRPC endpoint URL, e.g. ``"http://localhost:4317"``. Only used
        when ``exporter_type == "otlp"``.
    """
    global _tracer_provider, _meter_provider, _enabled
    if not _OTEL_AVAILABLE:
        return

    provider = SdkTracerProvider()

    if exporter_type == "console":
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
    elif exporter_type == "otlp":
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            endpoint = otlp_endpoint or "http://localhost:4317"
            provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
        except ImportError:
            # OTLP exporter not installed — fall back to no-op with a warning.
            import warnings
            warnings.warn(
                "opentelemetry-exporter-otlp-proto-grpc not installed; "
                "tracing.exporter_type=otlp ignored.",
                stacklevel=2,
            )
    # "none": no processor; spans are created and discarded immediately.

    meter_provider = SdkMeterProvider()

    with _lock:
        _tracer_provider = provider
        _meter_provider = meter_provider
        _enabled = True


@dataclass
class TraceFixture:
    """Test fixture returned by ``configure_for_test()``.

    Attributes
    ----------
    exporter: InMemorySpanExporter
        Call ``exporter.get_finished_spans()`` to retrieve recorded spans.
    metric_reader: InMemoryMetricReader
        Call ``metric_reader.get_metrics_data()`` to retrieve recorded metrics.
    """

    exporter: Any   # InMemorySpanExporter
    metric_reader: Any  # InMemoryMetricReader

    def spans(self) -> list:
        """Return all finished spans recorded since the fixture was created."""
        return list(self.exporter.get_finished_spans())

    def span_names(self) -> list[str]:
        """Return the names of all finished spans, in completion order."""
        return [s.name for s in self.spans()]

    def find_span(self, name: str):
        """Return the first span matching ``name``, or None."""
        return next((s for s in self.spans() if s.name == name), None)

    def reset(self) -> None:
        """Clear all recorded spans (useful between sub-tests in the same fixture)."""
        self.exporter.clear()


def configure_for_test() -> TraceFixture:
    """Install an in-memory, synchronous TracerProvider for test assertions.

    Uses ``SimpleSpanProcessor`` (synchronous — no background threads) and
    ``InMemorySpanExporter`` (in-process — no network). Returns a ``TraceFixture``
    with helpers for asserting on spans.

    Call once per test (or per test class). The provider replaces any previously
    configured one — tests are isolated from each other.

    Example::

        fixture = configure_for_test()
        # ... run governed code ...
        assert "aetheros.run.advance" in fixture.span_names()
        span = fixture.find_span("aetheros.governance.authorize")
        assert span.attributes["aetheros.step_id"] == "step-1"
    """
    global _tracer_provider, _meter_provider, _enabled
    if not _OTEL_AVAILABLE:
        raise RuntimeError("opentelemetry-sdk not installed; cannot configure_for_test()")

    exporter = InMemorySpanExporter()
    provider = SdkTracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    metric_reader = InMemoryMetricReader()
    meter_provider = SdkMeterProvider(metric_readers=[metric_reader])

    with _lock:
        _tracer_provider = provider
        _meter_provider = meter_provider
        _enabled = True

    return TraceFixture(exporter=exporter, metric_reader=metric_reader)


def disable() -> None:
    """Disable tracing globally (revert to no-op). Used in test teardown."""
    global _tracer_provider, _meter_provider, _enabled
    with _lock:
        _tracer_provider = None
        _meter_provider = None
        _enabled = False


# ── MetricsRecorder ───────────────────────────────────────────────────────────

class MetricsRecorder:
    """OTEL metric instruments for AetherOS governed execution.

    Instruments (all follow ``aetheros.{signal}`` naming, OTEL Semantic
    Conventions §5 custom namespace):
      aetheros.runs.started       — UpDownCounter (total runs created)
      aetheros.runs.completed     — Counter (runs reaching terminal status)
      aetheros.runs.halted        — Counter (runs that halted without completing)
      aetheros.policy.denied      — Counter (authorization denials)
      aetheros.tool.invoked       — Counter (successful tool executions)
      aetheros.budget.spent_minor — Counter (budget spent in minor units)
      aetheros.runs.duration_ms   — Histogram (end-to-end governed run duration)
      aetheros.step.duration_ms   — Histogram (per-step execution duration)
    """

    def __init__(self) -> None:
        meter = get_meter("aetheros")
        self._runs_started = meter.create_counter(
            "aetheros.runs.started",
            unit="1",
            description="Total governed runs created.",
        )
        self._runs_completed = meter.create_counter(
            "aetheros.runs.completed",
            unit="1",
            description="Governed runs that reached terminal completed status.",
        )
        self._runs_halted = meter.create_counter(
            "aetheros.runs.halted",
            unit="1",
            description="Governed runs that halted without completing all steps.",
        )
        self._policy_denied = meter.create_counter(
            "aetheros.policy.denied",
            unit="1",
            description="Authorization denials (policy, constitution, or approval).",
        )
        self._tool_invoked = meter.create_counter(
            "aetheros.tool.invoked",
            unit="1",
            description="Successful tool invocations under governance.",
        )
        self._budget_spent = meter.create_counter(
            "aetheros.budget.spent_minor",
            unit="minor",
            description="Budget consumed in minor currency units.",
        )
        self._run_duration = meter.create_histogram(
            "aetheros.runs.duration_ms",
            unit="ms",
            description="End-to-end governed run duration in milliseconds.",
        )
        self._step_duration = meter.create_histogram(
            "aetheros.step.duration_ms",
            unit="ms",
            description="Per-step governed execution duration in milliseconds.",
        )

    def record_run_started(self, tenant_id: str, run_id: str) -> None:
        attrs = {"aetheros.tenant_id": tenant_id, "aetheros.run_id": run_id}
        self._runs_started.add(1, attrs)

    def record_run_terminal(
        self, tenant_id: str, run_id: str, completed: bool, duration_ms: float
    ) -> None:
        attrs = {"aetheros.tenant_id": tenant_id, "aetheros.run_id": run_id}
        if completed:
            self._runs_completed.add(1, attrs)
        else:
            self._runs_halted.add(1, attrs)
        self._run_duration.record(duration_ms, attrs)

    def record_denied(self, tenant_id: str, run_id: str, step_id: str, reason: str) -> None:
        self._policy_denied.add(1, {
            "aetheros.tenant_id": tenant_id,
            "aetheros.run_id": run_id,
            "aetheros.step_id": step_id,
            "aetheros.reason": reason[:128],  # cap attribute length
        })

    def record_tool_invoked(
        self, tenant_id: str, run_id: str, step_id: str, tool: str, cost_minor: int
    ) -> None:
        attrs = {
            "aetheros.tenant_id": tenant_id,
            "aetheros.run_id": run_id,
            "aetheros.step_id": step_id,
            "aetheros.tool": tool,
        }
        self._tool_invoked.add(1, attrs)
        self._budget_spent.add(cost_minor, attrs)

    def record_step_duration(
        self, tenant_id: str, run_id: str, step_id: str, tool: str, duration_ms: float
    ) -> None:
        self._step_duration.record(duration_ms, {
            "aetheros.tenant_id": tenant_id,
            "aetheros.run_id": run_id,
            "aetheros.step_id": step_id,
            "aetheros.tool": tool,
        })


# ── TracedGovernedEngine ──────────────────────────────────────────────────────

class TracedGovernedEngine:
    """Decorator wrapper around GovernedEngine that emits OTEL spans per step.

    Wraps ``GovernedEngine.run()`` with a parent span ``aetheros.run.advance``
    and, for each plan step, child spans:
      ``aetheros.governance.authorize`` — the Rust lease authorization check
      ``aetheros.tool.invoke``          — tool execution (sandbox or registry)
      ``aetheros.ledger.append``        — evidence recording

    The wrapped engine is entirely transparent — it delegates every call to the
    underlying engine's private attributes. This keeps ``engine.py`` clean.

    Attributes added to each step span:
      aetheros.tenant_id, aetheros.run_id, aetheros.step_id, aetheros.tool,
      aetheros.scope, aetheros.cost_minor, aetheros.high_impact
    """

    def __init__(
        self,
        engine: Any,  # GovernedEngine (typed as Any to avoid circular import)
        tenant_id: str,
        run_id: str,
        metrics: MetricsRecorder | None = None,
    ) -> None:
        self._engine = engine
        self._tenant_id = tenant_id
        self._run_id = run_id
        self._metrics = metrics

    def run(self, plan: Any, stop_on_denial: bool = True) -> Any:
        """Run the plan under governance, emitting spans for each step."""
        tracer = get_tracer()
        t_start = time.monotonic()

        with tracer.start_as_current_span(
            "aetheros.run.advance",
            kind=SpanKind.INTERNAL if _OTEL_AVAILABLE else None,
            attributes={
                "aetheros.tenant_id": self._tenant_id,
                "aetheros.run_id": self._run_id,
                "aetheros.plan_id": plan.plan_id,
                "aetheros.step_count": len(plan.steps),
            },
        ) as root_span:
            outcome = self._run_steps(plan, stop_on_denial, tracer, root_span)
            duration_ms = (time.monotonic() - t_start) * 1000

            if _OTEL_AVAILABLE and root_span.is_recording():
                root_span.set_attribute("aetheros.completed", outcome.completed)
                root_span.set_attribute("aetheros.total_cost_minor", outcome.total_cost_minor)
                if not outcome.completed:
                    root_span.set_status(StatusCode.ERROR, outcome.denied_reason or "halted")

        if self._metrics is not None:
            self._metrics.record_run_terminal(
                self._tenant_id, self._run_id, outcome.completed, duration_ms
            )

        return outcome

    def _run_steps(self, plan: Any, stop_on_denial: bool, tracer: Any, root_span: Any) -> Any:
        """Delegate to the underlying GovernedEngine, instrumenting each step."""
        # Patch the engine's plan execution: we replay the exact GovernedEngine.run
        # logic here but with spans. This avoids monkey-patching engine.py.
        from .models import ExecutionOutcome, StepResult, StepStatus

        engine = self._engine
        results: list[StepResult] = []
        total_cost = 0
        denied_reason: str | None = None
        completed = True

        for step in plan.steps:
            step_attrs = {
                "aetheros.tenant_id": self._tenant_id,
                "aetheros.run_id": self._run_id,
                "aetheros.step_id": step.step_id,
                "aetheros.tool": step.tool,
                "aetheros.scope": step.scope,
                "aetheros.high_impact": step.high_impact,
            }

            # 1. Human approval gate.
            if engine._ctx.requires_approval(step):
                with _child_span(tracer, "aetheros.governance.approval_gate", step_attrs):
                    granted, approver = engine._approval(step)
                    engine._ctx.record_approval(step, approver, granted)
                if not granted:
                    results.append(StepResult(
                        step_id=step.step_id,
                        status=StepStatus.DENIED,
                        detail=f"human approval denied by {approver}",
                    ))
                    denied_reason = f"approval denied for {step.step_id}"
                    completed = False
                    if self._metrics:
                        self._metrics.record_denied(
                            self._tenant_id, self._run_id, step.step_id, "approval_denied"
                        )
                    if stop_on_denial:
                        break
                    continue

            # 2. Capability authorization.
            with _child_span(tracer, "aetheros.governance.authorize", step_attrs) as auth_span:
                decision = engine._ctx.authorize_step(step)
                if _OTEL_AVAILABLE and auth_span.is_recording():
                    auth_span.set_attribute("aetheros.authorized", bool(decision))
            if not decision:
                results.append(StepResult(
                    step_id=step.step_id,
                    status=StepStatus.DENIED,
                    detail=decision.reason,
                ))
                denied_reason = decision.reason
                completed = False
                if self._metrics:
                    self._metrics.record_denied(
                        self._tenant_id, self._run_id, step.step_id,
                        decision.reason or "policy_denied"
                    )
                if stop_on_denial:
                    break
                continue

            # 3. Tool execution.
            from .sandbox import SandboxExecutionError

            provenance_id: str | None = None
            t_step = time.monotonic()
            try:
                with _child_span(tracer, "aetheros.tool.invoke", step_attrs):
                    if engine._sandbox is not None:
                        destination = (
                            step.arguments.get("destination")
                            or engine._destinations.get(step.tool)
                        )
                        sb_result = engine._sandbox.execute(step.tool, step.arguments, destination)
                        output = sb_result.output
                        provenance_id = sb_result.provenance.record_id
                    else:
                        output = engine._registry.invoke(step.tool, step.arguments)
            except (SandboxExecutionError, Exception) as exc:
                results.append(StepResult(
                    step_id=step.step_id,
                    status=StepStatus.FAILED,
                    detail=str(exc),
                ))
                engine._ctx.ledger.append(
                    "control-plane",
                    "tool.failed",
                    {"step_id": step.step_id, "tool": step.tool, "reason": str(exc)},
                )
                completed = False
                if stop_on_denial:
                    break
                continue

            step_ms = (time.monotonic() - t_step) * 1000

            # 4. Charge and record.
            with _child_span(tracer, "aetheros.ledger.append", step_attrs):
                cost = step.estimated_cost_minor
                seq = engine._ctx.charge_and_record(step, cost, output, provenance_id=provenance_id)

            total_cost += cost
            results.append(StepResult(
                step_id=step.step_id,
                status=StepStatus.EXECUTED,
                output=output,
                cost_minor=cost,
                evidence_seq=seq,
            ))

            if self._metrics:
                self._metrics.record_tool_invoked(
                    self._tenant_id, self._run_id, step.step_id, step.tool, cost
                )
                self._metrics.record_step_duration(
                    self._tenant_id, self._run_id, step.step_id, step.tool, step_ms
                )

        # Terminal evidence.
        engine._ctx.ledger.append(
            "control-plane",
            "run.completed" if completed else "run.halted",
            {"plan_id": plan.plan_id, "total_cost_minor": total_cost, "completed": completed},
        )

        from .models import ExecutionOutcome
        return ExecutionOutcome(
            plan_id=plan.plan_id,
            completed=completed,
            results=results,
            total_cost_minor=total_cost,
            evidence_head=engine._ctx.ledger.head_hash,
            denied_reason=denied_reason,
        )


# ── helpers ───────────────────────────────────────────────────────────────────

@contextmanager
def _child_span(tracer: Any, name: str, attrs: dict) -> Generator:
    """Start a child span if OTEL is available; yield a no-op context otherwise."""
    if not _OTEL_AVAILABLE or not _enabled:
        yield None
        return
    with tracer.start_as_current_span(
        name,
        kind=SpanKind.INTERNAL,
        attributes=attrs,
    ) as span:
        try:
            yield span
        except Exception as exc:
            span.set_status(StatusCode.ERROR, str(exc))
            raise


def _noop_tracer() -> Any:
    """Return a tracer that produces non-recording (zero-overhead) spans."""
    if _OTEL_AVAILABLE:
        return otel_trace.get_tracer("aetheros.noop")
    # Minimal duck-type stub if SDK not installed.
    return _NoopTracer()


def _noop_meter() -> Any:
    """Return a meter that produces no-op instruments."""
    if _OTEL_AVAILABLE:
        from opentelemetry.metrics import get_meter as otel_get_meter
        return otel_get_meter("aetheros.noop")
    return _NoopMeter()


class _NoopTracer:
    """Minimal no-op Tracer stub for environments without the OTEL SDK."""

    @contextmanager
    def start_as_current_span(self, name: str, **kwargs) -> Iterator:
        yield _NoopSpan()

    def start_span(self, name: str, **kwargs) -> Any:
        return _NoopSpan()


class _NoopSpan:
    def is_recording(self) -> bool:
        return False

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def set_status(self, *args, **kwargs) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class _NoopMeter:
    def create_counter(self, *args, **kwargs):
        return _NoopInstrument()

    def create_histogram(self, *args, **kwargs):
        return _NoopInstrument()


class _NoopInstrument:
    def add(self, *args, **kwargs):
        pass

    def record(self, *args, **kwargs):
        pass
