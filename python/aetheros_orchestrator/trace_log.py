"""Structured log-trace correlation for AetherOS — Phase 21.

Injects active OpenTelemetry span context (trace_id, span_id, trace_flags) into
every Python LogRecord so that structured log aggregators (Datadog, Elastic, Splunk,
Loki) can correlate a log line to its distributed trace without any manual plumbing.

Standards / specification references
──────────────────────────────────────
* RFC 5424 (BSD Syslog, IETF 2009): §6.3 — Structured Data elements carry
  key=value pairs inside log messages, enabling machine-parseable context
  injection. The trace_id / span_id fields mirror that design philosophy.
* OTEL Logs Bridge API Spec v1.27.0 (CNCF 2024): §4.2 — LogRecord.trace_id
  (16-byte / 128-bit), LogRecord.span_id (8-byte / 64-bit), and
  LogRecord.trace_flags (TraceFlags) are the canonical correlation fields.
* W3C Trace-Context spec (W3C Recommendation 2021): §2.2.4 — trace-id is
  represented as 32 lowercase hex characters (128-bit). §2.2.5 — parent-id
  (span_id) is 16 lowercase hex characters (64-bit).
* CNCF OTEL Best Practices 2023: structured log correlation should attach
  trace context as discrete log record attributes, not as free-form text, so
  that downstream systems can index and query them efficiently.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

# ── OTEL imports (graceful no-op when SDK not installed) ──────────────────────
try:
    from opentelemetry import trace as _otel_trace
    _OTEL_AVAILABLE = True
except ImportError:
    _OTEL_AVAILABLE = False


# ── OtelLoggingFilter ─────────────────────────────────────────────────────────

class OtelLoggingFilter(logging.Filter):
    """A logging.Filter that injects the active OTEL span context into LogRecords.

    When an active span exists, injects three attributes into every LogRecord:
      - trace_id:    32-character lowercase hex string (W3C 128-bit trace-id)
      - span_id:     16-character lowercase hex string (W3C 64-bit span/parent-id)
      - trace_flags: int (OTEL TraceFlags — 0 = not sampled, 1 = sampled)

    When no span is active (INVALID_SPAN_CONTEXT, trace_id == 0), the filter
    adds trace_id and span_id as empty strings and trace_flags as 0.

    Always returns True — this filter never drops log records.

    Design note: using a Filter (not a Handler) ensures the enrichment is
    handler-agnostic; any handler attached to the logger (console, file, Loki,
    Datadog agent) automatically sees the correlation fields.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if _OTEL_AVAILABLE:
            try:
                span = _otel_trace.get_current_span()
                ctx = span.get_span_context()
                if ctx is not None and ctx.trace_id != 0:
                    # W3C format: 32 lowercase hex chars for trace_id
                    record.trace_id = format(ctx.trace_id, "032x")
                    # W3C format: 16 lowercase hex chars for span_id
                    record.span_id = format(ctx.span_id, "016x")
                    record.trace_flags = int(ctx.trace_flags)
                else:
                    record.trace_id = ""
                    record.span_id = ""
                    record.trace_flags = 0
            except Exception:
                record.trace_id = ""
                record.span_id = ""
                record.trace_flags = 0
        else:
            record.trace_id = ""
            record.span_id = ""
            record.trace_flags = 0
        return True


# ── install_log_filter ────────────────────────────────────────────────────────

def install_log_filter(logger_name: str = "aetheros_orchestrator") -> None:
    """Add an OtelLoggingFilter to the named logger if one is not already present.

    Idempotent: calling this function multiple times has the same effect as
    calling it once. The function checks whether any existing filter on the
    logger is an instance of OtelLoggingFilter before adding a new one.

    Intended to be called from tracing.configure() and tracing.configure_for_test()
    so that every log line emitted during a traced run automatically carries
    trace_id and span_id for downstream correlation.

    Parameters
    ----------
    logger_name:
        The name of the Python logger to attach the filter to.
        Defaults to "aetheros_orchestrator" (the package root logger).
    """
    logger = logging.getLogger(logger_name)
    # Idempotency: skip if an OtelLoggingFilter is already installed.
    for existing in logger.filters:
        if isinstance(existing, OtelLoggingFilter):
            return
    logger.addFilter(OtelLoggingFilter())


# ── get_trace_context ─────────────────────────────────────────────────────────

def get_trace_context() -> dict[str, str]:
    """Return the active OTEL span's trace_id and span_id as a dict.

    Returns
    -------
    dict with keys "trace_id" and "span_id":
      - "trace_id": 32-char lowercase hex string when a span is active, else "".
      - "span_id":  16-char lowercase hex string when a span is active, else "".

    This function is used to inject trace context into ledger entry payloads so
    that audit trails can be correlated to distributed traces without requiring
    the trace exporter to be consulted at query time.
    """
    if not _OTEL_AVAILABLE:
        return {"trace_id": "", "span_id": ""}
    try:
        span = _otel_trace.get_current_span()
        ctx = span.get_span_context()
        if ctx is not None and ctx.trace_id != 0:
            return {
                "trace_id": format(ctx.trace_id, "032x"),
                "span_id": format(ctx.span_id, "016x"),
            }
    except Exception:
        pass
    return {"trace_id": "", "span_id": ""}
