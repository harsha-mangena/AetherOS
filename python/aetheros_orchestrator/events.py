"""AetherOS real-time event bus — Phase 25.

Provides a lightweight pub/sub mechanism for Server-Sent Events (SSE) streaming.
The EventBus holds a set of subscriber asyncio.Queues; RunService emits snapshots
on each state change; the SSE endpoint diffs consecutive snapshots to yield events.

Standards:
    W3C Server-Sent Events (W3C Recommendation 2015): text/event-stream format,
    event/data/id fields, Last-Event-ID reconnection header.
    CloudEvents v1.0.2 (CNCF 2022): structured event schema with specversion,
    id, source, type, time, data fields.
    OTEL Semantic Conventions v1.25.0: event naming convention aetheros.run.{action}.
"""
from __future__ import annotations

import asyncio
import json
import threading
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

# ──────────────────────────────────────────────────────────────────────────────
# Event schema (CloudEvents v1.0.2 aligned)
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class RunEvent:
    """A single governance engine event (CloudEvents v1.0.2 aligned).

    Fields:
        specversion:  Always "1.0" (CloudEvents spec).
        id:           UUID4 uniquely identifying this event instance.
        source:       Always "/aetheros/run-service" — the origin component.
        type:         aetheros.run.created | aetheros.run.step_completed |
                      aetheros.run.halted | aetheros.run.completed |
                      aetheros.run.approval_required | aetheros.heartbeat
        time:         ISO-8601 UTC timestamp.
        data:         Arbitrary dict payload (run summary fields).
    """

    type: str
    data: dict[str, Any]
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    specversion: str = "1.0"
    source: str = "/aetheros/run-service"
    time: str = field(
        default_factory=lambda: datetime.now(timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )

    def to_sse_data(self) -> str:
        """Serialize to JSON for the SSE data field."""
        return json.dumps(asdict(self))


# ──────────────────────────────────────────────────────────────────────────────
# Event bus (pub/sub over asyncio.Queue)
# ──────────────────────────────────────────────────────────────────────────────


class EventBus:
    """Thread-safe pub/sub event bus for SSE subscribers.

    Each SSE connection subscribes with subscribe() which returns an asyncio.Queue.
    publish() puts events on all active queues. unsubscribe() removes the queue
    on connection close.

    This is intentionally simple — no persistence, no replay, no back-pressure
    beyond asyncio.Queue's maxsize. For production scale, replace with Redis
    pub/sub or a Kafka consumer group.
    """

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self._lock = threading.Lock()

    def subscribe(self, maxsize: int = 100) -> asyncio.Queue:
        """Register a new SSE subscriber. Returns the queue to read events from."""
        q: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        with self._lock:
            self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        """Deregister a subscriber (called on connection close)."""
        with self._lock:
            self._subscribers.discard(q)

    def publish(self, event: RunEvent) -> None:
        """Publish an event to all active subscribers (non-blocking, drops if full)."""
        with self._lock:
            subscribers = list(self._subscribers)
        for q in subscribers:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass  # slow consumer — drop rather than block

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)


# ──────────────────────────────────────────────────────────────────────────────
# Snapshot differ
# ──────────────────────────────────────────────────────────────────────────────


def diff_snapshots(
    previous: dict[str, dict],
    current: dict[str, dict],
) -> list[RunEvent]:
    """Diff two run snapshots and return the events that describe the delta.

    Parameters
    ----------
    previous:
        Dict mapping run_id → run summary dict from the previous poll.
    current:
        Dict mapping run_id → run summary dict from the current poll.

    Returns a list of RunEvents (possibly empty if nothing changed).
    """
    events: list[RunEvent] = []

    # New runs.
    for run_id, run in current.items():
        if run_id not in previous:
            events.append(RunEvent(type="aetheros.run.created", data=run))

    # Status changes on existing runs.
    for run_id, run in current.items():
        if run_id in previous:
            old = previous[run_id]
            if run.get("status") != old.get("status"):
                status = run.get("status", "unknown")
                if status == "completed":
                    event_type = "aetheros.run.completed"
                elif status == "halted":
                    event_type = "aetheros.run.halted"
                elif status == "awaiting_approval":
                    event_type = "aetheros.run.approval_required"
                else:
                    event_type = "aetheros.run.step_completed"
                events.append(RunEvent(type=event_type, data=run))
            elif run.get("cursor") != old.get("cursor"):
                events.append(
                    RunEvent(type="aetheros.run.step_completed", data=run)
                )

    # Removed runs (deleted).
    for run_id in previous:
        if run_id not in current:
            events.append(
                RunEvent(type="aetheros.run.deleted", data={"run_id": run_id})
            )

    return events


# ──────────────────────────────────────────────────────────────────────────────
# Global event bus instance (one per process)
# ──────────────────────────────────────────────────────────────────────────────

_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    """Return the process-level singleton EventBus, creating it if needed."""
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus


def reset_event_bus() -> None:
    """Reset the singleton (for test isolation)."""
    global _bus
    _bus = None
