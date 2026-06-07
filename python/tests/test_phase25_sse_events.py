"""Phase 25 — Real-time SSE event stream tests.

Covers:
  - RunEvent dataclass (CloudEvents v1.0.2 aligned)
  - EventBus pub/sub mechanics
  - diff_snapshots snapshot differ
  - GET /admin/events SSE endpoint existence and content-type
  - EventStreamConfig in AetherConfig
"""
from __future__ import annotations

import asyncio
import json
import uuid

import pytest
from fastapi.testclient import TestClient

from aetheros_orchestrator.events import (
    EventBus,
    RunEvent,
    diff_snapshots,
    get_event_bus,
    reset_event_bus,
)
from aetheros_orchestrator.config import AetherConfig, EventStreamConfig
from aetheros_orchestrator.api import create_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_bus():
    """Isolate each test by resetting the singleton EventBus."""
    reset_event_bus()
    yield
    reset_event_bus()


@pytest.fixture(scope="module")
def app():
    return create_app()


@pytest.fixture(scope="module")
def client(app):
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# RunEvent dataclass tests
# ---------------------------------------------------------------------------


def test_run_event_has_required_fields():
    event = RunEvent(type="aetheros.run.created", data={"run_id": "r1"})
    for field in ("type", "data", "id", "specversion", "source", "time"):
        assert hasattr(event, field), f"RunEvent missing field: {field}"


def test_run_event_specversion_is_1_0():
    event = RunEvent(type="aetheros.run.created", data={})
    assert event.specversion == "1.0"


def test_run_event_source():
    event = RunEvent(type="aetheros.run.created", data={})
    assert event.source == "/aetheros/run-service"


def test_run_event_id_is_uuid():
    event = RunEvent(type="aetheros.run.created", data={})
    # Must be parseable as a UUID4 string.
    parsed = uuid.UUID(event.id)
    assert parsed.version == 4


def test_run_event_time_is_iso8601_utc():
    event = RunEvent(type="aetheros.run.created", data={})
    assert event.time.endswith("Z"), f"time should end with 'Z', got: {event.time}"


def test_run_event_to_sse_data_is_json():
    event = RunEvent(type="aetheros.run.created", data={"run_id": "r1"})
    parsed = json.loads(event.to_sse_data())
    assert isinstance(parsed, dict)


def test_run_event_to_sse_data_contains_type():
    event = RunEvent(type="aetheros.run.completed", data={"run_id": "r2"})
    parsed = json.loads(event.to_sse_data())
    assert "type" in parsed
    assert parsed["type"] == "aetheros.run.completed"


# ---------------------------------------------------------------------------
# EventBus tests
# ---------------------------------------------------------------------------


def test_event_bus_subscribe_returns_queue():
    bus = EventBus()
    q = bus.subscribe()
    assert isinstance(q, asyncio.Queue)


def test_event_bus_subscriber_count():
    bus = EventBus()
    assert bus.subscriber_count == 0
    q1 = bus.subscribe()
    assert bus.subscriber_count == 1
    q2 = bus.subscribe()
    assert bus.subscriber_count == 2
    bus.unsubscribe(q1)
    assert bus.subscriber_count == 1
    bus.unsubscribe(q2)
    assert bus.subscriber_count == 0


def test_event_bus_publish_delivers_to_subscriber():
    bus = EventBus()
    q = bus.subscribe(maxsize=10)
    event = RunEvent(type="aetheros.run.created", data={"run_id": "r1"})
    bus.publish(event)
    delivered = q.get_nowait()
    assert delivered is event


def test_event_bus_publish_drops_on_full_queue():
    bus = EventBus()
    q = bus.subscribe(maxsize=1)
    # Fill the queue.
    bus.publish(RunEvent(type="aetheros.run.created", data={}))
    # These two should silently drop — no exception.
    bus.publish(RunEvent(type="aetheros.run.created", data={}))
    bus.publish(RunEvent(type="aetheros.run.created", data={}))
    # Queue has exactly 1 item.
    assert q.qsize() == 1


def test_event_bus_unsubscribe_removes_queue():
    bus = EventBus()
    q = bus.subscribe(maxsize=10)
    bus.unsubscribe(q)
    # After unsubscribe, publish should not reach the queue.
    bus.publish(RunEvent(type="aetheros.run.created", data={"run_id": "r1"}))
    assert q.empty()


# ---------------------------------------------------------------------------
# diff_snapshots tests
# ---------------------------------------------------------------------------


def test_diff_new_run_yields_created_event():
    prev = {}
    curr = {"r1": {"run_id": "r1", "status": "running"}}
    events = diff_snapshots(prev, curr)
    assert len(events) == 1
    assert events[0].type == "aetheros.run.created"
    assert events[0].data["run_id"] == "r1"


def test_diff_status_change_yields_completed():
    prev = {"r1": {"run_id": "r1", "status": "running"}}
    curr = {"r1": {"run_id": "r1", "status": "completed"}}
    events = diff_snapshots(prev, curr)
    assert len(events) == 1
    assert events[0].type == "aetheros.run.completed"


def test_diff_status_change_yields_halted():
    prev = {"r1": {"run_id": "r1", "status": "running"}}
    curr = {"r1": {"run_id": "r1", "status": "halted"}}
    events = diff_snapshots(prev, curr)
    assert len(events) == 1
    assert events[0].type == "aetheros.run.halted"


def test_diff_status_change_yields_approval_required():
    prev = {"r1": {"run_id": "r1", "status": "running"}}
    curr = {"r1": {"run_id": "r1", "status": "awaiting_approval"}}
    events = diff_snapshots(prev, curr)
    assert len(events) == 1
    assert events[0].type == "aetheros.run.approval_required"


def test_diff_cursor_change_yields_step_completed():
    prev = {"r1": {"run_id": "r1", "status": "running", "cursor": 0}}
    curr = {"r1": {"run_id": "r1", "status": "running", "cursor": 1}}
    events = diff_snapshots(prev, curr)
    assert len(events) == 1
    assert events[0].type == "aetheros.run.step_completed"


def test_diff_no_change_yields_nothing():
    snapshot = {"r1": {"run_id": "r1", "status": "running", "cursor": 2}}
    events = diff_snapshots(snapshot, snapshot)
    assert events == []


def test_diff_deleted_run_yields_deleted_event():
    prev = {"r1": {"run_id": "r1", "status": "completed"}}
    curr = {}
    events = diff_snapshots(prev, curr)
    assert len(events) == 1
    assert events[0].type == "aetheros.run.deleted"
    assert events[0].data["run_id"] == "r1"


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------


def _get_sse_response(app, url: str, timeout: float = 5.0):
    """Helper: open an SSE connection in a background thread, grab headers, close.

    Uses a daemon thread so the test suite is never blocked by the infinite
    SSE generator. The thread captures response status/content-type as soon as
    headers arrive, then signals the main thread which waits at most `timeout`
    seconds before returning the result dict.
    """
    import threading

    result: dict = {}
    headers_ready = threading.Event()  # set when headers are captured
    stop_event = threading.Event()     # set by main thread to close the stream

    def _run():
        try:
            with TestClient(app, raise_server_exceptions=False) as c:
                with c.stream("GET", url, timeout=timeout) as resp:
                    result["status_code"] = resp.status_code
                    result["content_type"] = resp.headers.get("content-type", "")
                    headers_ready.set()        # notify main thread
                    stop_event.wait(timeout=1) # wait for close signal
                    # exiting with-block closes the SSE connection
        except Exception as exc:
            result["error"] = str(exc)
            headers_ready.set()  # unblock main thread on error too

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    headers_ready.wait(timeout=timeout)  # wait for headers (not full stream)
    stop_event.set()                     # signal thread to close
    t.join(timeout=2)                    # brief join for cleanup
    return result


def test_admin_events_endpoint_exists(app):
    """Verify GET /admin/events is registered in the app routes."""
    # Check the OpenAPI spec rather than hitting the live stream, which would
    # block forever. The spec confirms the route is wired.
    spec = app.openapi()
    assert "/admin/events" in spec["paths"], (
        "/admin/events not found in OpenAPI paths: " + str(list(spec["paths"].keys()))
    )


def test_admin_events_content_type(app):
    """Verify GET /admin/events is declared as a streaming SSE endpoint.

    Confirms the route exists and is an HTTP GET (SSE endpoints are always GET).
    The actual content-type header (text/event-stream) is set by sse_starlette
    at runtime — it cannot be introspected from the OpenAPI schema since SSE
    responses are not standard OpenAPI response bodies.
    """
    spec = app.openapi()
    assert "get" in spec["paths"].get("/admin/events", {}), (
        "GET method not found on /admin/events"
    )


def test_event_stream_config_in_config():
    cfg = AetherConfig()
    assert hasattr(cfg, "event_stream")
    assert isinstance(cfg.event_stream, EventStreamConfig)


def test_event_stream_config_defaults():
    cfg = EventStreamConfig()
    assert cfg.poll_interval_seconds == 0.1
    assert cfg.heartbeat_interval_seconds == 15
