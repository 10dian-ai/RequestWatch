from types import SimpleNamespace

import pytest

from requestwatch.runtime import Runtime
from requestwatch.store import Store


@pytest.fixture
def clock(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr("requestwatch.store.time.time", lambda: now[0])
    return now


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / "activity.sqlite3")
    yield value
    value.close()


def active(record_id="live", **changes):
    return {"id": record_id, "source": "http", "protocol": "HTTP", "state": "forwarded",
            "http_in_flight": True, "response_streaming": True,
            "response_body_complete": False, "response_body_text": "received-prefix", **changes}


def test_inactive_long_response_keeps_lease_with_heartbeats_without_changing_capture_totals(store, clock):
    record = store.save(active(http_activity_at=1))
    assert record["http_activity_at"] == 1000
    stats = store.stats()
    body_ref = record["response_body_ref"]
    for _ in range(30):
        clock[0] += 30
        assert store.touch_http(["live", "live", "unknown"]) == 1
        assert store.expire_http() == []
    record = store.get("live")
    assert record["http_in_flight"] and record["response_body_ref"] == body_ref
    assert record["http_activity_at"] == clock[0]
    assert store.stats() == stats


def test_expired_lease_keeps_captured_body_and_releases_retention_protection(store, clock):
    store.max_records = 1
    saved = store.save(active())
    clock[0] += 119
    assert store.expire_http() == []
    clock[0] += 1
    assert store.expire_http() == ["live"]
    assert store.expire_http() == []
    item = store.get("live")
    assert item["state"] == "error" and item["http_in_flight"] is False
    assert item["response_streaming"] is False and item["response_body_complete"] is False
    assert item["response_truncated"] is True and item["response_body_error"]
    assert item["response_body_ref"] == saved["response_body_ref"]
    assert store.bodies.read_text(item, "response") == "received-prefix"
    assert store.touch_http(["live"]) == 0
    store.save({"source": "packet", "id": "next"})
    assert store.get("live") is None
    assert store.stats()["captured_total"] == 2


def test_heartbeats_do_not_revive_completed_error_or_packet_records(store, clock):
    for name, state in (("complete", "forwarded"), ("failed", "error"), ("dropped", "dropped")):
        store.save(active(name, state=state, http_in_flight=False))
    store.save({"id": "packet", "source": "packet", "http_in_flight": True})
    before = {name: store.get(name) for name in ("complete", "failed", "dropped", "packet")}
    clock[0] += 1000
    assert store.touch_http(list(before)) == 0
    assert store.expire_http() == []
    assert before == {name: store.get(name) for name in before}


def test_completed_response_ignores_delayed_heartbeat(store, clock):
    store.save(active())
    clock[0] += 30
    store.update("live", {"http_in_flight": False, "response_streaming": False,
                          "response_body_complete": True, "response_body_text": "whole-response"})
    completed = store.get("live")
    assert store.touch_http(["live"]) == 0
    clock[0] += 1000
    assert store.expire_http() == []
    assert store.get("live") == completed
    assert store.bodies.read_text(completed, "response") == "whole-response"


def test_heartbeats_batch_ids_and_expiration_returns_only_actual_changes(store, clock):
    for number in range(501):
        store.save(active(str(number), response_body_text=""))
    clock[0] += 110
    assert store.touch_http([str(number) for number in range(0, 501, 2)]) == 251
    clock[0] += 10
    assert set(store.expire_http()) == {str(number) for number in range(1, 501, 2)}
    assert store.touch_http([str(number) for number in range(501)]) == 251
    assert store.stats()["captured_total"] == 501


def paused_runtime(store):
    store.save_rule({"id": "pause", "name": "pause test", "source": "http", "host": "example.test",
                     "enabled": True, "timeout_seconds": 300})
    runtime = Runtime(store, SimpleNamespace(pending_limit=5, demo=False))
    held = runtime.ingest(active(url="http://example.test/stream"), can_intercept=True)
    assert held["state"] == "pending"
    return runtime


def test_runtime_expiration_atomically_removes_pending_decisions(store, clock):
    runtime = paused_runtime(store)
    assert runtime.pending_count() == 1
    clock[0] += 120
    assert runtime.expire_http() == 1
    assert runtime.pending_count() == 0
    with pytest.raises(ValueError):
        runtime.resolve("live", "accept", {})
    assert runtime.take_decision("live") is None
    assert store.get("live")["state"] == "error"


@pytest.mark.parametrize("operation", ["resolve", "take_decision"])
def test_stale_runtime_entry_cannot_reopen_a_terminal_record(store, clock, operation):
    runtime = paused_runtime(store)
    if operation == "take_decision":
        runtime.resolve("live", "accept", {})
    # Simulate expiry/state invalidation outside the Runtime lock.
    clock[0] += 120
    assert store.expire_http() == ["live"]
    if operation == "resolve":
        with pytest.raises(ValueError):
            runtime.resolve("live", "accept", {})
    else:
        assert runtime.take_decision("live") is None
    assert runtime.pending_count() == 0 and store.get("live")["state"] == "error"
