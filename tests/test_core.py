import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from requestwatch.app import create_app
from requestwatch.config import Config
from requestwatch.rules import RuleInput, matches
from requestwatch.runtime import Runtime
from requestwatch.store import Store

TOKEN = "requestwatch-test-token-32-characters"


def rule(**overrides):
    value = {"name": "pause test", "source": "http", "host": "example.test", "timeout_seconds": 30}
    value.update(overrides)
    return RuleInput(**value).model_dump()


def record(**overrides):
    value = {"id": "record-1", "source": "http", "protocol": "HTTPS", "url": "https://example.test/v1/orders",
             "dst_ip": "192.0.2.20", "dst_port": 443, "src_ip": "172.18.0.3",
             "request_body_text": "订单 ORD-2048 100%_match", "state": "captured"}
    value.update(overrides)
    return value


@pytest.fixture
def db(tmp_path):
    store = Store(tmp_path / "test.sqlite3", max_records=3)
    yield store
    store.close()


def test_search_content_literal_wildcards_and_combined_filters(db):
    db.save(record(container_id="api", src_container_id="api", dst_container_id="worker"))
    db.save(record(id="another", protocol="HTTP", request_body_text="anything", response_body_text="回复成功"))
    assert db.query(q="订单", protocol="HTTPS", container_id="api")["total"] == 1
    assert db.query(container_id="worker")["total"] == 1
    assert db.query(q="100%_")["total"] == 1
    assert db.query(q="%not_wildcard")["total"] == 0
    assert db.query(q="ORD-2048".lower())["total"] == 1
    assert db.query(q="回复成功")["total"] == 1


def test_retention_never_evicts_waiting_decisions(db):
    db.save(record(id="pending", state="pending", created_at=1))
    for index in range(6):
        db.save(record(id=str(index), created_at=index + 2))
    assert db.stats()["total"] == 3
    assert db.get("pending") is not None
    assert db.get("0") is None


def test_restart_expires_unrecoverable_pending(tmp_path):
    location = tmp_path / "restart.sqlite3"
    first = Store(location)
    first.save(record(state="pending"))
    first.close()
    second = Store(location)
    assert second.get("record-1")["state"] == "error"
    second.close()


def test_rule_requires_scope_and_protocol_consistency():
    with pytest.raises(ValidationError):
        RuleInput(name="all traffic")
    with pytest.raises(ValidationError):
        RuleInput(name="wrong protocol", source="packet", protocol="HTTPS", port=443)
    with pytest.raises(ValidationError):
        RuleInput(name="too long", host="example.test", timeout_seconds=999)


def test_matching_requires_all_conditions():
    scoped = rule(keyword="订单", container_id="worker", port=443)
    traffic = record(dst_container_id="worker")
    assert matches(scoped, traffic)
    assert not matches({**scoped, "keyword": "different"}, traffic)
    assert not matches({**scoped, "port": 80}, traffic)
    assert not matches({**scoped, "enabled": False}, traffic)
    assert matches(rule(host="192.0.2.0/24"), traffic)


def test_runtime_single_verdict_timeout_and_capacity(db):
    db.save_rule(rule())
    runtime = Runtime(db, SimpleNamespace(pending_limit=1, demo=False))
    held = runtime.ingest(record(), can_intercept=True)
    assert held["state"] == "pending"
    overflow = runtime.ingest(record(id="overflow"), can_intercept=True)
    assert overflow["state"] == "captured"
    runtime.resolve("record-1", "accept", {"method": "PATCH"})
    with pytest.raises(ValueError):
        runtime.resolve("record-1", "drop", {})
    assert runtime.take_decision("record-1") == {"action": "accept", "edits": {"method": "PATCH"}}
    assert runtime.take_decision("record-1") is None
    runtime.ingest(record(id="timeout"), can_intercept=True)
    runtime._pending["timeout"]["deadline"] = time.monotonic() - 1
    assert runtime.take_decision("timeout") == {"action": "accept", "edits": {}}


@pytest.fixture
def client(tmp_path):
    cfg = Config(data_dir=tmp_path / "app", token=TOKEN, demo=True, capture_enabled=False, proxy_enabled=False)
    with TestClient(create_app(cfg)) as instance:
        instance.headers["Authorization"] = f"Bearer {TOKEN}"
        yield instance


def test_authentication_and_static_page(client):
    unauthorized = client.get("/api/status", headers={"Authorization": ""})
    assert unauthorized.status_code == 401
    assert client.get("/healthz", headers={"Authorization": ""}).status_code == 200
    assert client.get("/").status_code == 200
    assert client.get("/api/status").json()["port"] == 7030
    assert client.get("/api/status").json()["mode"] == "demo"
    assert client.get("/api/status").headers["X-Frame-Options"] == "DENY"


def test_full_rule_intercept_modify_and_search_flow(client):
    saved = client.post("/api/rules", json=rule(keyword="review-me")).json()
    assert saved["id"]
    held = client.post("/api/demo/intercept").json()
    assert held["state"] == "pending"
    result = client.post(f"/api/records/{held['id']}/decision", json={"action": "accept", "edits": {"body_text": "approved"}})
    assert result.status_code == 200
    assert client.post(f"/api/records/{held['id']}/decision", json={"action": "drop"}).status_code == 400
    client.app.state.runtime.demo_tick()
    assert client.get(f"/api/records/{held['id']}").json()["state"] == "forwarded"
    assert client.get("/api/records", params={"q": "approved", "protocol": "HTTPS"}).json()["total"] == 1
    exported = client.get(f"/api/records/{held['id']}/export")
    assert exported.status_code == 200
    assert "attachment" in exported.headers["Content-Disposition"]
    assert client.delete(f"/api/rules/{saved['id']}").status_code == 200
    assert client.get("/api/rules").json()["items"] == []


def test_proxy_ingest_update_and_response_search(client):
    body = record(id="integration-proxy")
    body["request_headers"] = [["X-Trace", "alpha"]]
    captured = client.post("/api/internal/ingest", json=body)
    assert captured.status_code == 200
    client.put("/api/internal/records/integration-proxy", json={"response_body_text": "response-only-needle", "state": "forwarded", "status_code": 200})
    assert client.get("/api/records", params={"q": "response-only-needle"}).json()["total"] == 1
    assert client.get("/api/internal/decision/integration-proxy").json() == {"decision": None}


def test_invalid_rule_and_stale_replay_errors(client):
    assert client.post("/api/rules", json={"name": "everything"}).status_code == 422
    assert client.get("/api/records/does-not-exist").status_code == 404
    client.post("/api/rules", json=rule())
    held = client.post("/api/demo/intercept").json()
    assert client.post(f"/api/records/{held['id']}/replay", json={"edits": {}}).status_code == 409
    assert client.get("/api/ca").status_code == 404


def test_demo_replay_is_recorded_without_network(client, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("demo must not send network traffic")
    monkeypatch.setattr("requestwatch.app.replay_http", forbidden)
    response = client.post("/api/records/demo-http-0/replay", json={"edits": {}})
    assert response.status_code == 200
    assert response.json()["state"] == "replayed"
    assert response.json()["replay_of"] == "demo-http-0"
