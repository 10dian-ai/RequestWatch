import base64
import gzip
import brotli
import zstandard
import json

import pytest
from fastapi.testclient import TestClient

from requestwatch.app import create_app
from requestwatch.config import Config
from requestwatch.network import packet_record
from requestwatch.store import Store
from test_tcp_streams import packet


@pytest.fixture
def client(tmp_path):
    app = create_app(Config(data_dir=tmp_path, token="packet-detail-test-token", demo=True))
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer packet-detail-test-token"
        yield client


def ingest(client, payload=b"", **kwargs):
    raw = base64.b64decode(packet(payload, **kwargs)["raw_b64"])
    return client.app.state.runtime.ingest(packet_record(raw))


def test_packet_list_is_explicit_preview_detail_is_full_and_linked_to_direction(client):
    ingest(client, seq=99, flags=2)
    ingest(client, seq=199, flags=0x12, reverse=True)
    payload = ("data: " + json.dumps({"choices": [{"delta": {"reasoning_content": "灰色" * 150, "content": "正文" * 150}}]}, ensure_ascii=False) + "\n\n").encode()
    record = ingest(client, payload, seq=200, reverse=True)
    listed = client.get("/api/records", params={"q": "灰色"}).json()["items"][0]
    assert listed["detail_level"] == "summary" and listed["payload_preview_truncated"]
    assert len(listed["payload_text"]) == 240 and "payload_hex" not in listed
    detail = client.get("/api/records/" + record["id"]).json()
    assert detail["detail_level"] == "full" and detail["payload_text"] == payload.decode()
    assert bytes.fromhex(detail["payload_hex"]) == payload
    assert detail["tcp_session_available"] and detail["tcp_session_direction"] == "server"
    assert client.get(f"/api/sessions/{detail['tcp_session_id']}/body/server?view=raw").content == payload
    assert client.get("/api/records/" + record["id"], headers={"Authorization": ""}).status_code == 401


def test_legacy_record_link_recovers_only_by_exact_observation(client):
    record = ingest(client, b"exact-record", seq=100)
    session_id = record.pop("tcp_session_id")
    client.app.state.store.save(record)
    detail = client.get("/api/records/" + record["id"]).json()
    assert detail["tcp_session_id"] == session_id and detail["tcp_session_direction"] == "client"
    unknown = {**record, "id": "unassociated"}
    client.app.state.store.save(unknown)
    detail = client.get("/api/records/unassociated").json()
    assert not detail["tcp_session_available"] and "tcp_session_id" not in detail
    assert "准确会话关联" in detail["tcp_session_unavailable_reason"]


def test_evicted_session_does_not_claim_available(client):
    record = ingest(client, b"retained-packet", seq=100)
    with client.app.state.streams.lock, client.app.state.streams.db:
        client.app.state.streams.db.execute("DELETE FROM sessions WHERE id=?", (record["tcp_session_id"],))
    detail = client.get("/api/records/" + record["id"]).json()
    assert not detail["tcp_session_available"]
    assert detail["tcp_session_id"] == record["tcp_session_id"] and "保留数量" in detail["tcp_session_unavailable_reason"]


def test_direction_download_completeness_is_for_matching_snapshot(client):
    ingest(client, seq=99, flags=2)
    ingest(client, seq=199, flags=0x12, reverse=True)
    record = ingest(client, b"whole-direction", seq=100)
    ingest(client, seq=100 + len(b"whole-direction"), flags=0x11)
    route = f"/api/sessions/{record['tcp_session_id']}/body/"
    response = client.get(route + "client?view=raw")
    assert response.content == b"whole-direction" and response.headers["X-Body-Complete"] == "true"
    assert client.get(route + "server?view=raw").headers["X-Body-Complete"] == "false"


@pytest.mark.parametrize("compressed", ["", "gzip", "br", "zstd"])
def test_old_sse_mojibake_text_reference_does_not_override_correct_original(client, compressed):
    text = 'data: {"choices":[{"delta":{"reasoning_content":"思考内容", "content":"中文正文"}}]}\n\ndata: [DONE]\n\n'
    payload = text.encode()
    raw = {"": lambda data: data, "gzip": gzip.compress, "br": brotli.compress, "zstd": zstandard.ZstdCompressor().compress}[compressed](payload)
    store = client.app.state.store
    headers = [["Content-Type", "text/event-stream"]]
    if compressed:
        headers.append(["Content-Encoding", compressed])
    store.save({"id": "old-sse", "source": "http", "protocol": "HTTP", "response_headers": headers,
                **store.bodies.snapshot("response", raw, payload.decode("latin-1"))})
    meta = client.get("/api/records/old-sse/readable/response").json()
    readable = client.get(meta["content_url"]).text
    assert "中文正文" in readable and "思考内容" in readable
    assert client.get("/api/records/old-sse/body/response?view=raw").content == raw
    assert client.get("/api/records/old-sse/body/response?view=text").text == text
    assert store.get("old-sse")["response_text_ref"] == store.bodies.put(payload.decode("latin-1").encode())


def test_unfinished_http_response_survives_packet_retention_then_can_be_evicted(tmp_path):
    store = Store(tmp_path / "retention.sqlite3", max_records=2)
    store.save({"id": "live", "source": "http", "state": "forwarded", "http_in_flight": True, "request_body_text": "question"})
    for index in range(15):
        store.save({"source": "packet", "id": str(index)})
    assert store.get("live") is not None
    update = store.update("live", {"response_body_text": "first chunk", "response_streaming": True, "response_body_complete": False})
    assert store.bodies.read_text(update, "response") == "first chunk"
    store.update("live", {"response_body_text": "first chunk then final", "response_body_complete": True, "response_streaming": False, "http_in_flight": False})
    store.save({"source": "packet", "id": "next"})
    assert store.get("live") is None
    assert store.stats()["captured_total"] == 17
    store.close()


def test_restart_retains_partial_http_content_but_clears_active_claim(tmp_path):
    path = tmp_path / "restart.sqlite3"
    store = Store(path)
    store.save({"id": "interrupted", "source": "http", "state": "forwarded", "http_in_flight": True,
                "response_streaming": True, "response_body_text": "已收到前半部分", "response_body_complete": False})
    store.close()
    store = Store(path)
    record = store.get("interrupted")
    assert not record["http_in_flight"] and not record["response_streaming"]
    assert not record["response_body_complete"] and record["state"] == "error"
    assert store.bodies.read_text(record, "response") == "已收到前半部分"
    assert "服务重启" in record["response_body_error"]
    store.close()


def test_http_heartbeat_is_authenticated_bounded_and_cannot_revive_terminal_record(client):
    store = client.app.state.store
    store.save({"id": "heartbeat-active", "source": "http", "http_in_flight": True})
    store.save({"id": "heartbeat-done", "source": "http", "http_in_flight": False})
    response = client.post("/api/internal/heartbeat", json={"record_ids": ["heartbeat-active", "heartbeat-done", "missing"]})
    assert response.status_code == 200 and response.json()["updated"] == 1
    assert not store.get("heartbeat-done")["http_in_flight"]
    assert client.post("/api/internal/heartbeat", json={"record_ids": ["heartbeat-active"]}, headers={"Authorization": ""}).status_code == 401
    assert client.post("/api/internal/heartbeat", json={"record_ids": ["x"] * 501}).status_code == 422
    assert client.post("/api/internal/heartbeat", json={"record_ids": [""]}).status_code == 422
