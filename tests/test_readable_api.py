import base64
import gzip
import json

import pytest
from fastapi.testclient import TestClient

from requestwatch.app import create_app
from requestwatch.config import Config
from test_tcp_streams import packet

TOKEN = "readable-integration-test-token"


@pytest.fixture
def client(tmp_path):
    app = create_app(Config(data_dir=tmp_path, token=TOKEN, demo=True))
    with TestClient(app) as instance:
        instance.headers["Authorization"] = "Bearer " + TOKEN
        yield instance


def events(parts):
    return ("".join("data: " + json.dumps({"id": "test-stream", "choices": [{"index": 0, "delta": {"content": part}}]}, ensure_ascii=True) + "\n\n" for part in parts) + "data: [DONE]\n\n").encode()


def test_http_readable_uses_full_decoded_body_and_keeps_raw_download(client):
    payload = events(["第一行\n", "后半部分" + "x" * (1024 * 1024) + "完整尾标"])
    compressed = gzip.compress(payload)
    store = client.app.state.store
    store.save({"id": "readable-http", "source": "http", "protocol": "HTTP", "method": "GET", "url": "http://example.test/sse",
                "response_headers": [["Content-Type", "text/event-stream"], ["Content-Encoding", "gzip"], ["Transfer-Encoding", "chunked"]],
                **store.bodies.snapshot("response", compressed, payload.decode())})
    meta = client.get("/api/records/readable-http/readable/response").json()
    assert meta["recognized"] and meta["kind"] == "sse"
    content = client.get(meta["content_url"])
    assert content.status_code == 200
    assert "第一行\n后半部分" in content.text and "完整尾标" in content.text
    assert meta["content_size"] == len(content.content) > 1024 * 1024
    assert client.get(meta["download_url"]).content == content.content
    assert client.get("/api/records/readable-http/body/response?view=raw").content == compressed
    again = client.get("/api/records/readable-http/readable/response").json()
    assert again["revision"] == meta["revision"]
    assert client.get(meta["content_url"], headers={"Authorization": ""}).status_code == 401
    store.save({"id": "other", "source": "http", "request_body_text": "different"})
    assert client.get(f"/api/records/other/readable/request/content?revision={meta['revision']}").status_code == 410


def test_tcp_chunked_fragment_readable_and_gap_refusal(client):
    payload = events(["普通中文\n", "第二段结束"])
    chunks = [payload[i:i + 31] for i in range(0, len(payload), 31)]
    raw = b"".join(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n" for chunk in chunks) + b"0\r\n\r\n"
    runtime = client.app.state.runtime
    record = runtime.ingest(packet(raw[:80], seq=100))
    sid = record["tcp_session_id"]
    runtime.ingest(packet(raw[80:], seq=180))
    meta = client.get(f"/api/sessions/{sid}/readable/client").json()
    assert meta["recognized"] and not meta["complete"]
    readable = client.get(meta["content_url"]).text
    assert "普通中文\n第二段结束" in readable
    assert client.get(f"/api/sessions/{sid}/body/client?view=raw").content == raw
    # A gap after the readable prefix must invalidate the decoded snapshot, not join unrelated bytes.
    runtime.ingest(packet(b"data: tail\n\n", seq=100 + len(raw) + 10))
    gap = client.get(f"/api/sessions/{sid}/readable/client").json()
    assert gap["revision"] != meta["revision"] and not gap["recognized"]
    assert any("缺" in warning for warning in gap["warnings"])
    # Old metadata keeps referencing its own immutable content, even as TCP advances.
    assert client.get(meta["content_url"]).text == readable


def test_api_statistics_keep_moving_at_record_limit(client):
    store = client.app.state.store
    store.max_records = 3
    before = client.get("/api/status").json()["stats"]["captured_total"]
    for number in range(6):
        store.save({"id": "count-" + str(number), "source": "packet", "protocol": "UDP"})
    stats = client.get("/api/status").json()["stats"]
    assert stats["retained"] == 3 and stats["captured_total"] == before + 6
    assert stats["last_capture_at"]


def test_conflicting_tcp_bytes_cannot_be_presented_as_decoded_application_content(client):
    payload = events(["原始正文"])
    runtime = client.app.state.runtime
    record = runtime.ingest(packet(payload, seq=100))
    sid = record["tcp_session_id"]
    runtime.ingest(packet(b"xxxxxx", seq=100))
    meta = client.get(f"/api/sessions/{sid}/readable/client").json()
    assert not meta["recognized"] and not meta["complete"]
    assert client.get(f"/api/sessions/{sid}/body/client?view=raw").content == payload
