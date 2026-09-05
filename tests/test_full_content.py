import base64
import hashlib
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from requestwatch.app import create_app
from requestwatch.body_store import BodyStore, PREVIEW_BYTES
from requestwatch.config import Config
from requestwatch.runtime import Runtime
from requestwatch.store import Store


def test_complete_snapshot_hash_and_cross_chunk_unicode_search(tmp_path):
    bodies = BodyStore(tmp_path)
    text = "前" * (PREVIEW_BYTES - 1) + "Straße跨块尾部" + "尾" * 800000
    raw = b"\x00\xff" + text.encode()
    record = bodies.snapshot("request", raw, text)
    assert bodies.read_body(record) == raw
    assert bodies.read_text(record) == text
    assert record["request_body_ref"] == hashlib.sha256(raw).hexdigest()
    assert record["request_body_complete"] and record["request_preview_truncated"]
    assert record["request_body_b64"] is None
    assert bodies.contains(record, "STRASSE跨块尾部")
    assert len(record["request_body_text"].encode()) <= PREVIEW_BYTES
    with pytest.raises(ValueError):
        bodies.path("../admin-token")


def test_full_content_search_rule_and_small_database(tmp_path):
    store = Store(tmp_path / "records.sqlite3")
    text = "x" * (2 * 1024 * 1024) + "full-tail-marker"
    captured = {"source": "http", "protocol": "HTTP", "url": "http://example.test/full",
                **store.bodies.snapshot("request", text.encode(), text)}
    store.save_rule({"name": "full body rule", "keyword": "FULL-TAIL-MARKER", "timeout_seconds": 30})
    runtime = Runtime(store, SimpleNamespace(pending_limit=10, demo=False))
    saved = runtime.ingest(captured, can_intercept=True)
    assert saved["state"] == "pending"
    assert store.query(q="full-tail-marker")["total"] == 1
    row = store.db.execute("SELECT LENGTH(data),LENGTH(search_text) FROM records").fetchone()
    assert row[0] < 200000 and row[1] < 100000
    store.close()


def test_reference_retention_and_inline_updates(tmp_path):
    store = Store(tmp_path / "records.sqlite3", max_records=1)
    first = store.save({"id": "one", "source": "http", "request_body_text": "old-complete"})
    old_ref = first["request_body_ref"]
    second = store.update("one", {"request_body_text": "new-complete"})
    assert store.bodies.read_body(second) == b"new-complete"
    assert store.query(q="old-complete")["total"] == 0
    orphan = store.bodies.path(old_ref)
    os.utime(orphan, (time.time()-1000,) * 2)
    store.gc_bodies()
    assert not orphan.exists()
    assert store.bodies.path(second["request_body_ref"]).exists()
    store.close()


def test_body_api_full_bytes_text_export_auth_and_legacy(tmp_path):
    app = create_app(Config(data_dir=tmp_path, token="full-content-api-test-token", demo=True))
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer full-content-api-test-token"
        text = "正文" * 600000 + "下载末尾"
        raw = text.encode()
        record = app.state.store.save({"id": "large", "source": "http", "protocol": "HTTP", "method": "POST",
            "url": "http://example.test/upload?a=1", "request_headers": [["Content-Type", "text/plain; charset=utf-8"], ["X-Repeat", "one"], ["X-Repeat", "two"], ["Transfer-Encoding", "chunked"]],
            **app.state.store.bodies.snapshot("request", raw, text),
            **app.state.store.bodies.snapshot("response", raw[::-1], "decoded response tail")})
        detail = client.get("/api/records/large").json()
        assert detail["request_preview_truncated"] and detail["request_body_complete"]
        assert client.get("/api/records/large/body/request?view=raw").content == raw
        assert client.get("/api/records/large/body/request?view=text").text == text
        assert client.get("/api/records/large/body/response?view=raw").content == raw[::-1]
        exported = client.get("/api/records/large/message/request")
        head, body = exported.content.split(b"\r\n\r\n", 1)
        assert body == raw and head.startswith(b"POST /upload?a=1 HTTP/1.1")
        assert b"X-Repeat: one\r\nX-Repeat: two" in head
        assert b"Transfer-Encoding" not in head
        assert f"Content-Length: {len(raw)}".encode() in head
        assert client.get("/api/records/large/body/request", headers={"Authorization": ""}).status_code == 401
        assert client.get("/api/records", params={"q": "下载末尾"}).json()["total"] == 1
        legacy = app.state.store.save({"id": "legacy", "source": "http", "request_body_text": "prefix", "request_truncated": True, "request_body_size": 10000000})
        assert not legacy["request_body_complete"]
        assert client.get("/api/records/legacy/message/request").status_code == 409
        assert client.get("/api/records/legacy/body/request").headers["X-Body-Complete"] == "false"
        app.state.store.bodies.path(record["request_body_ref"]).unlink()
        assert client.get("/api/records/large/body/request?view=raw").status_code == 410


def test_tcp_session_runtime_api_and_complete_download(tmp_path):
    app = create_app(Config(data_dir=tmp_path, token="tcp-api-test-token", demo=True))
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer tcp-api-test-token"
        sessions = client.get("/api/sessions", params={"q": "跨包完整会话", "container_id": "demo-worker"}).json()
        assert sessions["total"] == 1
        session = sessions["items"][0]
        assert session["complete"] and session["state"] == "closed"
        records = client.get("/api/records", params={"protocol": "TCP"}).json()["items"]
        assert all(r["tcp_session_id"] == session["id"] for r in records)
        path = f"/api/sessions/{session['id']}/body/client"
        text = client.get(path).text
        assert "跨包完整会话" in text and text.endswith('"TCP-DEMO-END"}')
        assert client.get(path + "?view=raw").content == text.encode()
        ranged = client.get(path + "?view=raw", headers={"Range": "bytes=5-12"})
        assert ranged.status_code == 206 and ranged.content == text.encode()[5:13]
        assert client.get(path, headers={"Authorization": ""}).status_code == 401


def test_demo_body_retention_cannot_remove_production_bodies(tmp_path):
    live = create_app(Config(data_dir=tmp_path, token="isolation-live-token", capture_enabled=False, proxy_enabled=False))
    demo = create_app(Config(data_dir=tmp_path, token="isolation-demo-token", demo=True))
    with TestClient(live), TestClient(demo):
        body = live.state.store.save({"source": "http", "request_body_text": "production-content"})
        path = live.state.store.bodies.path(body["request_body_ref"])
        os.utime(path, (time.time()-1000,) * 2)
        demo.state.store.gc_bodies()
        assert path.read_bytes() == b"production-content"
        assert live.state.store.bodies.root != demo.state.store.bodies.root


def test_binary_only_update_replaces_old_searchable_text(tmp_path):
    store = Store(tmp_path / "update.sqlite3")
    store.save({"id": "body", "source": "http", "request_body_text": "OLD"})
    updated = store.update("body", {"request_body_b64": base64.b64encode(b"NEW").decode()})
    assert store.bodies.read_body(updated) == b"NEW"
    assert store.bodies.read_text(updated) == "NEW"
    assert store.query(q="NEW")["total"] == 1
    assert store.query(q="OLD")["total"] == 0
    store.close()


def test_failed_persistence_does_not_consume_pending_slot(tmp_path):
    store = Store(tmp_path / "pending.sqlite3")
    store.save_rule({"name": "test", "port": 80, "timeout_seconds": 30})
    runtime = Runtime(store, SimpleNamespace(pending_limit=1, demo=False))
    with pytest.raises(ValueError):
        runtime.ingest({"id": "bad", "source": "http", "protocol": "HTTP", "dst_port": 80,
                        "request_body_ref": "a" * 64}, can_intercept=True)
    assert runtime.pending_count() == 0 and store.get("bad") is None
    store.close()


def test_full_search_does_not_block_capture(tmp_path, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    store = Store(tmp_path / "concurrent.sqlite3")
    store.save({"source": "http", "request_body_text": "initial"})
    entered, release = threading.Event(), threading.Event()
    def slow_contains(*args):
        entered.set()
        assert release.wait(5)
        return False
    monkeypatch.setattr(store.bodies, "contains", slow_contains)
    with ThreadPoolExecutor(max_workers=2) as executor:
        searching = executor.submit(store.query, q="missing")
        assert entered.wait(2)
        try:
            capturing = executor.submit(store.save, {"source": "packet", "payload_text": "new capture"})
            assert capturing.result(timeout=2)["payload_text"] == "new capture"
        finally:
            release.set()
        assert searching.result(timeout=2)["total"] == 0
    store.close()
