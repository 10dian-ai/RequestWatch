"""Opt-in end-to-end test against the actual app, proxy, store, rules and replay.

RW_RUN_APP_INTEGRATION=1 RW_MITMDUMP=/absolute/path/to/mitmdump python -m pytest
    tests/test_app_integration.py -q

All listeners use random loopback ports. Packet capture stays disabled, and the
test does not use the application's normal data directory or port 7030.
"""
import concurrent.futures
import json
import os
from pathlib import Path
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
import uvicorn

from requestwatch.app import create_app
from requestwatch.config import Config


def until(predicate, description, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.04)
    pytest.fail(f"Timed out waiting for {description}")


@pytest.mark.skipif(os.getenv("RW_RUN_APP_INTEGRATION") != "1", reason="Opt-in real app/mitmdump integration")
def test_app_rule_pause_edit_search_and_replay(tmp_path):
    mitmdump = os.getenv("RW_MITMDUMP", "")
    assert mitmdump and Path(mitmdump).is_absolute() and Path(mitmdump).is_file(), "Set RW_MITMDUMP to an absolute executable path"
    seen = []
    original_body = "x" * (2 * 1024 * 1024) + "hold-me"
    approved_body = "y" * (3 * 1024 * 1024) + "approved-body-tail"
    replayed_body = "z" * (2 * 1024 * 1024) + "replayed-body-tail"

    class Origin(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
            request = {"method": self.command, "path": self.path, "body": body,
                       "repeat": self.headers.get_all("X-Repeat")}
            seen.append(request)
            content = json.dumps({"marker": "origin-response-only-marker", "received": request}).encode()
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        do_PUT = do_POST

    origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()
    management_socket = socket.socket()
    management_socket.bind(("127.0.0.1", 0))
    management_socket.listen(2048)
    management_port = management_socket.getsockname()[1]
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        proxy_port = reservation.getsockname()[1]
    token = "app-integration-private-test-token"
    config = Config(host="127.0.0.1", port=management_port, data_dir=tmp_path / "live-app",
                    token=token, capture_enabled=False, passive_only=False, proxy_enabled=True,
                    proxy_host="127.0.0.1", proxy_port=proxy_port, demo=False)
    app = create_app(config)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=management_port,
                                           log_level="error", access_log=False))
    server_thread = threading.Thread(target=server.run, kwargs={"sockets": [management_socket]}, daemon=True)
    server_thread.start()
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    origin_url = f"http://127.0.0.1:{origin.server_port}"
    admin_url = f"http://127.0.0.1:{management_port}"

    def send_request():
        with httpx.Client(proxy=f"http://127.0.0.1:{proxy_port}", trust_env=False, timeout=20) as client:
            return client.post(origin_url + "/original", content=original_body, headers={"Content-Type": "text/plain"})

    try:
        until(lambda: server.started, "actual app startup", seconds=20)
        with httpx.Client(base_url=admin_url, headers={"Authorization": "Bearer " + token},
                          trust_env=False, timeout=5) as admin:
            status = admin.get("/api/status").json()
            assert status["mode"] == "live"
            assert status["port"] == management_port != 7030

            def proxy_ready():
                try:
                    with socket.create_connection(("127.0.0.1", proxy_port), timeout=0.1):
                        return True
                except OSError:
                    return False

            until(proxy_ready, "mitmdump listener", seconds=20)
            rule = admin.post("/api/rules", json={"name": "integration hold",
                "source": "http", "protocol": "HTTP", "host": "127.0.0.1", "port": origin.server_port,
                "keyword": "hold-me", "timeout_seconds": 30})
            assert rule.status_code == 200, rule.text
            future = executor.submit(send_request)

            def pending_record():
                response = admin.get("/api/records", params={"state": "pending", "source": "http"})
                response.raise_for_status()
                items = response.json()["items"]
                return items[0] if items else None

            pending = until(pending_record, "request held by the actual rule")
            record_id = pending["id"]
            assert not future.done()
            assert seen == [], "The pending request must not have reached the origin"
            detail = admin.get(f"/api/records/{record_id}").json()
            assert detail["request_body_complete"] and detail["request_preview_truncated"]
            assert admin.get(f"/api/records/{record_id}/body/request?view=text").text == original_body
            assert admin.get("/api/records", params={"q": "hold-me"}).json()["total"] == 1
            decision = admin.post(f"/api/records/{record_id}/decision", json={"action": "accept", "edits": {
                "method": "PUT", "url": origin_url + "/edited", "body_text": approved_body,
                "headers": [["Content-Type", "text/plain; charset=utf-8"], ["X-Repeat", "one"], ["X-Repeat", "two"]]}})
            assert decision.status_code == 200, decision.text
            response = future.result(timeout=10)
            assert response.status_code == 201
            assert seen == [{"method": "PUT", "path": "/edited", "body": approved_body, "repeat": ["one", "two"]}]

            def response_is_searchable():
                result = admin.get("/api/records", params={"q": "origin-response-only-marker", "source": "http"}).json()
                return result if result["total"] == 1 else None

            assert until(response_is_searchable, "response body search")["items"][0]["id"] == record_id
            updated = admin.get(f"/api/records/{record_id}").json()
            assert updated["state"] == "forwarded"
            assert updated["status_code"] == 201
            assert updated["request_body_complete"] and updated["request_preview_truncated"]
            assert admin.get(f"/api/records/{record_id}/body/request?view=raw").content == approved_body.encode()
            assert admin.get(f"/api/records/{record_id}/body/response?view=raw").content == response.content
            assert admin.get(f"/api/records/{record_id}/message/request").content.endswith(approved_body.encode())
            assert admin.get("/api/records", params={"q": "approved-body-tail"}).json()["total"] == 1
            unchanged = admin.post(f"/api/records/{record_id}/replay", json={"edits": {}})
            assert unchanged.status_code == 200, unchanged.text
            assert seen[-1]["body"] == approved_body
            replay = admin.post(f"/api/records/{record_id}/replay", json={"edits": {"body_text": replayed_body}})
            assert replay.status_code == 200, replay.text
            repeated = replay.json()
            assert repeated["id"] != record_id
            assert repeated["replay_of"] == record_id
            assert repeated["state"] == "replayed"
            assert repeated["status_code"] == 201
            assert len(seen) == 3 and seen[2] == {"method": "PUT", "path": "/edited", "body": replayed_body, "repeat": ["one", "two"]}
            assert admin.get("/api/records", params={"q": "origin-response-only-marker"}).json()["total"] == 3
    finally:
        server.should_exit = True
        server_thread.join(timeout=15)
        if server_thread.is_alive():
            server.force_exit = True
            server_thread.join(timeout=3)
        management_socket.close()
        origin.shutdown()
        origin.server_close()
        origin_thread.join(timeout=2)
        executor.shutdown(wait=True, cancel_futures=True)
        assert not server_thread.is_alive(), "The temporary app must shut down after the test"
