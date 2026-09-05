"""Actual local origin -> mitmdump -> app/store integration, with no host capture."""
import concurrent.futures
import json
import os
from pathlib import Path
import socket
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
import uvicorn

from requestwatch.app import create_app
from requestwatch.config import Config
from test_app_integration import until


@pytest.mark.skipif(os.getenv("RW_RUN_APP_INTEGRATION") != "1", reason="Opt-in real app/mitmdump integration")
@pytest.mark.parametrize("scenario", ["sse", "gzip-sse", "interrupted-json"])
def test_response_visible_before_eof_and_retained_during_packet_flood(tmp_path, scenario):
    executable = os.getenv("RW_MITMDUMP", "")
    assert Path(executable).is_absolute() and Path(executable).is_file()
    first = ('data: ' + json.dumps({"choices": [{"delta": {"reasoning_content": "灰色思考", "content": "第一段中文\n"}}]}, ensure_ascii=False) + '\n\n').encode()
    last = b'data: {"choices":[{"delta":{"content":"TAIL-AT-END"}}]}\n\ndata: [DONE]\n\n'
    if scenario == "interrupted-json":
        first, last = '{"partial":"已到达的内容'.encode(), b""
    compressor = zlib.compressobj(wbits=31) if scenario == "gzip-sse" else None
    wire_first = compressor.compress(first) + compressor.flush(zlib.Z_SYNC_FLUSH) if compressor else first
    wire_last = compressor.compress(last) + compressor.flush() if compressor else last
    release = threading.Event()
    received = threading.Event()
    client_data = bytearray()

    class Origin(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        def log_message(self, *args):
            pass
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json" if scenario == "interrupted-json" else "text/event-stream")
            if compressor:
                self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length" if scenario == "interrupted-json" else "Transfer-Encoding",
                             "99999" if scenario == "interrupted-json" else "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            def send(data):
                if scenario == "interrupted-json":
                    self.wfile.write(data)
                else:
                    self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                self.wfile.flush()
            send(wire_first)
            release.wait(25)
            if scenario != "interrupted-json":
                send(wire_last)
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            self.close_connection = True

    origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(2048)
    port = listener.getsockname()[1]
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        proxy_port = reserve.getsockname()[1]
    token = "streaming-integration-test-token"
    app = create_app(Config(host="127.0.0.1", port=port, data_dir=tmp_path / "app", token=token,
                            capture_enabled=False, proxy_enabled=True, proxy_host="127.0.0.1",
                            proxy_port=proxy_port, mitmdump=executable))
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)

    def send_request():
        try:
            with httpx.Client(proxy=f"http://127.0.0.1:{proxy_port}", trust_env=False, timeout=20) as requester:
                with requester.stream("GET", f"http://127.0.0.1:{origin.server_port}/{scenario}") as response:
                    for chunk in response.iter_raw():
                        client_data.extend(chunk)
                        received.set()
        except httpx.RemoteProtocolError:
            if scenario != "interrupted-json":
                raise

    try:
        until(lambda: server.started, "actual app started", seconds=20)
        def ready():
            try:
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=0.1):
                    return True
            except OSError:
                return False
        until(ready, "proxy ready", seconds=20)
        future = pool.submit(send_request)
        assert received.wait(6), "The first response chunk must reach the client before origin EOF"
        assert not future.done() and not release.is_set()
        with httpx.Client(base_url=f"http://127.0.0.1:{port}", headers={"Authorization": "Bearer " + token}, timeout=5, trust_env=False) as admin:
            def first_saved():
                records = admin.get("/api/records", params={"source": "http"}).json()["items"]
                if not records:
                    return None
                record = admin.get("/api/records/" + records[0]["id"]).json()
                return record if record.get("response_body_size", 0) >= len(wire_first) else None
            record = until(first_saved, "partial response persisted before EOF")
            rid = record["id"]
            route = "/api/records/" + rid
            assert record["http_in_flight"] and record["response_streaming"]
            assert record["response_body_complete"] is False
            assert admin.get(route + "/body/response?view=raw").content == wire_first
            assert admin.get(route + "/body/response?view=text").text == first.decode()
            if scenario != "interrupted-json":
                meta = admin.get(route + "/readable/response").json()
                text = admin.get(meta["content_url"]).text
                assert "灰色思考" in text and "第一段中文" in text
            app.state.store.max_records = 4
            for number in range(20):
                app.state.runtime.ingest({"source": "packet", "protocol": "UDP", "payload_text": str(number)})
            assert admin.get(route).status_code == 200, "Packet retention cannot evict an unfinished response"
            release.set()
            future.result(timeout=10)
            def finished():
                result = admin.get(route).json()
                return result if result.get("http_in_flight") is False else None
            final = until(finished, "terminal response snapshot")
            assert final["response_streaming"] is False
            assert admin.get(route + "/body/response?view=raw").content == wire_first + wire_last
            assert bytes(client_data) == wire_first + wire_last
            assert admin.get(route + "/body/response?view=text").text == (first + last).decode()
            if scenario == "interrupted-json":
                assert final["state"] == "error" and not final["response_body_complete"]
                assert admin.get(route + "/message/response").status_code == 409
            else:
                assert final["response_body_complete"]
                assert admin.get("/api/records", params={"q": "TAIL-AT-END"}).json()["total"] == 1
                meta = admin.get(route + "/readable/response").json()
                assert "第一段中文\nTAIL-AT-END" in admin.get(meta["content_url"]).text
    finally:
        release.set()
        pool.shutdown(wait=True, cancel_futures=True)
        server.should_exit = True
        thread.join(timeout=15)
        if thread.is_alive():
            server.force_exit = True
            thread.join(timeout=3)
        listener.close()
        origin.shutdown()
        origin.server_close()
        origin_thread.join(timeout=2)
        assert not thread.is_alive()
