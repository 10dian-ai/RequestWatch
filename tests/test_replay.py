import base64
import gzip
import json
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from requestwatch.replay import replay_http, replay_packet, request_parts, validate_http_edits
from requestwatch.body_store import BodyStore


@pytest.fixture
def http_origin():
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            record = {
                "method": self.command, "path": self.path, "body_b64": base64.b64encode(body).decode(),
                "repeated": self.headers.get_all("X-Repeat"),
                "content_type": self.headers.get("Content-Type"),
                "content_encoding": self.headers.get("Content-Encoding"),
                "host": self.headers.get("Host"),
                "connection_secret": self.headers.get("X-Connection-Only"),
            }
            seen.append(record)
            response = json.dumps(record).encode()
            if self.path == "/compressed-response":
                response = gzip.compress(response)
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            if self.path == "/compressed-response":
                self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(response) + (100 if self.path == "/incomplete" else 0)))
            self.send_header("Set-Cookie", "one=1")
            self.send_header("Set-Cookie", "two=2")
            self.end_headers()
            self.wfile.write(response)

        do_GET = do_POST

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request_record(url="http://example.com/", body=b"original\x00\xff"):
    return {
        "id": "original-id", "source": "http", "method": "POST", "url": url,
        "request_body_b64": base64.b64encode(body).decode(),
        "request_body_text": "display preview only",
        "request_headers": [["Host", "old.example"], ["X-Repeat", "one"], ["X-Repeat", "two"],
                            ["Content-Length", "99999"], ["Transfer-Encoding", "chunked"],
                            ["Connection", "X-Connection-Only"], ["X-Connection-Only", "private"]],
    }


def test_http_replay_reaches_origin_with_binary_body_and_duplicate_headers(http_origin):
    url, seen = http_origin
    result = replay_http(request_record(url + "/replay"), {})
    assert result["state"] == "replayed"
    assert result["status_code"] == 201
    assert result["replay_of"] == "original-id"
    assert result["container_id"] == ""
    assert seen[0]["repeated"] == ["one", "two"]
    assert base64.b64decode(seen[0]["body_b64"]) == b"original\x00\xff"
    assert seen[0]["connection_secret"] is None
    assert seen[0]["host"] == url.removeprefix("http://")
    sent_headers = dict(result["request_headers"])
    assert sent_headers["host"] == seen[0]["host"]
    assert sent_headers["content-length"] == str(len(b"original\x00\xff"))
    assert [v for k, v in result["response_headers"] if k.lower() == "set-cookie"] == ["one=1", "two=2"]
    assert json.loads(result["response_body_text"])["path"] == "/replay"
    assert base64.b64decode(result["response_body_b64"]).decode() == result["response_body_text"]


@pytest.mark.parametrize("use_store", [False, True])
def test_large_request_and_response_are_saved_and_replayed_in_full(http_origin, tmp_path, use_store):
    import hashlib
    url, seen = http_origin
    raw = b"\x00large-full-body\xff" * 90_000 + b"TAIL_AFTER_ONE_MIB"
    bodies = BodyStore(tmp_path) if use_store else None
    record = request_record(url + "/full", raw)
    if bodies is not None:
        record.update(bodies.snapshot("request", raw, raw.decode("utf-8", "replace")))
    result = replay_http(record, {}, bodies)
    assert result["state"] == "replayed", result
    assert result["status_code"] == 201
    assert result["request_truncated"] is False
    assert result["response_truncated"] is False
    assert result["request_body_complete"] is True
    assert result["response_body_complete"] is True
    assert base64.b64decode(seen[0]["body_b64"]) == raw
    if bodies is not None:
        assert result["request_body_ref"] == hashlib.sha256(raw).hexdigest()
        assert bodies.read_body(result, "request") == raw
        response = json.loads(bodies.read_text(result, "response"))
        assert len(result["response_body_text"].encode()) <= 64 * 1024
        assert result["response_preview_truncated"] is True
    else:
        assert base64.b64decode(result["request_body_b64"]) == raw
        response = json.loads(result["response_body_text"])
    assert base64.b64decode(response["body_b64"]) == raw


def test_large_text_and_binary_edits_are_not_restricted_to_one_mib(http_origin, tmp_path):
    url, seen = http_origin
    bodies = BodyStore(tmp_path)
    text = "完整编辑" * 100_000 + "TEXT_TAIL_AFTER_ONE_MIB"
    assert len(text.encode()) > 1024 * 1024
    result = replay_http(request_record(url), {"body_text": text}, bodies)
    assert result["state"] == "replayed"
    assert base64.b64decode(seen[-1]["body_b64"]) == text.encode()
    assert bodies.read_text(result, "request") == text
    raw = b"\x00\xff" * 600_000 + b"BINARY_TAIL_AFTER_ONE_MIB"
    result = replay_http(request_record(url), {"body_b64": base64.b64encode(raw).decode()}, bodies)
    assert result["state"] == "replayed"
    assert base64.b64decode(seen[-1]["body_b64"]) == raw
    assert bodies.read_body(result, "request") == raw


def test_compressed_response_retains_raw_encoding_and_full_decoded_text(http_origin, tmp_path):
    url, seen = http_origin
    bodies = BodyStore(tmp_path)
    raw = b"full-compressed-body-" * 65_000 + b"COMPRESSED_RESPONSE_TAIL"
    result = replay_http(request_record(url + "/compressed-response", raw), {}, bodies)
    assert result["state"] == "replayed"
    assert result["response_body_complete"] is True
    response_raw = bodies.read_body(result, "response")
    response_text = bodies.read_text(result, "response")
    assert gzip.decompress(response_raw).decode() == response_text
    assert base64.b64decode(json.loads(response_text)["body_b64"]) == raw
    assert result["response_body_size"] < 64 * 1024
    assert result["response_preview_truncated"] is True
    assert any(k.lower() == "content-encoding" and v == "gzip" for k, v in result["response_headers"])


def test_interrupted_response_is_explicitly_incomplete_and_keeps_received_bytes(http_origin, tmp_path):
    url, _ = http_origin
    bodies = BodyStore(tmp_path)
    result = replay_http(request_record(url + "/incomplete"), {}, bodies)
    assert result["state"] == "error"
    assert result["status_code"] == 201
    assert result["request_body_complete"] is True
    assert result["response_body_complete"] is False
    assert result["response_truncated"] is True
    assert "complete" in result["response_body_error"]
    assert bodies.read(result["response_body_ref"])


def test_response_disk_failure_is_not_marked_complete(http_origin, tmp_path):
    url, _ = http_origin

    class FailingResponseStore(BodyStore):
        def snapshot(self, prefix, raw, text):
            if prefix == "response":
                raise OSError("disk full while saving response")
            return super().snapshot(prefix, raw, text)

    result = replay_http(request_record(url), {}, FailingResponseStore(tmp_path))
    assert result["state"] == "error"
    assert result["request_body_complete"] is True
    assert result["response_body_complete"] is False
    assert result["response_truncated"] is True
    assert result["response_body_ref"] is None
    assert result["response_body_size"] > 0
    assert "disk full" in result["response_body_error"]


def test_missing_body_file_cannot_silently_replay_preview(tmp_path):
    bodies = BodyStore(tmp_path)
    raw = b"x" * 100_000 + b"FILE_TAIL"
    record = request_record()
    record.update(bodies.snapshot("request", raw, raw.decode()))
    bodies.path(record["request_body_ref"]).unlink()
    with pytest.raises(ValueError, match="完整请求正文"):
        request_parts(record, {}, bodies)
    assert request_parts(record, {"body_text": "explicit replacement"}, bodies)[3] == b"explicit replacement"


def test_file_body_without_store_cannot_silently_replay_preview(tmp_path):
    bodies = BodyStore(tmp_path)
    record = request_record()
    record.update(bodies.snapshot("request", b"x" * 100_000, "x" * 100_000))
    with pytest.raises(ValueError, match="正文存储"):
        request_parts(record, {})


def test_failed_capture_cannot_replay_partial_bytes():
    record = request_record()
    record["request_body_complete"] = False
    with pytest.raises(ValueError, match="截断"):
        request_parts(record, {})


def test_http_text_edit_updates_charset_and_removes_old_compression(http_origin):
    url, seen = http_origin
    record = request_record(url + "/edit", gzip.compress(b"old"))
    record["request_headers"].extend([["Content-Type", "text/plain; charset=gbk"], ["Content-Encoding", "gzip"]])
    result = replay_http(record, {"body_text": "\u4e2d\u6587\u6d4b\u8bd5"})
    assert result["status_code"] == 201
    assert base64.b64decode(seen[0]["body_b64"]) == "\u4e2d\u6587\u6d4b\u8bd5".encode("utf-8")
    assert "charset=\"utf-8\"" in seen[0]["content_type"] or "charset=utf-8" in seen[0]["content_type"]
    assert "gbk" not in seen[0]["content_type"]
    assert seen[0]["content_encoding"] is None


def test_raw_compressed_body_replay_preserves_content_encoding(http_origin):
    url, seen = http_origin
    raw = gzip.compress(b"compressed original")
    record = request_record(url + "/gzip", raw)
    record["request_headers"].append(["Content-Encoding", "gzip"])
    assert replay_http(record, {})["status_code"] == 201
    assert base64.b64decode(seen[0]["body_b64"]) == raw
    assert seen[0]["content_encoding"] == "gzip"


def test_truncated_http_requires_explicit_complete_replacement():
    record = request_record()
    record["request_truncated"] = True
    with pytest.raises(ValueError, match="截断"):
        request_parts(record, {"method": "PUT"})
    assert request_parts(record, {"body_text": "complete replacement"})[3] == b"complete replacement"
    assert request_parts(record, {"body_b64": ""})[3] == b""


def test_empty_saved_binary_body_does_not_use_preview_text():
    record = request_record(body=b"")
    assert request_parts(record, {})[3] == b""


@pytest.mark.parametrize("edits", [
    None, [], {"unknown": True}, {"method": 123}, {"method": "GET\r\nBad: injected"},
    {"url": None}, {"url": "file:///etc/passwd"}, {"url": "http://@example.com/"},
    {"url": "https://example.com/#"}, {"url": "http://example.com:0"},
    {"url": "http://example.com:65536"}, {"url": "http://example.com/a b"},
    {"url": "http://example.com/\npath"}, {"url": "http://evil\\host/"},
    {"headers": [["X-Header", "bad\r\nInjected: value"]]}, {"headers": {"X": "Y"}},
    {"body_text": "x", "body_b64": "eA=="}, {"body_b64": 12}, {"body_b64": "bad!"},
    {"body_text": 12},
])
def test_invalid_http_edits_are_rejected_before_network(edits):
    with pytest.raises(ValueError):
        validate_http_edits(edits)


@pytest.mark.parametrize("protocol", ["TCP", "UDP"])
def test_packet_replay_uses_new_connection_and_receives_echo(protocol):
    payload = b"requestwatch-echo\x00\xff"
    received = []

    class TCPHandler(socketserver.BaseRequestHandler):
        def handle(self):
            body = self.request.recv(65535)
            received.append(body)
            self.request.sendall(body)

    class UDPHandler(socketserver.BaseRequestHandler):
        def handle(self):
            body, connection = self.request
            received.append(body)
            connection.sendto(body, self.client_address)

    server_type = socketserver.ThreadingTCPServer if protocol == "TCP" else socketserver.ThreadingUDPServer
    handler_type = TCPHandler if protocol == "TCP" else UDPHandler
    server = server_type(("127.0.0.1", 0), handler_type)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    record = {"id": "packet-id", "protocol": protocol, "dst_ip": "127.0.0.1", "dst_port": server.server_address[1],
              "payload_hex": payload.hex(), "src_ip": "172.17.0.2", "src_port": 1, "container_id": "old-container"}
    try:
        result = replay_packet(record, {})
        assert result["state"] == "replayed"
        assert result["replay_of"] == "packet-id"
        assert result["attribution"] == "host-replay"
        assert result["container_id"] == ""
        assert result["src_ip"] == "127.0.0.1"
        assert result["src_port"] != 1
        assert result["sent_bytes"] == len(payload)
        assert base64.b64decode(result["response_body_b64"]) == payload
        assert received == [payload]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_truncated_packet_requires_explicit_payload():
    record = {"id": "packet-id", "protocol": "UDP", "dst_ip": "127.0.0.1", "dst_port": 8080,
              "payload_hex": "abcd", "truncated": True}
    with pytest.raises(ValueError, match="截断"):
        replay_packet(record, {})


@pytest.mark.parametrize("edits", [None, [], {"payload_hex": "zz"}, {"payload_hex": ""},
                                   {"payload_hex": None}, {"url": "http://example.com"}])
def test_invalid_packet_edits_are_rejected_before_network(edits):
    with pytest.raises(ValueError):
        replay_packet({"id": "packet-id", "payload_hex": "ab", "dst_ip": "127.0.0.1", "dst_port": 8080,
                       "protocol": "UDP"}, edits)
