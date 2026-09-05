import base64
import gzip
import json
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from requestwatch.replay import replay_http, replay_packet, request_parts, validate_http_edits


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
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
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
    assert [v for k, v in result["response_headers"] if k.lower() == "set-cookie"] == ["one=1", "two=2"]
    assert json.loads(result["response_body_text"])["path"] == "/replay"
    assert base64.b64decode(result["response_body_b64"]).decode() == result["response_body_text"]


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
