import asyncio
import base64
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import urlsplit

import httpx
import pytest

from requestwatch import proxy_addon as addon_module
from requestwatch.proxy import ProxyProcess
from requestwatch.body_store import BodyStore
from requestwatch.proxy_addon import RequestWatchAddon, body_snapshot, edited_request, validate_url


class Headers:
    """Small public-API stand-in so Ubuntu's mitmproxy is optional in unit tests."""
    def __init__(self, fields=()):
        self.fields = list(fields)

    def items(self, multi=False):
        return [(k.decode(), v.decode()) for k, v in self.fields]

    def pop(self, key, default=None):
        found = [v for k, v in self.fields if k.decode().lower() == key.lower()]
        self.fields = [(k, v) for k, v in self.fields if k.decode().lower() != key.lower()]
        return found[0].decode() if found else default

    def __setitem__(self, key, value):
        self.pop(key, None)
        self.fields.append((key.encode(), value.encode()))

    def __getitem__(self, key):
        return next(v.decode() for k, v in self.fields if k.decode().lower() == key.lower())


class Request:
    def __init__(self, raw=b"original\x00binary"):
        self.headers = Headers([(b"Host", b"example.com"), (b"X-Repeat", b"one"),
                                (b"X-Repeat", b"two"), (b"Content-Length", b"15")])
        self.raw_content = raw
        self.method = "POST"
        self.url = "https://example.com/resource"
        self.trailers = None

    @property
    def url(self):
        return self._url

    @url.setter
    def url(self, value):
        self._url = value
        parsed = urlsplit(value)
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (443 if self.scheme == "https" else 80)

    @property
    def host_header(self):
        return self.headers["host"]

    @host_header.setter
    def host_header(self, value):
        self.headers["host"] = value

    def get_text(self, strict=False):
        return self.raw_content.decode("utf-8", "replace")

    @property
    def text(self):
        return self.get_text()

    @text.setter
    def text(self, value):
        self.raw_content = value.encode("utf-8")


def flow():
    return SimpleNamespace(id="flow-1", request=Request(), response=None,
                           metadata={}, client_conn=SimpleNamespace(peername=("172.17.0.2", 40000)),
                           server_conn=SimpleNamespace(peername=None), error=None)


def test_headers_and_url_edits_preserve_full_binary_body():
    request = Request(b"\x00\xff" * 600_000)
    result = edited_request(request, {"url": "http://other.example:8088/new", "headers": [
        ["X-Repeat", "one"], ["X-Repeat", "two"], ["Transfer-Encoding", "chunked"],
        ["Content-Length", "2"]]})
    assert result.raw_content == request.raw_content
    assert result.url == "http://other.example:8088/new"
    assert result.host_header == "other.example:8088"
    assert result.headers["content-length"] == "1200000"
    assert ("X-Repeat", "one") in result.headers.items(multi=True)
    assert ("X-Repeat", "two") in result.headers.items(multi=True)
    assert not any(k.lower() == "transfer-encoding" for k, _ in result.headers.items())
    assert request.host_header == "example.com"


def test_text_and_base64_body_edits_repair_framing():
    request = Request()
    request.headers["Transfer-Encoding"] = "chunked"
    text = edited_request(request, {"body_text": "中文"})
    assert text.raw_content == "中文".encode()
    assert text.headers["content-length"] == "6"
    binary = edited_request(request, {"body_b64": base64.b64encode(b"\x00\xff").decode()})
    assert binary.raw_content == b"\x00\xff"
    assert binary.headers["content-length"] == "2"
    assert edited_request(request, {"body_text": ""}).raw_content == b""
    assert request.raw_content == b"original\x00binary"


@pytest.mark.parametrize("url", ["file:///tmp/file", "https://user:pass@example.com/",
                                 "https://example.com/#secret", "https://example.com/#",
                                 "https://example.com:99999", "http://example.com:0/",
                                 "http://example.com/with space", "http:///missing", "https://evil\\host/"])
def test_invalid_edit_urls_are_rejected(url):
    with pytest.raises(ValueError):
        validate_url(url)


@pytest.mark.parametrize("edits", [{"method": "GET\r\nX: 1"}, {"body_b64": "not valid!"},
                                   {"headers": [["X-Test", "x\r\nInjected: y"]]},
                                   {"body_b64": "", "body_text": ""}])
def test_invalid_edits_leave_live_request_unchanged(edits):
    request = Request()
    with pytest.raises(ValueError):
        edited_request(request, {"url": "https://other.example/", **edits})
    assert request.url == "https://example.com/resource"
    assert request.raw_content == b"original\x00binary"


def test_capture_preview_does_not_truncate_saved_or_live_body(tmp_path):
    import hashlib
    raw = ("完整正文 ".encode("utf-8") * 120_000) + b"TAIL_AFTER_ONE_MIB"
    request = Request(raw)
    bodies = BodyStore(tmp_path)
    result = body_snapshot(request, "request", bodies)
    assert result["request_truncated"] is False
    assert result["request_body_complete"] is True
    assert result["request_preview_truncated"] is True
    assert result["request_body_size"] == len(raw)
    assert len(result["request_body_text"].encode("utf-8")) <= 64 * 1024
    assert not result.get("request_body_b64")
    assert result["request_body_ref"] == hashlib.sha256(raw).hexdigest()
    assert bodies.read_body(result, "request") == raw
    assert bodies.read_text(result, "request").endswith("TAIL_AFTER_ONE_MIB")
    assert request.raw_content == raw


def test_inline_snapshot_does_not_truncate_without_store():
    raw = b"x" * (1024 * 1024 + 7) + b"TAIL"
    result = body_snapshot(Request(raw), "request")
    assert result["request_body_complete"] is True
    assert result["request_truncated"] is False
    assert base64.b64decode(result["request_body_b64"]) == raw
    assert result["request_body_text"].endswith("TAIL")


def test_absent_streamed_body_is_not_reported_as_complete(tmp_path):
    result = body_snapshot(Request(None), "request", BodyStore(tmp_path))
    assert result["request_body_complete"] is False
    assert result["request_truncated"] is True
    assert "unavailable" in result["request_body_error"]


def test_body_storage_failure_keeps_request_forwarding_and_marks_incomplete():
    class UnwritableStore:
        def snapshot(self, *args):
            raise OSError("disk full")

    async def run():
        addon = RequestWatchAddon(body_store=UnwritableStore())
        addon._api = AsyncMock(return_value={"id": "flow-1", "state": "captured"})
        addon._update = AsyncMock()
        item = flow()
        original = item.request
        await addon.request(item)
        await asyncio.gather(*addon._tasks)
        record = addon._api.call_args.args[2]
        assert record["request_body_complete"] is False
        assert record["request_truncated"] is True
        assert record["request_body_ref"] is None
        assert "disk full" in record["request_body_error"]
        assert item.request is original
        assert item.response is None
        assert addon._update.call_args.args[1]["state"] == "forwarded"
    asyncio.run(run())


def test_disk_save_is_not_limited_by_management_api_timeout(tmp_path, monkeypatch):
    import time
    monkeypatch.setattr(addon_module, "API_OUTAGE_SECONDS", 0.01)

    class SlowStore(BodyStore):
        def snapshot(self, *args):
            time.sleep(0.04)
            return super().snapshot(*args)

    async def run():
        bodies = SlowStore(tmp_path)
        addon = RequestWatchAddon(body_store=bodies)
        addon._api = AsyncMock(return_value={"id": "flow-1", "state": "captured"})
        addon._update = AsyncMock()
        item = flow()
        ticks = []

        async def concurrent_work():
            for _ in range(3):
                await asyncio.sleep(0.005)
                ticks.append(1)

        await asyncio.gather(addon.request(item), concurrent_work())
        await asyncio.gather(*addon._tasks)
        record = addon._api.call_args.args[2]
        assert record["request_body_complete"] is True
        assert bodies.read_body(record) == item.request.raw_content
        assert len(ticks) == 3
    asyncio.run(run())


def test_pause_timeout_is_nonblocking_and_releases_original():
    async def run():
        addon = RequestWatchAddon()
        addon._api = AsyncMock(return_value={"decision": None})
        other_work = []

        async def ticker():
            for _ in range(5):
                await asyncio.sleep(0.002)
                other_work.append(1)

        decision, _ = await asyncio.gather(addon.wait_for_decision("test", 0.03), ticker())
        assert decision["action"] == "accept"
        assert "timed out" in decision["reason"]
        assert len(other_work) == 5
    asyncio.run(run())


def test_management_outage_has_bounded_fail_open(monkeypatch):
    monkeypatch.setattr(addon_module, "API_OUTAGE_SECONDS", 0.02)
    monkeypatch.setattr(addon_module, "POLL_SECONDS", 0.002)

    async def run():
        addon = RequestWatchAddon()
        addon._api = AsyncMock(side_effect=httpx.ConnectError("offline"))
        decision = await asyncio.wait_for(addon.wait_for_decision("test", 10), timeout=0.2)
        assert decision["action"] == "accept"
        assert "API unavailable" in decision["reason"]
    asyncio.run(run())


def test_pending_drop_returns_local_response_and_response_hook_keeps_dropped(monkeypatch):
    monkeypatch.setattr(addon_module, "http", SimpleNamespace(Response=SimpleNamespace(
        make=lambda status, body, headers: SimpleNamespace(status_code=status))))

    async def run():
        addon = RequestWatchAddon()
        addon._api = AsyncMock(side_effect=[{"id": "flow-1", "state": "pending", "timeout_seconds": 1},
                                           {"decision": {"action": "drop"}}])
        addon._update = AsyncMock()
        item = flow()
        await addon.request(item)
        await asyncio.gather(*addon._tasks)
        assert item.response.status_code == 499
        assert item.metadata["rw_dropped"] is True
        assert addon._update.call_args.args[1]["state"] == "dropped"
        await addon.response(item)
        assert addon._update.call_count == 1
        assert item.request.raw_content == b"original\x00binary"
    asyncio.run(run())


def test_api_failure_during_ingest_preserves_original():
    async def run():
        addon = RequestWatchAddon()
        addon._api = AsyncMock(side_effect=httpx.ConnectError("offline"))
        item = flow()
        original = item.request
        await addon.request(item)
        assert item.request is original
        assert item.response is None
        # A lost acknowledgement may follow a committed ingest. Retain the ID
        # for a later final update while preserving the original request unchanged.
        assert item.metadata["rw_id"] == item.id
    asyncio.run(run())


def test_management_endpoint_is_excluded():
    async def run():
        addon = RequestWatchAddon(api_url="http://127.0.0.1:7030")
        addon._api = AsyncMock()
        item = flow()
        item.request.url = "http://localhost:7030/api/internal/ingest"
        await addon.request(item)
        addon._api.assert_not_called()
        assert item.metadata["rw_skip"] is True
    asyncio.run(run())


def test_proxy_missing_binary_is_reported_without_crashing(tmp_path, monkeypatch):
    config = SimpleNamespace(proxy_enabled=True, proxy_host="127.0.0.1", proxy_port=8080,
                             port=7030, token="example-test-token", data_dir=tmp_path, proxy_auth="")
    process = ProxyProcess(config)
    monkeypatch.setattr(process, "_executable", lambda: None)
    status = process.start()
    assert status["running"] is False
    assert "mitmdump is unavailable" in status["error"]
    assert "token" not in status
    process.stop()


def test_real_mitmproxy_preserves_compression_and_repeated_headers(tmp_path):
    mitm_http = pytest.importorskip("mitmproxy.http")
    import gzip
    request = mitm_http.Request.make("POST", "https://example.com/old", content=b"old",
                                     headers={"Content-Type": "text/plain; charset=utf-8"})
    request.headers["content-encoding"] = "gzip"
    decoded = b"old compressed body" * 80_000 + b"COMPRESSED_TAIL_AFTER_ONE_MIB"
    request.content = decoded
    request.headers.add("X-Repeat", "one")
    request.headers.add("X-Repeat", "two")
    original = request.raw_content
    bodies = BodyStore(tmp_path)
    snapshot = body_snapshot(request, "request", bodies)
    assert len(original) < 64 * 1024
    assert len(decoded) > 1024 * 1024
    assert snapshot["request_body_complete"] is True
    assert snapshot["request_truncated"] is False
    assert snapshot["request_preview_truncated"] is True
    assert bodies.read_body(snapshot) == original
    assert bodies.read_text(snapshot, "request").encode() == decoded
    unchanged = edited_request(request, {"url": "https://new.example/new"})
    assert unchanged.raw_content == original
    assert unchanged.host_header == "new.example"
    assert unchanged.headers.get_all("X-Repeat") == ["one", "two"]
    changed = edited_request(request, {"body_text": "modified compressed body"})
    assert gzip.decompress(changed.raw_content) == b"modified compressed body"
    assert changed.headers["content-length"] == str(len(changed.raw_content))
    assert request.raw_content == original


def test_real_mitmproxy_decode_failure_preserves_raw_bytes(tmp_path):
    mitm_http = pytest.importorskip("mitmproxy.http")
    raw = b"not-a-valid-gzip-stream"
    request = mitm_http.Request.make("POST", "https://example.com/bad-compression", content=raw)
    request.headers["content-encoding"] = "gzip"
    bodies = BodyStore(tmp_path)
    result = body_snapshot(request, "request", bodies)
    assert result["request_body_complete"] is True
    assert result["request_body_binary"] is True
    assert result["request_body_decode_error"]
    assert bodies.read_body(result) == raw


@pytest.mark.parametrize("use_tls", [False, True])
def test_live_proxy_roundtrip(tmp_path, use_tls, monkeypatch):
    """Opt-in real mitmdump test: RW_RUN_PROXY_INTEGRATION=1 python -m pytest ...

    Runs only on loopback, using ephemeral HTTP origin/API servers. No Docker,
    firewall changes, external network, or trusted-CA installation is needed.
    """
    import json
    import os
    import socket
    import ssl
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlsplit

    if os.getenv("RW_RUN_PROXY_INTEGRATION") != "1":
        pytest.skip("Set RW_RUN_PROXY_INTEGRATION=1 to launch real mitmdump")
    records = {}
    seen = []
    expected_token = "integration-test-token"
    large_body = b"captured-full-body-" * 70_000 + b"TAIL_AFTER_ONE_MIB"
    bodies = BodyStore(tmp_path)

    class QuietHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, value):
            body = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def read_json(self):
            return json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))

    class Management(QuietHandler):
        def authorized(self):
            if self.headers.get("Authorization") != "Bearer " + expected_token:
                self.reply(401, {"error": "authentication required"})
                return False
            return True

        def do_POST(self):
            if not self.authorized():
                return
            record = self.read_json()
            record["state"] = "pending" if urlsplit(record["url"]).path in {"/edit", "/drop"} else "captured"
            records[record["id"]] = record
            self.reply(200, {"id": record["id"], "state": record["state"], "timeout_seconds": 1})

        def do_GET(self):
            if not self.authorized():
                return
            record = records[self.path.rsplit("/", 1)[1]]
            decision = {"action": "drop"} if urlsplit(record["url"]).path == "/drop" else {
                "action": "accept", "edits": {"method": "POST", "body_text": "edited payload"}}
            self.reply(200, {"decision": decision})

        def do_PUT(self):
            if not self.authorized():
                return
            records[self.path.rsplit("/", 1)[1]].update(self.read_json())
            self.reply(200, {"ok": True})

    class Origin(QuietHandler):
        def do_GET(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            seen.append({"method": self.command, "path": self.path, "body": body.decode()})
            self.reply(200, seen[-1])

        do_POST = do_GET

    api = ThreadingHTTPServer(("127.0.0.1", 0), Management)
    origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    if use_tls:
        context = tls_origin_context(tmp_path)
        origin.socket = context.wrap_socket(origin.socket, server_side=True)
    api_thread = threading.Thread(target=api.serve_forever, daemon=True)
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    api_thread.start()
    origin_thread.start()
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        proxy_port = reservation.getsockname()[1]
    config = SimpleNamespace(proxy_enabled=True, proxy_host="127.0.0.1", proxy_port=proxy_port,
                             port=api.server_port, token=expected_token, data_dir=tmp_path,
                             proxy_auth="tester:password")
    process = ProxyProcess(config)
    try:
        assert process.start()["running"], process.status()
        deadline = time.monotonic() + 20
        while True:
            try:
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=0.1):
                    break
            except OSError:
                if time.monotonic() >= deadline or not process.status()["running"]:
                    pytest.fail("Proxy did not start: " + (tmp_path / "proxy.log").read_text())
                time.sleep(0.05)
        scheme = "https" if use_tls else "http"
        origin_url = f"{scheme}://127.0.0.1:{origin.server_port}"
        verification = ssl.create_default_context(cafile=str(tmp_path / "mitmproxy" / "mitmproxy-ca-cert.pem")) if use_tls else True
        with httpx.Client(proxy=f"http://127.0.0.1:{proxy_port}", trust_env=False, timeout=5,
                          verify=verification) as client:
            if use_tls:
                with pytest.raises(httpx.ProxyError, match="407"):
                    client.get(origin_url + "/unauthenticated")
            else:
                assert client.get(origin_url + "/unauthenticated").status_code == 407
        with httpx.Client(proxy=f"http://tester:password@127.0.0.1:{proxy_port}", trust_env=False,
                          timeout=5, verify=verification) as client:
            assert client.get(origin_url + "/capture").json()["path"] == "/capture"
            edited = client.get(origin_url + "/edit").json()
            assert edited == {"method": "POST", "path": "/edit", "body": "edited payload"}
            assert client.get(origin_url + "/drop").status_code == 499
            large_response = client.post(origin_url + "/large", content=large_body)
            assert large_response.json()["body"].encode() == large_body
        deadline = time.monotonic() + 5
        while not (len(records) == 4 and all(r.get("status_code") and not r.get("http_in_flight") for r in records.values())):
            if time.monotonic() >= deadline:
                pytest.fail("Missing capture updates: " + repr(records))
            time.sleep(0.02)
        assert [r["path"] for r in seen] == ["/capture", "/edit", "/large"]
        dropped = next(r for r in records.values() if urlsplit(r["url"]).path == "/drop")
        assert dropped["state"] == "dropped"
        assert dropped["status_code"] == 499
        captured = next(r for r in records.values() if urlsplit(r["url"]).path == "/capture")
        assert captured["response_body_text"]
        assert captured["state"] == "forwarded"
        assert captured["protocol"] == ("HTTPS" if use_tls else "HTTP")
        large = next(r for r in records.values() if urlsplit(r["url"]).path == "/large")
        assert large["request_body_complete"] is True
        assert large["response_body_complete"] is True
        assert large["request_truncated"] is False
        assert large["response_truncated"] is False
        assert large["request_preview_truncated"] is True
        assert large["response_preview_truncated"] is True
        assert len(large["request_body_text"].encode()) <= 64 * 1024
        assert bodies.read_body(large, "request") == large_body
        assert bodies.read_body(large, "response") == large_response.content
        assert json.loads(bodies.read_text(large, "response"))["body"].encode() == large_body
        from requestwatch.replay import replay_http
        original_client = httpx.Client
        with monkeypatch.context() as patch:
            if use_tls:
                trusted = ssl.create_default_context(cafile=str(tmp_path / "origin-ca.pem"))
                patch.setattr(httpx, "Client", lambda *args, **kwargs: original_client(*args, **kwargs, verify=trusted))
            replayed = replay_http(large, {}, bodies)
        assert replayed["state"] == "replayed", replayed.get("error")
        assert replayed["response_body_complete"] is True
        assert seen[-1]["body"].encode() == large_body
        assert bodies.read_body(replayed, "request") == large_body
        assert json.loads(bodies.read_text(replayed, "response"))["body"].encode() == large_body
    finally:
        process.stop()
        api.shutdown()
        origin.shutdown()
        api.server_close()
        origin.server_close()
        api_thread.join(timeout=2)
        origin_thread.join(timeout=2)


def test_late_forward_notification_cannot_overwrite_upstream_error():
    async def run():
        addon = RequestWatchAddon()
        addon._api = AsyncMock(return_value={"id": "flow-1", "state": "captured"})
        states = []

        async def delayed_update(record_id, changes):
            if changes["state"] == "forwarded":
                await asyncio.sleep(0.02)
            states.append(changes["state"])

        addon._update = delayed_update
        item = flow()
        await addon.request(item)
        item.error = "Connection refused"
        await addon.error(item)
        await asyncio.gather(*addon._tasks)
        assert states == ["forwarded", "error"]
    asyncio.run(run())


def test_proxy_child_uses_configured_token_and_ipv6_api_host(tmp_path, monkeypatch):
    from requestwatch import proxy as process_module
    captured = {}

    class Child:
        pid = 1234
        returncode = None

        def __init__(self, command, **kwargs):
            captured.update(command=command, **kwargs)

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = 0

        def wait(self, timeout):
            return self.returncode

    config = SimpleNamespace(proxy_enabled=True, proxy_host="127.0.0.1", proxy_port=8080,
                             host="::", port=7030, token="configured-private-token",
                             data_dir=tmp_path, proxy_auth="tester:password")
    process = ProxyProcess(config)
    monkeypatch.setattr(process, "_executable", lambda: "mitmdump")
    monkeypatch.setattr(process_module.subprocess, "Popen", Child)
    monkeypatch.setenv("RW_TOKEN", "wrong-inherited-token")
    try:
        assert process.start()["running"] is True
        assert captured["env"]["RW_TOKEN"] == "configured-private-token"
        assert captured["env"]["RW_API_URL"] == "http://[::1]:7030"
        assert "configured-private-token" not in " ".join(captured["command"])
        assert "proxyauth=tester:password" in captured["command"]
        assert captured["env"]["RW_DATA_DIR"] == str(tmp_path.resolve())
    finally:
        process.stop()
    assert process.status()["running"] is False


def tls_origin_context(tmp_path):
    """Create a private test CA and trusted local TLS origin; no system CA edits."""
    import datetime
    import ipaddress
    import ssl
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RequestWatch test CA")])
    ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
               .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=1))
               .not_valid_after(now + datetime.timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
               .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False,
                                            key_cert_sign=True, crl_sign=True, content_commitment=False,
                                            data_encipherment=False, key_agreement=False,
                                            encipher_only=False, decipher_only=False), critical=True)
               .sign(ca_key, hashes.SHA256()))
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    leaf_cert = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(ca_name)
                 .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
                 .not_valid_before(now - datetime.timedelta(minutes=1))
                 .not_valid_after(now + datetime.timedelta(days=1))
                 .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                 .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
                 .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                 .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False,
                                              key_cert_sign=False, crl_sign=False, content_commitment=False,
                                              data_encipherment=False, key_agreement=False,
                                              encipher_only=False, decipher_only=False), critical=True)
                 .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                 .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                 .sign(ca_key, hashes.SHA256()))
    ca_path = tmp_path / "origin-ca.pem"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_path, key_path = tmp_path / "origin.pem", tmp_path / "origin-key.pem"
    cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
    confdir = tmp_path / "mitmproxy"
    confdir.mkdir(exist_ok=True)
    (confdir / "config.yaml").write_text("ssl_verify_upstream_trusted_ca: '" + ca_path.as_posix() + "'\n", encoding="utf-8")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path), str(key_path))
    return context
