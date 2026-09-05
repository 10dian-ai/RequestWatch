"""mitmdump addon: capture HTTP(S), await decisions without blocking other flows.

Loaded directly with ``mitmdump -s``. Keep this module independent from the web
application: mitmdump may live in its own virtual environment.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import copy
import logging
import importlib.util
from pathlib import Path
import os
import re
import time
import tempfile
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

try:
    from mitmproxy import http
    from mitmproxy.net.http.headers import infer_content_encoding
except ImportError:  # Pure edit and timeout helpers are testable without mitmproxy.
    http = None
    infer_content_encoding = None

# mitmdump executes this file as an independent module in its own venv.
# Load the adjacent stdlib-only body store without importing the web application.
if __package__ == "requestwatch":
    from .body_store import BodyStore
else:
    _body_spec = importlib.util.spec_from_file_location(
        "requestwatch_body_store", Path(__file__).with_name("body_store.py"))
    _body_module = importlib.util.module_from_spec(_body_spec)
    _body_spec.loader.exec_module(_body_module)
    BodyStore = _body_module.BodyStore

PREVIEW_BYTES = 64 * 1024
API_OUTAGE_SECONDS = 3.0
POLL_SECONDS = 0.20
HEARTBEAT_SECONDS = 10.0
TOKEN_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
log = logging.getLogger("requestwatch.proxy")


def safe_text(value: str) -> str:
    """JSON/SQLite cannot encode surrogate-escaped bytes from HTTP headers."""
    return value.encode("utf-8", "replace").decode("utf-8")


def header_pairs(headers: Any) -> list[list[str]]:
    return [[safe_text(k), safe_text(v)] for k, v in headers.items(multi=True)]


def body_snapshot(message: Any, prefix: str, body_store: Any = None) -> dict[str, Any]:
    """Save complete raw and decoded bodies; only metadata carries a preview."""
    raw = message.raw_content
    if raw is None:
        return failed_body_snapshot(message, prefix, "Body unavailable (streamed or incomplete capture)")
    decode_error = None
    try:
        content_type = next((v for k, v in header_pairs(message.headers) if k.lower() == "content-type"), "")
        if "text/event-stream" in content_type.lower():
            # SSE is always UTF-8, including when no charset is declared. mitmproxy's
            # general text fallback is latin-1 and would corrupt Chinese SSE text.
            content = message.get_content(strict=True) if hasattr(message, "get_content") else raw
            text = (content or b"").decode("utf-8-sig")
        else:
            text = message.get_text(strict=True) or ""
    except (ValueError, LookupError) as exc:
        decode_error = safe_text(str(exc))
        try:
            text = message.get_text(strict=False) or ""
        except (ValueError, LookupError):
            text = raw.decode("utf-8", "replace")
    binary = decode_error is not None or "\x00" in text or "\ufffd" in text or any(0xDC80 <= ord(c) <= 0xDCFF for c in text)
    text = safe_text(text)
    if body_store is not None:
        result = body_store.snapshot(prefix, raw, text)
    else:
        # Compatibility for old inline records and pure helper callers. Production
        # always supplies RW_DATA_DIR, so complete bodies are stored as files.
        result = {
            f"{prefix}_body_b64": base64.b64encode(raw).decode("ascii"),
            f"{prefix}_body_text": text,
            f"{prefix}_body_size": len(raw),
            f"{prefix}_text_size": len(text.encode("utf-8")),
            f"{prefix}_body_complete": True,
            f"{prefix}_truncated": False,
            f"{prefix}_preview_truncated": False,
        }
    result[f"{prefix}_body_binary"] = binary
    result[f"{prefix}_body_error"] = None
    result[f"{prefix}_body_decode_error"] = decode_error
    result[f"{prefix}_sse_utf8"] = decode_error is None and "text/event-stream" in content_type.lower()
    return result


def failed_body_snapshot(message: Any, prefix: str, error: str) -> dict[str, Any]:
    """Never pass a failed disk write or absent body off as complete capture."""
    raw = message.raw_content or b""
    preview = raw[:PREVIEW_BYTES].decode("utf-8", "replace")
    return {
        f"{prefix}_body_ref": None, f"{prefix}_text_ref": None,
        f"{prefix}_body_b64": base64.b64encode(raw[:PREVIEW_BYTES]).decode("ascii"),
        f"{prefix}_body_text": preview, f"{prefix}_body_size": len(raw),
        f"{prefix}_text_size": None, f"{prefix}_body_complete": False,
        f"{prefix}_truncated": True, f"{prefix}_preview_truncated": len(raw) > PREVIEW_BYTES,
        f"{prefix}_body_binary": "\x00" in preview or "\ufffd" in preview,
        f"{prefix}_body_error": safe_text(error),
    }


def validate_url(value: Any) -> str:
    if not isinstance(value, str) or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise ValueError("URL must be an HTTP(S) URL without whitespace")
    parsed = urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment or "#" in value or "\\" in value):
        raise ValueError("Only HTTP(S) URLs with a host and no credentials or fragment are supported")
    port = parsed.port  # Also validates malformed/out-of-range ports.
    if port is not None and port < 1:
        raise ValueError("URL port must be between 1 and 65535")
    return value


def validate_headers(value: Any) -> list[tuple[bytes, bytes]]:
    if not isinstance(value, list):
        raise ValueError("Headers must be a list of name/value pairs")
    result = []
    for pair in value:
        if (not isinstance(pair, (list, tuple)) or len(pair) != 2
                or not all(isinstance(v, str) for v in pair)):
            raise ValueError("Each header must contain two strings")
        name, content = pair
        if not TOKEN_RE.fullmatch(name) or any(c in content for c in "\r\n\x00"):
            raise ValueError("Invalid header name or value")
        result.append((name.encode("ascii"), content.encode("utf-8")))
    return result


def edited_request(request: Any, edits: dict[str, Any]) -> Any:
    """Return an edited copy, leaving the live request untouched on any error.

    body_b64 represents raw bytes, including any chosen Content-Encoding.
    body_text is decoded text and is re-encoded by mitmproxy. Omitting both
    preserves the original complete binary body, including truncated captures.
    """
    if not isinstance(edits, dict):
        raise ValueError("Edits must be an object")
    if "body_text" in edits and "body_b64" in edits:
        raise ValueError("Specify either body_text or body_b64, not both")
    if "method" in edits and (not isinstance(edits["method"], str)
                              or not TOKEN_RE.fullmatch(edits["method"])):
        raise ValueError("Invalid HTTP method")
    if "url" in edits:
        validate_url(edits["url"])
    fields = validate_headers(edits["headers"]) if "headers" in edits else None
    raw = None
    if "body_b64" in edits:
        try:
            raw = base64.b64decode(edits["body_b64"], validate=True)
        except (ValueError, TypeError, binascii.Error) as exc:
            raise ValueError("Invalid base64 body") from exc
    if "body_text" in edits and not isinstance(edits["body_text"], str):
        raise ValueError("body_text must be a string")
    changed = copy.deepcopy(request)
    if fields is not None:
        changed.headers = type(request.headers)(fields)
    if "method" in edits:
        changed.method = edits["method"]
    if "url" in edits:
        changed.url = edits["url"]
        changed.host_header = urlsplit(edits["url"]).netloc
    body_changed = "body_b64" in edits or "body_text" in edits
    if fields is not None or body_changed:
        for header in ("content-length", "transfer-encoding", "trailer"):
            changed.headers.pop(header, None)
        changed.trailers = None
    if "body_b64" in edits:
        changed.raw_content = raw
    elif "body_text" in edits:
        changed.text = edits["body_text"]
    if (fields is not None or body_changed) and changed.raw_content is not None:
        changed.headers["content-length"] = str(len(changed.raw_content))
    return changed


class ResponseCapture:
    """A lossless tee: append encoded body bytes, return precisely the input chunk."""
    def __init__(self, body_store):
        self.body_store = body_store
        fd, name = tempfile.mkstemp(prefix=".stream-", dir=body_store.root)
        self.path = Path(name)
        self.output = os.fdopen(fd, "wb", buffering=0)
        self.size = 0
        self.received = 0
        self.error = None
        self.last_snapshot = None
        self.stop = asyncio.Event()
        self.task = None

    def feed(self, chunk):
        self.received += len(chunk)
        if chunk and self.error is None:
            try:
                written = self.output.write(chunk)
                self.size += written
                if written != len(chunk):
                    raise OSError("Short write while saving streamed response")
            except OSError as exc:
                self.error = str(exc)
                log.warning("Could not save streamed response: %s", exc)
        return chunk

    def close(self):
        self.output.close()
        self.path.unlink(missing_ok=True)


class RequestWatchAddon:
    def __init__(self, api_url: str | None = None, token: str | None = None,
                 client: Any = None, body_store: Any = None):
        self.api_url = (api_url or os.getenv("RW_API_URL", "http://127.0.0.1:7030")).rstrip("/")
        self.token = token if token is not None else os.getenv("RW_TOKEN", "")
        self.client = client
        self.body_store = body_store
        self.data_dir = os.getenv("RW_DATA_DIR")
        self._tasks: set[asyncio.Task] = set()
        self._updates: dict[str, asyncio.Task] = {}
        self._streams: dict[str, ResponseCapture] = {}
        self._active_flows: dict[str, str] = {}
        self._heartbeat_task = None
        self._heartbeat_wake = asyncio.Event()

    async def _snapshot(self, message: Any, prefix: str) -> dict[str, Any]:
        def save():
            if self.body_store is None and self.data_dir:
                self.body_store = BodyStore(self.data_dir)
            return body_snapshot(message, prefix, self.body_store)

        try:
            # Disk I/O and full-body decoding must neither block concurrent flows
            # nor inherit the management API's three-second outage timeout.
            return await asyncio.to_thread(save)
        except (OSError, ValueError, UnicodeError) as exc:
            log.warning("Could not save complete %s body: %s; forwarding remains available", prefix, exc)
            return failed_body_snapshot(message, prefix, f"Could not save complete body: {exc}")

    async def _api(self, method: str, path: str, data: dict | None = None,
                   timeout: float = API_OUTAGE_SECONDS) -> dict:
        if self.client is None:
            self.client = httpx.AsyncClient(trust_env=False, follow_redirects=False)
        response = await self.client.request(
            method, self.api_url + path, json=data,
            headers={"Authorization": f"Bearer {self.token}"}, timeout=timeout,
        )
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Invalid RequestWatch API response")
        return result

    def _is_internal(self, flow: Any) -> bool:
        target = urlsplit(self.api_url)
        hosts = {target.hostname}
        if target.hostname in {"127.0.0.1", "localhost", "::1"}:
            hosts.update({"127.0.0.1", "localhost", "::1"})
        return flow.request.host in hosts and flow.request.port == (target.port or (443 if target.scheme == "https" else 80))

    def _track(self, flow_id, record_id):
        self._active_flows[flow_id] = record_id
        if self._heartbeat_task is None or self._heartbeat_task.done():
            self._heartbeat_task = asyncio.create_task(self._heartbeat())

    def _untrack(self, flow_id):
        self._active_flows.pop(flow_id, None)
        if not self._active_flows:
            self._heartbeat_wake.set()

    async def _heartbeat(self):
        while self._active_flows:
            self._heartbeat_wake.clear()
            try:
                await asyncio.wait_for(self._heartbeat_wake.wait(), timeout=HEARTBEAT_SECONDS)
            except asyncio.TimeoutError:
                pass
            ids = list(set(self._active_flows.values()))
            for offset in range(0, len(ids), 500):
                try:
                    await asyncio.wait_for(self._api("POST", "/api/internal/heartbeat",
                        {"record_ids": ids[offset:offset+500]}), timeout=API_OUTAGE_SECONDS)
                except (httpx.HTTPError, ValueError, OSError, asyncio.TimeoutError):
                    # The server lease expires honestly during a prolonged outage.
                    # A quiet live request must not otherwise expire merely for idling.
                    log.debug("Could not renew RequestWatch active-flow leases")

    async def _update(self, record_id: str, changes: dict) -> None:
        terminal = changes.get("http_in_flight") is False
        attempts = 3 if terminal else 1
        for attempt in range(attempts):
            try:
                await asyncio.wait_for(
                    self._api("PUT", f"/api/internal/records/{quote(record_id, safe='')}", changes),
                    timeout=API_OUTAGE_SECONDS)
                return
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code < 500 and exc.response.status_code != 429:
                    break  # Authentication failure or an absent/evicted record is definitive.
            except (httpx.HTTPError, ValueError, OSError, asyncio.TimeoutError):
                pass
            if attempt+1 < attempts:
                await asyncio.sleep(.2 * (attempt+1))
        log.warning("Could not update a RequestWatch record after %s attempt(s)", attempts)

    def _update_later(self, record_id: str, changes: dict) -> None:
        # A down management API must never add another delay before forwarding.
        previous = self._updates.get(record_id)

        async def ordered_update():
            if previous is not None:
                await previous
            await self._update(record_id, changes)

        task = asyncio.create_task(ordered_update())
        self._tasks.add(task)
        self._updates[record_id] = task

        def completed(done):
            self._tasks.discard(done)
            if self._updates.get(record_id) is done:
                self._updates.pop(record_id, None)

        task.add_done_callback(completed)

    async def wait_for_decision(self, record_id: str, timeout_seconds: float) -> dict:
        deadline = time.monotonic() + max(0.0, timeout_seconds)
        outage_start = None
        while time.monotonic() < deadline:
            now = time.monotonic()
            remaining = deadline - now
            if outage_start is not None:
                remaining = min(remaining, API_OUTAGE_SECONDS - (now - outage_start))
            if remaining <= 0:
                break
            call_start = time.monotonic()
            try:
                payload = await asyncio.wait_for(
                    self._api("GET", f"/api/internal/decision/{quote(record_id, safe='')}",
                              timeout=min(API_OUTAGE_SECONDS, remaining)),
                    timeout=min(API_OUTAGE_SECONDS, remaining),
                )
                outage_start = None
                decision = payload.get("decision")
                if isinstance(decision, dict) and decision.get("action") in {"accept", "drop"}:
                    return decision
            except (httpx.HTTPError, ValueError, OSError, asyncio.TimeoutError):
                if outage_start is None:
                    outage_start = call_start
                if time.monotonic() - outage_start >= API_OUTAGE_SECONDS:
                    return {"action": "accept", "reason": "API unavailable; original request released"}
            remaining = deadline - time.monotonic()
            if outage_start is not None:
                remaining = min(remaining, API_OUTAGE_SECONDS - (time.monotonic() - outage_start))
            if remaining > 0:
                await asyncio.sleep(min(POLL_SECONDS, remaining))
        reason = "API unavailable" if outage_start is not None else "Interception timed out"
        return {"action": "accept", "reason": reason + "; original request released"}

    @staticmethod
    def _search_text(request: Any, snapshot: dict) -> str:
        headers = "\n".join(f"{k}: {v}" for k, v in header_pairs(request.headers))
        return safe_text(f"{request.method} {request.url}\n{headers}\n{snapshot['request_body_text']}")

    async def request(self, flow: Any) -> None:
        if self._is_internal(flow) or flow.response is not None:
            flow.metadata["rw_skip"] = True
            return
        flow.metadata["rw_start"] = time.monotonic()
        request = flow.request
        src = flow.client_conn.peername or ("", 0)
        dst = flow.server_conn.peername or (request.host, request.port)
        snapshot = await self._snapshot(request, "request")
        record = {
            "id": flow.id, "source": "http", "protocol": request.scheme.upper(),
            "created_at": time.time(), "src_ip": src[0], "src_port": src[1],
            "dst_ip": dst[0], "dst_port": dst[1], "method": request.method,
            "url": safe_text(request.url), "request_headers": header_pairs(request.headers),
            "http_version": safe_text(getattr(request, "http_version", "HTTP/1.1")),
            "request_trailers": header_pairs(request.trailers) if getattr(request, "trailers", None) is not None else [],
            "summary": safe_text(f"{request.method} {request.url}"), "state": "captured",
            "http_in_flight": True,
            "payload_text": self._search_text(request, snapshot), **snapshot,
        }
        # A timed-out POST may already have committed. Keep the known record ID
        # so subsequent response/error updates can still complete that same record.
        flow.metadata["rw_id"] = flow.id
        flow.metadata["rw_payload"] = record["payload_text"]
        self._track(flow.id, flow.id)
        try:
            result = await asyncio.wait_for(
                self._api("POST", "/api/internal/ingest", record), API_OUTAGE_SECONDS)
        except (httpx.HTTPError, ValueError, OSError, asyncio.TimeoutError):
            log.warning("RequestWatch API unavailable; allowing original request")
            return
        record_id = str(result.get("id", flow.id))
        flow.metadata["rw_id"] = record_id
        self._track(flow.id, record_id)
        flow.metadata["rw_payload"] = record["payload_text"]
        decision = {"action": "accept"}
        if result.get("state") == "pending":
            try:
                duration = min(3600.0, max(0.0, float(result.get("timeout_seconds", 30))))
            except (TypeError, ValueError):
                duration = 30.0
            decision = await self.wait_for_decision(record_id, duration)
        if decision["action"] == "drop":
            if http is None:
                raise RuntimeError("mitmproxy is required to drop HTTP requests")
            flow.metadata["rw_dropped"] = True
            self._untrack(flow.id)
            flow.response = http.Response.make(
                499, b"Request dropped by RequestWatch\n", {"Content-Type": "text/plain; charset=utf-8"})
            self._update_later(record_id, {"state": "dropped", "status_code": 499, "http_in_flight": False})
            return
        changes: dict[str, Any] = {"state": "forwarded"}
        if decision.get("reason"):
            changes["intercept_note"] = decision["reason"]
        if decision.get("edits"):
            try:
                flow.request = edited_request(flow.request, decision["edits"])
                snapshot = await self._snapshot(flow.request, "request")
                changes.update({"method": flow.request.method, "url": flow.request.url,
                                "summary": f"{flow.request.method} {flow.request.url}",
                                "request_headers": header_pairs(flow.request.headers),
                                "request_trailers": header_pairs(flow.request.trailers) if getattr(flow.request, "trailers", None) is not None else [],
                                **snapshot})
                flow.metadata["rw_payload"] = self._search_text(flow.request, snapshot)
                changes["payload_text"] = flow.metadata["rw_payload"]
            except (ValueError, TypeError, UnicodeError) as exc:
                changes["intercept_note"] = f"Edits rejected; original request released: {exc}"
        self._update_later(record_id, changes)

    @staticmethod
    def _response_fields(flow):
        response = flow.response
        headers = header_pairs(response.headers)
        return {"status_code": response.status_code, "response_headers": headers,
                "response_http_version": safe_text(getattr(response, "http_version", "HTTP/1.1")),
                "response_trailers": header_pairs(response.trailers) if getattr(response, "trailers", None) is not None else []}

    async def responseheaders(self, flow: Any) -> None:
        if flow.metadata.get("rw_skip") or "rw_id" not in flow.metadata or flow.metadata.get("rw_dropped") or flow.response is None:
            return
        # Do not claim to capture a WebSocket conversation after its HTTP upgrade.
        if flow.response.status_code == 101:
            return
        try:
            if self.body_store is None and self.data_dir:
                self.body_store = BodyStore(self.data_dir)
            if self.body_store is None:
                return  # Legacy standalone/test callers retain the inline buffered path.
            capture = ResponseCapture(self.body_store)
        except OSError as exc:
            flow.metadata["rw_stream_error"] = str(exc)
            flow.response.stream = True  # Capture failure must not stall the client.
            return
        self._streams[flow.id] = capture
        flow.response.stream = capture.feed
        self._update_later(flow.metadata["rw_id"], {
            **self._response_fields(flow), "http_in_flight": True,
            "response_streaming": True, "response_body_complete": False,
            "response_truncated": False, "response_body_text": "", "response_body_size": 0,
        })

        async def publish_periodically():
            last_size = -1
            while not capture.stop.is_set():
                size = capture.size
                if size != last_size:
                    snapshot = await self._stream_snapshot(flow, capture, size, False)
                    self._update_later(flow.metadata["rw_id"], self._stream_changes(flow, snapshot, False))
                    # Coalesce while the management API is slow; never accumulate
                    # an unbounded queue of obsolete body snapshots for one stream.
                    pending = self._updates.get(flow.metadata["rw_id"])
                    if pending is not None:
                        await pending
                    last_size = size
                try:
                    await asyncio.wait_for(capture.stop.wait(), timeout=1.0)
                except asyncio.TimeoutError:
                    pass
        capture.task = asyncio.create_task(publish_periodically())

    async def _stream_snapshot(self, flow, capture, size, complete):
        headers = {k.lower(): v for k, v in header_pairs(flow.response.headers)}
        try:
            snapshot = await asyncio.to_thread(
                capture.body_store.snapshot_file, "response", capture.path, size=size,
                complete=complete and capture.error is None,
                content_type=headers.get("content-type", ""),
                content_encoding=headers.get("content-encoding", ""),
                infer_encoding=infer_content_encoding)
            if capture.error:
                snapshot.update(response_body_complete=False, response_truncated=True,
                                response_body_error="Could not save every response byte: " + capture.error,
                                response_received_size=capture.received)
            capture.last_snapshot = dict(snapshot)
            return snapshot
        except (OSError, ValueError, UnicodeError) as exc:
            capture.error = str(exc)
            if capture.last_snapshot is not None:
                # A failed newer write must not erase the last successfully saved
                # prefix from the record. Its references remain useful for diagnosis.
                result = dict(capture.last_snapshot)
                result.update(response_body_complete=False, response_truncated=True,
                              response_body_error="Could not save every response byte: " + str(exc))
            else:
                result = failed_body_snapshot(flow.response, "response", "Could not save streamed body: " + str(exc))
            result["response_received_size"] = capture.received
            return result

    def _stream_changes(self, flow, snapshot, final):
        fields = self._response_fields(flow)
        search = "\n".join(f"{k}: {v}" for k, v in fields["response_headers"])
        return {**fields, **snapshot, "state": "forwarded", "http_in_flight": not final,
                "response_streaming": not final,
                "duration_ms": round((time.monotonic()-flow.metadata["rw_start"])*1000, 2),
                "payload_text": flow.metadata.get("rw_payload", "") + "\n" + search + "\n" + snapshot["response_body_text"]}

    async def _finish_stream(self, flow, complete):
        capture = self._streams.pop(flow.id, None)
        if capture is None:
            return None
        capture.stop.set()
        try:
            if capture.task:
                await capture.task  # Its earlier snapshot must never overwrite the final one.
            return await self._stream_snapshot(flow, capture, capture.size, complete)
        finally:
            capture.close()

    async def response(self, flow: Any) -> None:
        if flow.metadata.get("rw_skip") or "rw_id" not in flow.metadata or flow.metadata.get("rw_dropped") or flow.response is None:
            return
        snapshot = await self._finish_stream(flow, True)
        if snapshot is None:
            snapshot = await self._snapshot(flow.response, "response")
        self._untrack(flow.id)
        self._update_later(flow.metadata["rw_id"], self._stream_changes(flow, snapshot, True))

    async def error(self, flow: Any) -> None:
        if "rw_id" in flow.metadata and not flow.metadata.get("rw_dropped"):
            snapshot = await self._finish_stream(flow, False)
            changes = {}
            if snapshot is not None:
                changes = self._stream_changes(flow, snapshot, True)
            elif flow.response is not None:
                # Buffered fallback may expose partial bytes; preserve whatever exists.
                snapshot = await self._snapshot(flow.response, "response")
                changes = self._stream_changes(flow, snapshot, True)
            changes.update({"state": "error", "error": safe_text(str(flow.error)),
                            "http_in_flight": False, "response_streaming": False,
                            "response_body_complete": False, "response_truncated": True,
                            "response_body_error": "Upstream response did not complete: " + safe_text(str(flow.error)),
                            "duration_ms": round((time.monotonic()-flow.metadata["rw_start"])*1000, 2)})
            self._untrack(flow.id)
            self._update_later(flow.metadata["rw_id"], changes)

    def done(self):
        # mitmproxy calls done after the event loop stops. Existing published
        # snapshots remain available; the application marks active records interrupted.
        for capture in self._streams.values():
            capture.close()
        self._streams.clear()
        self._active_flows.clear()


addons = [RequestWatchAddon()]
