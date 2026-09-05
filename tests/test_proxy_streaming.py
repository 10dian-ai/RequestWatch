import asyncio
import gzip
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tracemalloc
import zlib

import pytest

from requestwatch.body_store import BodyStore
from requestwatch.proxy_addon import RequestWatchAddon, body_snapshot
from requestwatch.stream_decode import decode_stream_file
from test_proxy import Headers, Request, flow


@pytest.mark.parametrize("coding", ["identity", "gzip", "deflate", "raw-deflate", "br", "zstd", "gzip-members", "stacked"])
def test_file_snapshot_keeps_complete_compressed_bytes_and_utf8(tmp_path, coding):
    body = ("完整中文正文\n" * 60000 + "FINAL-END-MARKER").encode()
    if coding == "gzip":
        raw, header = gzip.compress(body), "gzip"
    elif coding == "deflate":
        raw, header = zlib.compress(body), "deflate"
    elif coding == "raw-deflate":
        raw, header = zlib.compress(body)[2:-4], "deflate"
    elif coding == "br":
        raw, header = pytest.importorskip("brotli").compress(body), "br"
    elif coding == "zstd":
        raw, header = pytest.importorskip("zstandard").ZstdCompressor().compress(body), "zstd"
    elif coding == "gzip-members":
        raw, header = gzip.compress(body[:55555]) + gzip.compress(body[55555:]), "gzip"
    elif coding == "stacked":
        raw, header = zlib.compress(gzip.compress(body)), "gzip, deflate"
    else:
        raw, header = body, ""
    source = tmp_path / "incoming"
    source.write_bytes(raw)
    store = BodyStore(tmp_path)
    result = store.snapshot_file("response", source, content_type="text/event-stream", content_encoding=header)
    assert result["response_body_complete"] is True
    assert not result["response_body_decode_error"]
    assert result["response_sse_utf8"] is True
    assert store.read_body(result, "response") == raw
    assert store.read_text(result, "response").encode() == body
    assert len(result["response_body_text"].encode()) <= 65536


def test_stream_snapshot_prefix_is_immutable_and_partial_utf8_is_not_mojibake(tmp_path):
    source = tmp_path / "incoming"
    source.write_bytes("先到中文\n尾".encode())
    store = BodyStore(tmp_path)
    size = source.stat().st_size - 1
    partial = store.snapshot_file("response", source, size=size, complete=False, content_type="text/event-stream")
    assert not partial["response_body_complete"] and not partial["response_truncated"]
    assert not partial["response_body_decode_error"]
    assert store.read_text(partial, "response") == "先到中文\n"
    assert store.read_body(partial, "response") == source.read_bytes()[:size]
    final = store.snapshot_file("response", source, content_type="text/event-stream")
    assert store.read_text(final, "response") == "先到中文\n尾"
    assert store.read_body(partial, "response") != store.read_body(final, "response")


def test_gzip_open_prefix_decodes_before_trailer_and_error_retains_raw(tmp_path):
    body = 'data: {"choices":[{"delta":{"content":"先到正文"}}]}\n\n'.encode()
    raw = gzip.compress(body)
    source = tmp_path / "incoming"
    source.write_bytes(raw[:-8])
    store = BodyStore(tmp_path)
    partial = store.snapshot_file("response", source, complete=False, content_type="text/event-stream", content_encoding="gzip")
    assert store.read_text(partial, "response").encode() == body
    final = store.snapshot_file("response", source, complete=True, content_type="text/event-stream", content_encoding="gzip")
    assert final["response_body_decode_error"]
    assert store.read_body(final, "response") == raw[:-8]


def test_file_snapshot_does_not_load_whole_body_into_memory(tmp_path):
    source = tmp_path / "incoming"
    chunk = b"x" * 65536
    with source.open("wb") as output:
        for _ in range(400):
            output.write(chunk)
    store = BodyStore(tmp_path)
    tracemalloc.start()
    try:
        result = store.snapshot_file("response", source, content_type="text/plain; charset=utf-8")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result["response_body_size"] == 400 * 65536
    assert peak < 4 * 1024 * 1024


def test_declared_non_utf8_charset_keeps_complete_text(tmp_path):
    source = tmp_path / "incoming"
    source.write_bytes("中文完整正文".encode("gb18030"))
    store = BodyStore(tmp_path)
    result = store.snapshot_file("response", source, content_type="text/plain; charset=gb18030")
    assert store.read_text(result, "response") == "中文完整正文"


def response():
    return SimpleNamespace(status_code=200, headers=Headers([(b"Content-Type", b"text/event-stream")]),
                           trailers=None, raw_content=None, http_version="HTTP/1.1", stream=False)


async def drain(addon):
    while addon._tasks:
        await asyncio.gather(*list(addon._tasks))


@pytest.mark.parametrize("failure", [False, True])
def test_addon_stream_publishes_before_eof_keeps_utf8_and_failure_prefix(tmp_path, failure):
    async def run():
        store = BodyStore(tmp_path)
        addon = RequestWatchAddon(body_store=store)
        records = {}
        async def api(method, path, data=None, **kwargs):
            if method == "POST":
                records.update(data)
                return {"id": data["id"], "state": "captured"}
            records.update(data or {})
            return {"ok": True}
        addon._api = api
        item = flow()
        await addon.request(item)
        assert records["http_in_flight"]
        item.response = response()
        await addon.responseheaders(item)
        first = 'data: {"choices":[{"delta":{"content":"先到中文\\n"}}]}\n\n'.encode()
        assert item.response.stream(first[:-2]) == first[:-2]
        assert item.response.stream(first[-2:]) == first[-2:]
        for _ in range(220):
            if records.get("response_body_size") == len(first) and records.get("response_body_ref"):
                break
            await asyncio.sleep(.01)
        assert records["response_streaming"] and records["http_in_flight"]
        assert not records["response_body_complete"] and not records["response_truncated"]
        assert store.read_body(records, "response") == first
        assert "先到中文" in store.read_text(records, "response")
        first_ref = records["response_body_ref"]
        tail = 'data: {"choices":[{"delta":{"content":"最终尾部"}}]}\n\n'.encode()
        assert item.response.stream(tail) == tail
        if failure:
            item.error = "connection interrupted before end marker"
            await addon.error(item)
        else:
            assert item.response.stream(b"") == b""
            await addon.response(item)
        await drain(addon)
        assert not records["http_in_flight"] and not records["response_streaming"]
        assert records["response_body_complete"] is (not failure)
        assert records["response_truncated"] is failure
        assert store.read_body(records, "response") == first + tail
        assert store.read(first_ref) == first
        assert "最终尾部" in store.read_text(records, "response")
        assert not addon._streams and not list(store.root.glob(".stream-*"))
    asyncio.run(run())


def test_sse_snapshot_never_uses_mitmproxy_latin1_default(tmp_path):
    http = pytest.importorskip("mitmproxy.http")
    raw = 'data: {"choices":[{"delta":{"content":"中文正文"}}]}\n\n'.encode()
    message = http.Response.make(200, raw, {"Content-Type": "text/event-stream"})
    assert "中文正文" not in message.get_text()
    store = BodyStore(tmp_path)
    result = body_snapshot(message, "response", store)
    assert "中文正文" in store.read_text(result, "response")
    assert result["response_sse_utf8"] is True


def test_parser_retains_live_text_before_incomplete_utf8_suffix(tmp_path):
    source, target = tmp_path / "raw", tmp_path / "parsed"
    source.write_bytes('data: {"choices":[{"delta":{"content":"已到完整事件"}}]}\n\n'.encode() + 'data: 后'.encode()[:-1])
    meta = decode_stream_file(source, target, content_type="text/event-stream", source_complete=False)
    assert meta["recognized"] and not meta["complete"]
    assert "已到完整事件" in target.read_text("utf-8")
    assert "末尾字符" in " ".join(meta["warnings"])


def test_duplicate_json_fields_remain_visible_in_readable_detail(tmp_path):
    source, target = tmp_path / "raw", tmp_path / "parsed"
    source.write_bytes(b'data: {"field":"first","field":"second"}\n\n')
    meta = decode_stream_file(source, target, content_type="text/event-stream")
    assert meta["recognized"]
    assert '"field":"first","field":"second"' in target.read_text("utf-8")


def test_stream_snapshot_disk_failure_keeps_last_saved_prefix_and_transparency(tmp_path):
    async def run():
        store = BodyStore(tmp_path)
        addon = RequestWatchAddon(body_store=store)
        record = {}
        async def api(method, path, data=None, **kwargs):
            record.update(data or {})
            return {"id": record.get("id"), "state": "captured"} if method == "POST" else {"ok": True}
        addon._api = api
        item = flow()
        await addon.request(item)
        item.response = response()
        await addon.responseheaders(item)
        first = b"data: before-disk-error\n\n"
        assert item.response.stream(first) == first
        for _ in range(220):
            if record.get("response_body_size") == len(first) and record.get("response_body_ref"):
                break
            await asyncio.sleep(.01)
        assert store.read_body(record, "response") == first
        def failure(*args, **kwargs):
            raise OSError("disk is full")
        store.snapshot_file = failure
        tail = b"data: still-delivered-to-client\n\n"
        assert item.response.stream(tail) == tail
        await addon.response(item)
        await drain(addon)
        assert record["response_truncated"] and not record["response_body_complete"]
        assert record["response_received_size"] == len(first + tail)
        assert store.read_body(record, "response") == first
        assert "disk is full" in record["response_body_error"]
    asyncio.run(run())


def test_heartbeat_covers_quiet_requests_and_stops_at_terminal(tmp_path, monkeypatch):
    from requestwatch import proxy_addon as module
    monkeypatch.setattr(module, "HEARTBEAT_SECONDS", .01)
    async def run():
        addon = RequestWatchAddon(body_store=BodyStore(tmp_path))
        heartbeats = []
        async def api(method, path, data=None, **kwargs):
            if path == "/api/internal/heartbeat":
                heartbeats.append(list(data["record_ids"]))
                return {"updated": len(data["record_ids"])}
            return {"id": "stored-flow-id", "state": "captured"}
        addon._api = api
        item = flow()
        await addon.request(item)
        for _ in range(100):
            if len(heartbeats) >= 2:
                break
            await asyncio.sleep(.005)
        assert len(heartbeats) >= 2 and all(ids == ["stored-flow-id"] for ids in heartbeats)
        item.error = "ended before headers"
        await addon.error(item)
        await drain(addon)
        await asyncio.wait_for(addon._heartbeat_task, timeout=1)
        count = len(heartbeats)
        await asyncio.sleep(.04)
        assert len(heartbeats) == count and not addon._active_flows
    asyncio.run(run())


def test_timed_out_ingest_still_finalizes_the_committed_record(tmp_path):
    import httpx
    async def run():
        store = BodyStore(tmp_path)
        addon = RequestWatchAddon(body_store=store)
        record = {}
        async def api(method, path, data=None, **kwargs):
            if path == "/api/internal/ingest":
                record.update(data)
                raise httpx.ReadTimeout("response lost after commit")
            if method == "PUT":
                record.update(data)
            return {"ok": True}
        addon._api = api
        item = flow()
        await addon.request(item)
        assert item.metadata["rw_id"] == item.id
        item.response = response()
        await addon.responseheaders(item)
        raw = b"data: complete despite lost ingest acknowledgement\n\n"
        assert item.response.stream(raw) == raw
        await addon.response(item)
        await drain(addon)
        assert not record["http_in_flight"] and record["response_body_complete"]
        assert store.read_body(record, "response") == raw
        await asyncio.wait_for(addon._heartbeat_task, timeout=1)
    asyncio.run(run())


def test_terminal_updates_retry_in_order_and_are_bounded():
    import httpx
    async def run():
        addon = RequestWatchAddon()
        observed = []
        failures = 0
        async def api(method, path, data=None, **kwargs):
            nonlocal failures
            observed.append(data["state"])
            if data["state"] == "error" and failures < 2:
                failures += 1
                raise httpx.ConnectError("temporary API outage")
            return {"ok": True}
        addon._api = api
        addon._update_later("id", {"state": "forwarded", "http_in_flight": True})
        addon._update_later("id", {"state": "error", "http_in_flight": False})
        await drain(addon)
        assert observed == ["forwarded", "error", "error", "error"]
        observed.clear()
        async def unavailable(method, path, data=None, **kwargs):
            observed.append(data["state"])
            raise httpx.ConnectError("permanent API outage")
        addon._api = unavailable
        await addon._update("id", {"state": "error", "http_in_flight": False})
        assert observed == ["error"] * 3
    asyncio.run(run())


def test_definitive_missing_record_does_not_retry():
    import httpx
    async def run():
        addon = RequestWatchAddon()
        calls = []
        async def api(method, path, data=None, **kwargs):
            calls.append(path)
            request = httpx.Request(method, "http://127.0.0.1" + path)
            response = httpx.Response(404, request=request)
            response.raise_for_status()
        addon._api = api
        await addon._update("missing", {"state": "error", "http_in_flight": False})
        assert len(calls) == 1
    asyncio.run(run())


def test_initial_empty_stream_is_not_mislabeled_missing_bytes(tmp_path):
    store = BodyStore(tmp_path)
    record = store.externalize({"source": "http", "response_body_text": "",
                               "response_body_complete": False, "response_truncated": False,
                               "response_streaming": True})
    assert not record["response_body_complete"] and not record["response_truncated"]
    assert store.read_body(record, "response") == b""
    legacy = store.externalize({"source": "http", "response_body_text": "prefix", "response_body_complete": False})
    assert legacy["response_truncated"] and not legacy["response_body_complete"]
