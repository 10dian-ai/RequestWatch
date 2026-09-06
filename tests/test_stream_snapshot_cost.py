import asyncio
import codecs
from pathlib import Path

import pytest

from requestwatch.body_store import BodyStore
from requestwatch.proxy_addon import RequestWatchAddon, stream_snapshot_due
from test_proxy import flow
from test_proxy_streaming import drain, response


class CountingBodyStore(BodyStore):
    def __init__(self, folder):
        super().__init__(folder)
        self.copied_bytes = 0
        self.copy_count = 0

    def put_file(self, source, size=None):
        self.copied_bytes += Path(source).stat().st_size if size is None else size
        self.copy_count += 1
        return super().put_file(source, size)


@pytest.mark.parametrize("content_type", ["text/event-stream", "application/json; charset=utf-8", "text/plain; charset=UTF8"])
def test_utf8_snapshot_reuses_raw_blob_without_duplicate_file_copy(tmp_path, content_type):
    raw = ("完整中文正文\n" * 15000 + "FINAL-PROMPT-END").encode()
    source = tmp_path / "incoming"
    source.write_bytes(raw)
    store = CountingBodyStore(tmp_path)
    result = store.snapshot_file("response", source, content_type=content_type)
    assert result["response_body_ref"] == result["response_text_ref"]
    assert store.copied_bytes == len(raw) and store.copy_count == 1
    assert store.read_body(result, "response") == raw
    assert store.read_text(result, "response").encode() == raw
    assert result["response_body_complete"] and not result["response_truncated"]


@pytest.mark.parametrize("raw,expected", [
    (codecs.BOM_UTF8 + "保留原始BOM".encode(), "保留原始BOM"),
    (b"\xef", ""),
    (b"\xef\xbb", ""),
    ("完整\n尾".encode()[:-1], "完整\n"),
])
def test_utf8_optimization_preserves_raw_bom_and_partial_character(tmp_path, raw, expected):
    source = tmp_path / "incoming"
    source.write_bytes(raw)
    store = CountingBodyStore(tmp_path)
    result = store.snapshot_file("response", source, complete=False, content_type="text/event-stream")
    assert store.read_body(result, "response") == raw
    assert store.read_text(result, "response") == expected
    assert not result["response_body_complete"] and not result["response_truncated"]
    assert not result["response_body_decode_error"]


def test_invalid_utf8_still_keeps_full_original_bytes(tmp_path):
    raw = b"data: prefix " + b"\xff" + b" TAIL"
    source = tmp_path / "incoming"
    source.write_bytes(raw)
    store = BodyStore(tmp_path)
    result = store.snapshot_file("response", source, content_type="text/event-stream")
    assert result["response_body_decode_error"] and result["response_body_binary"]
    assert store.read_body(result, "response") == raw
    assert result["response_text_ref"] is None


def test_long_sse_reduces_immutable_copies_keeps_full_tail_and_bounded_feedback(tmp_path):
    store = CountingBodyStore(tmp_path)
    source = tmp_path / "incoming"
    segment = b"data: " + b"x" * 8192 + b"\n\n"
    last_size, last_time = -1, 0.0
    snapshots = []
    expected = bytearray()
    baseline_copy_bytes = 0
    with source.open("wb", buffering=0) as incoming:
        for second in range(1, 91):
            incoming.write(segment)
            expected.extend(segment)
            size = len(expected)
            # Previous code copied both raw and decoded bodies every second.
            baseline_copy_bytes += size * 2
            if stream_snapshot_due(size, last_size, second - last_time):
                snapshot = store.snapshot_file("response", source, size=size, complete=False,
                                               content_type="text/event-stream")
                snapshots.append(snapshot)
                assert not snapshot["response_body_complete"]
                last_size, last_time = size, second
            assert second - last_time < 5
        incoming.write(b"data: FINAL-PROMPT-END\n\ndata: [DONE]\n\n")
        expected.extend(b"data: FINAL-PROMPT-END\n\ndata: [DONE]\n\n")
    final = store.snapshot_file("response", source, content_type="text/event-stream")
    assert len(snapshots) <= 20
    assert store.copied_bytes < baseline_copy_bytes * .15
    assert store.read_body(snapshots[0], "response") == segment
    assert final["response_body_complete"] and not final["response_truncated"]
    assert store.read_body(final, "response") == expected
    assert store.read_text(final, "response").encode() == expected


def test_large_growth_can_publish_before_maximum_interval():
    assert not stream_snapshot_due(1000001, 1000000, 1)
    assert stream_snapshot_due(1600000, 1000000, 1)
    assert not stream_snapshot_due(1600000, 1000000, .5)
    assert stream_snapshot_due(1000001, 1000000, 5)
    assert not stream_snapshot_due(1000000, 1000000, 100)


def test_live_small_delta_publishes_by_deadline_without_waiting_for_eof(tmp_path, monkeypatch):
    from requestwatch import proxy_addon as module
    monkeypatch.setattr(module, "STREAM_SNAPSHOT_MIN_SECONDS", .02)
    monkeypatch.setattr(module, "STREAM_SNAPSHOT_MAX_SECONDS", .08)

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
        first, tail = b"data: first\n\n", b"data: SMALL-DELTA\n\n"
        assert item.response.stream(first) == first
        for _ in range(100):
            if record.get("response_body_ref") and record.get("response_body_size") == len(first):
                break
            await asyncio.sleep(.005)
        assert store.read_body(record, "response") == first
        initial_ref = record["response_body_ref"]
        assert item.response.stream(tail) == tail
        for _ in range(100):
            if record.get("response_body_size") == len(first + tail):
                break
            await asyncio.sleep(.005)
        assert record["response_streaming"] and not record["response_body_complete"]
        assert store.read_body(record, "response") == first + tail
        assert store.read(initial_ref) == first
        await addon.response(item)
        await drain(addon)
        assert record["response_body_complete"] and not record["response_truncated"]
        await asyncio.wait_for(addon._heartbeat_task, timeout=1)
    asyncio.run(run())
