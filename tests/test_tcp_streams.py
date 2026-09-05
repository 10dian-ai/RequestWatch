import base64
import hashlib
import socket
import struct

import pytest

from requestwatch.tcp_streams import TCPStreamStore


def packet(payload=b"", *, seq=100, flags=0x18, reverse=False, version=4, **changes):
    source, target = ("10.0.0.2", "10.0.0.3") if version == 4 else ("fd00::2", "fd00::3")
    sport, dport = 42000, 8081
    if reverse:
        source, target, sport, dport = target, source, dport, sport
    transport = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xffffffff, 1, 80, flags, 65535, 0, 0)
    if version == 4:
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40+len(payload), 1, 0, 64, 6, 0,
                             socket.inet_aton(source), socket.inet_aton(target))
    else:
        header = struct.pack("!IHBB16s16s", 6 << 28, 20+len(payload), 6, 64,
                             socket.inet_pton(socket.AF_INET6, source), socket.inet_pton(socket.AF_INET6, target))
    item = {"source": "packet", "protocol": "TCP", "raw_b64": base64.b64encode(header+transport+payload).decode()}
    item.update(changes)
    return item


@pytest.fixture
def streams(tmp_path):
    store = TCPStreamStore(tmp_path)
    yield store
    store.close()


def handshake(streams, **kwargs):
    sid = streams.ingest(packet(seq=99, flags=2, **kwargs))
    assert streams.ingest(packet(seq=199, flags=0x12, reverse=True, **kwargs)) == sid
    return sid


@pytest.mark.parametrize("version", [4, 6])
def test_both_directions_complete_after_handshake_and_fin(streams, version):
    sid = handshake(streams, version=version)
    streams.ingest(packet(b"GET /hello", seq=100, version=version))
    streams.ingest(packet(b"OK\x00\xff", seq=200, reverse=True, version=version))
    streams.ingest(packet(seq=110, flags=0x11, version=version))
    streams.ingest(packet(seq=204, flags=0x11, reverse=True, version=version))
    item = streams.get(sid)
    assert item["state"] == "closed" and item["complete"]
    assert not item["midstream"]
    assert item["directions"]["client"]["byte_count"] == 10
    assert streams.body_path(sid, "client").read_bytes() == b"GET /hello"
    assert streams.body_path(sid, "server").read_bytes() == b"OK\x00\xff"
    assert streams.body_path(sid, "server", "latin1").read_text("utf-8") == "OK\x00ÿ"


def test_out_of_order_retransmission_overlap_and_export_invalidation(streams):
    sid = handshake(streams)
    streams.ingest(packet(b"world", seq=105))
    old_path = streams.body_path(sid, "client")
    assert old_path.read_bytes() == b"world"
    streams.ingest(packet(b"hello", seq=100))
    streams.ingest(packet(b"lowor", seq=103))
    streams.ingest(packet(b"world", seq=105))
    assert streams.body_path(sid, "client").read_bytes() == b"helloworld"
    item = streams.get(sid)["directions"]["client"]
    assert item["byte_count"] == 10 and item["missing_bytes"] == 0
    assert item["overlap_conflicts"] == 0
    assert streams._spool(sid, "client").stat().st_size == 10


def test_conflicting_retransmit_first_observed_bytes_win(streams):
    sid = handshake(streams)
    streams.ingest(packet(b"first", seq=100))
    streams.ingest(packet(b"other", seq=100))
    assert streams.body_path(sid, "client").read_bytes() == b"first"
    assert streams.get(sid)["directions"]["client"]["overlap_conflicts"] == 5


def test_gap_explicit_never_padded_and_can_be_repaired(streams):
    sid = handshake(streams)
    streams.ingest(packet(b"foo", seq=100))
    streams.ingest(packet(b"bar", seq=108))
    streams.ingest(packet(seq=111, flags=0x11))
    streams.ingest(packet(seq=200, flags=0x11, reverse=True))
    item = streams.get(sid)
    assert not item["complete"]
    assert item["directions"]["client"]["gaps"] == [{"start": 3, "end": 8, "size": 5}]
    assert streams.body_path(sid, "client").read_bytes() == b"foobar"
    assert streams.list_sessions(q="foobar")["total"] == 0  # No invented match across a hole.
    streams.ingest(packet(b"12345", seq=103))
    assert streams.get(sid)["complete"]
    assert streams.body_path(sid, "client").read_bytes() == b"foo12345bar"


def test_sequence_wrap_and_earlier_out_of_order_without_syn(streams):
    sid = streams.ingest(packet(b"def", seq=1))
    streams.ingest(packet(b"abc", seq=0xfffffffe))
    assert streams.body_path(sid, "client").read_bytes() == b"abcdef"
    item = streams.get(sid)
    assert item["midstream"] and not item["complete"]
    assert item["directions"]["client"]["first_offset"] == -3
    assert item["directions"]["client"]["missing_bytes"] == 0


def test_new_syn_reuses_tuple_but_creates_new_session(streams):
    sid = streams.ingest(packet(seq=99, flags=2))
    assert streams.ingest(packet(seq=99, flags=2)) == sid  # Retransmitted SYN.
    streams.ingest(packet(b"old", seq=100))
    newer = streams.ingest(packet(seq=9999, flags=2))
    assert sid != newer
    assert streams.get(sid)["state"] == "interrupted"
    assert streams.body_path(sid, "client").read_bytes() == b"old"


def test_syn_ack_first_identifies_directions_but_marks_midstream(streams):
    sid = streams.ingest(packet(seq=199, flags=0x12, reverse=True))
    streams.ingest(packet(b"reply", seq=200, reverse=True))
    streams.ingest(packet(b"request", seq=100))
    assert streams.get(sid)["client_ip"] == "10.0.0.2"
    assert streams.get(sid)["midstream"]
    assert streams.body_path(sid, "client").read_bytes() == b"request"
    assert streams.body_path(sid, "server").read_bytes() == b"reply"


def test_complete_megabytes_binary_and_tail_search(streams):
    sid = handshake(streams)
    content = bytes(range(256)) * 9000 + "末尾完整正文TAIL-unique".encode()
    for offset in range(0, len(content), 60000):
        streams.ingest(packet(content[offset:offset+60000], seq=100+offset, container_id="container-one"))
    streams.ingest(packet(seq=100+len(content), flags=0x11))
    streams.ingest(packet(seq=200, flags=0x11, reverse=True))
    path = streams.body_path(sid, "client")
    assert path.stat().st_size == len(content) > 2*1024*1024
    assert hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(content).digest()
    assert streams.list_sessions(q="末尾完整正文tail-UNIQUE", container_id="container-one")["total"] == 1
    assert streams.list_sessions(q="末尾完整正文", container_id="wrong")["total"] == 0
    # In-order traffic is a single disk extent, independent of packet count.
    assert streams.db.execute("SELECT COUNT(*) FROM ranges WHERE session_id=?", (sid,)).fetchone()[0] == 1
    assert streams.get(sid)["complete"]


def test_utf8_search_across_packet_and_read_chunk_boundaries(streams):
    sid = streams.ingest(packet(b"a"*60000, seq=100))
    suffix = b"a"*5535 + "界限文字".encode()
    streams.ingest(packet(suffix[:5536], seq=60100))
    streams.ingest(packet(suffix[5536:], seq=65636))
    assert streams.list_sessions(q="界限文字")["total"] == 1
    assert streams.body_path(sid, "client", "text").read_text("utf-8").endswith("界限文字")


def test_restart_keeps_full_historical_files_and_new_capture_separate(tmp_path):
    store = TCPStreamStore(tmp_path)
    sid = store.ingest(packet(b"persisted", seq=100))
    store.close()
    store = TCPStreamStore(tmp_path)
    try:
        assert store.get(sid)["state"] == "interrupted"
        assert store.body_path(sid, "client").read_bytes() == b"persisted"
        assert store.ingest(packet(b"new", seq=200)) != sid
        assert store.list_sessions(q="persisted")["total"] == 1
    finally:
        store.close()


def test_retention_and_record_id_deduplication(tmp_path):
    store = TCPStreamStore(tmp_path, max_sessions=1)
    try:
        record = packet(b"once", seq=100, id="capture-1", created_at=1)
        sid = store.ingest(record)
        assert store.ingest(record) == sid
        assert store.get(sid)["packet_count"] == 1
        store.body_path(sid, "client")
        newer = store.ingest(packet(b"new", seq=300, created_at=500))
        assert newer != sid and store.get(sid) is None
        assert not list(store.root.glob(sid + "-*.spool"))
        # Newly generated downloads get a 10-minute grace period before orphan cleanup.
        assert store.list_sessions()["total"] == 1
    finally:
        store.close()


def test_truncated_payload_never_claims_complete(streams):
    sid = handshake(streams)
    record = packet(b"missing-tail", seq=100)
    record["raw_b64"] = base64.b64encode(base64.b64decode(record["raw_b64"])[:-4]).decode()
    streams.ingest(record)
    streams.ingest(packet(seq=112, flags=0x11))
    streams.ingest(packet(seq=200, flags=0x11, reverse=True))
    item = streams.get(sid)
    assert not item["complete"]
    assert item["directions"]["client"]["truncated_packets"] == 1
    assert item["directions"]["client"]["missing_bytes"] == 4


def test_no_tcp_payload_and_bad_ids_are_safe(streams):
    assert streams.ingest({"protocol": "UDP"}) is None
    assert streams.ingest({"protocol": "TCP", "raw_b64": "bad"}) is None
    sid = streams.ingest(packet(seq=99, flags=2))
    assert streams.body_path(sid, "server").read_bytes() == b""
    with pytest.raises(ValueError):
        streams.body_path("../../etc/passwd", "client")
    with pytest.raises(ValueError):
        streams.body_path(sid, "unknown")
    with pytest.raises(KeyError):
        streams.body_path("0"*32, "client")


def test_closed_tuple_without_new_syn_gets_new_midstream_incarnation(streams):
    sid = handshake(streams)
    streams.ingest(packet(b"old", seq=100))
    streams.ingest(packet(seq=103, flags=0x11))
    streams.ingest(packet(seq=200, flags=0x11, reverse=True))
    assert streams.ingest(packet(b"old", seq=100)) == sid
    newer = streams.ingest(packet(b"new", seq=5000))
    assert newer != sid and streams.get(newer)["midstream"]
    assert streams.body_path(sid, "client").read_bytes() == b"old"
    assert streams.body_path(newer, "client").read_bytes() == b"new"


def test_reset_is_not_complete_even_with_observed_fins(streams):
    sid = handshake(streams)
    streams.ingest(packet(seq=100, flags=0x11))
    streams.ingest(packet(seq=200, flags=0x11, reverse=True))
    streams.ingest(packet(seq=101, flags=4))
    assert streams.get(sid)["state"] == "reset"
    assert not streams.get(sid)["complete"]


def test_ambiguous_large_sequence_jump_does_not_claim_complete(streams):
    sid = handshake(streams)
    streams.ingest(packet(seq=0x90000000, flags=0x11))
    streams.ingest(packet(seq=200, flags=0x11, reverse=True))
    item = streams.get(sid)
    assert not item["complete"]
    assert item["directions"]["client"]["sequence_anomalies"] > 0


@pytest.mark.parametrize("operation", ["search", "export"])
def test_slow_body_disk_read_does_not_block_capture(streams, monkeypatch, operation):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    from pathlib import Path

    sid = streams.ingest(packet(b"first-chunk", seq=100))
    spool = streams._spool(sid, "client")
    started, release = threading.Event(), threading.Event()
    original_open = Path.open

    def slow_open(path, mode="r", *args, **kwargs):
        if path == spool and mode == "rb":
            started.set()
            if not release.wait(5):
                raise TimeoutError("test did not release simulated slow disk")
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", slow_open)
    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(streams.list_sessions, q="first-chunk") if operation == "search" else pool.submit(streams.body_path, sid, "client")
        try:
            assert started.wait(2)
            # Exercise both metadata and a real append while a full-body read is stalled.
            captured = pool.submit(streams.ingest, packet(b"-later", seq=111))
            assert captured.result(timeout=2) == sid
        finally:
            release.set()
        result = future.result(timeout=2)
    if operation == "search":
        assert result["total"] == 1
    else:
        assert result.read_bytes() == b"first-chunk"  # Exactly the captured revision.
        assert streams.body_path(sid, "client").read_bytes() == b"first-chunk-later"
        assert streams.body_path(sid, "client") != result


def test_search_skips_spool_evicted_after_snapshot(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from pathlib import Path
    import threading

    store = TCPStreamStore(tmp_path, max_sessions=1)
    sid = store.ingest(packet(b"evicted-unique-body", seq=100, created_at=1))
    spool = store._spool(sid, "client")
    started, release = threading.Event(), threading.Event()
    original_open = Path.open

    def slow_open(path, mode="r", *args, **kwargs):
        if path == spool and mode == "rb":
            started.set()
            if not release.wait(5):
                raise TimeoutError("test did not release simulated slow disk")
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", slow_open)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            searching = pool.submit(store.list_sessions, q="evicted-unique-body")
            try:
                assert started.wait(2)
                captured = pool.submit(store.ingest, packet(b"new-body", seq=200, created_at=500))
                assert captured.result(timeout=2) != sid
                assert not spool.exists()
            finally:
                release.set()
            assert searching.result(timeout=2) == {"items": [], "total": 0}
    finally:
        store.close()


def test_search_does_not_hide_disk_corruption_or_permission_errors(streams, monkeypatch):
    from pathlib import Path

    sid = streams.ingest(packet(b"content", seq=100))
    spool = streams._spool(sid, "client")
    original_open = Path.open

    def denied_open(path, mode="r", *args, **kwargs):
        if path == spool and mode == "rb":
            raise PermissionError("disk access denied")
        return original_open(path, mode, *args, **kwargs)

    with monkeypatch.context() as patched:
        patched.setattr(Path, "open", denied_open)
        with pytest.raises(PermissionError):
            streams.list_sessions(q="content")
    spool.write_bytes(b"c")
    with pytest.raises(OSError, match="shorter"):
        streams.list_sessions(q="content")


def test_closed_midstream_retransmission_with_negative_offset_stays_in_session(streams):
    sid = streams.ingest(packet(b"def", seq=1))
    streams.ingest(packet(b"abc", seq=0xfffffffe))
    streams.ingest(packet(seq=4, flags=0x11))
    streams.ingest(packet(seq=200, flags=0x11, reverse=True))
    assert streams.get(sid)["state"] == "closed"
    assert streams.body_path(sid, "client").read_bytes() == b"abcdef"
    assert streams.ingest(packet(b"abc", seq=0xfffffffe)) == sid
    assert streams.body_path(sid, "client").read_bytes() == b"abcdef"
    newer = streams.ingest(packet(b"new", seq=0xfffffffb))
    assert newer != sid
    assert streams.body_path(newer, "client").read_bytes() == b"new"


def test_utf8_export_never_combines_partial_characters_across_a_gap(streams):
    sid = handshake(streams)
    streams.ingest(packet(b"\xe4", seq=100))
    streams.ingest(packet(b"\xb8\xad", seq=104))
    assert streams.get(sid)["directions"]["client"]["missing_bytes"] == 3
    # Raw exports contain every observed byte in sequence order, with missing
    # ranges omitted. UTF-8 views must retain the discontinuity while decoding.
    assert streams.body_path(sid, "client").read_bytes() == b"\xe4\xb8\xad"
    old = streams.root / f"{sid}-client-2.text"
    old.write_bytes(b"\xe4\xb8\xad")
    rendered = streams.body_path(sid, "client", "text")
    assert rendered != old
    assert rendered.read_text("utf-8") == "\ufffd\ufffd\ufffd"
    assert streams.list_sessions(q="\u4e2d")["total"] == 0
    # The same byte sequence is a valid character when capture contains no hole.
    other = streams.ingest(packet(b"\xe4", seq=1000))
    assert other == sid  # Same open connection; use a later contiguous range.
    streams.ingest(packet(b"\xb8\xad", seq=1001))
    assert streams.body_path(sid, "client", "text").read_text("utf-8").endswith("\u4e2d")
