import base64
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import time

import pytest

from requestwatch.network import packet_record
from requestwatch.runtime import Runtime
from requestwatch.store import Store
from requestwatch.tcp_streams import TCPStreamStore
from test_tcp_streams import packet


def observation(payload=b"", *, sport=42000, **kwargs):
    raw = bytearray(base64.b64decode(packet(payload, **kwargs)["raw_b64"]))
    offset = 22 if kwargs.get("reverse") else 20
    raw[offset:offset+2] = sport.to_bytes(2, "big")
    return packet_record(bytes(raw))


@pytest.fixture
def pipeline(tmp_path):
    store = Store(tmp_path / "records.sqlite3", max_records=10000)
    streams = TCPStreamStore(tmp_path)
    runtime = Runtime(store, SimpleNamespace(pending_limit=16, passive_only=True), streams=streams)
    yield runtime, store, streams
    streams.close()
    store.close()


def test_batch_out_of_order_retransmission_and_retention_preserve_every_observed_byte(pipeline):
    runtime, store, streams = pipeline
    store.max_records = 3
    records = [observation(seq=99, flags=2), observation(seq=199, flags=0x12, reverse=True),
               observation(b"world", seq=105), observation(b"hello", seq=100),
               observation(b"lowor", seq=103), observation(b"world", seq=105),
               observation(b"OK", seq=200, reverse=True), observation(seq=110, flags=0x11),
               observation(seq=202, flags=0x11, reverse=True)]
    # The same observation delivered twice is deduplicated, while a retransmission
    # with a new record ID remains an observation without duplicating stream bytes.
    records.insert(5, dict(records[4]))
    sql_records, sql_streams = [], []
    store.db.set_trace_callback(sql_records.append)
    streams.db.set_trace_callback(sql_streams.append)
    saved = runtime.ingest_packets(records)
    assert len(saved) == len(records)
    sid = saved[0]["tcp_session_id"]
    assert all(item["tcp_session_id"] == sid for item in saved)
    assert streams.get(sid)["complete"]
    assert streams.get(sid)["packet_count"] == 9
    assert streams.body_path(sid, "client").read_bytes() == b"helloworld"
    assert streams.body_path(sid, "server").read_bytes() == b"OK"
    stats = store.stats()
    assert stats["captured_total"] == 9 and stats["retained"] == 3 and stats["evicted_total"] == 6
    expected = {item["id"]: item for item in records}
    for item in store.query()["items"]:
        full = store.get(item["id"])
        assert full["raw_b64"] == expected[item["id"]]["raw_b64"]
        assert full["payload_hex"] == expected[item["id"]]["payload_hex"]
    assert sum(statement == "COMMIT" for statement in sql_records) == 1
    assert sum(statement == "COMMIT" for statement in sql_streams) == 1


def test_batch_exceeding_session_limit_reconstructs_before_eviction(pipeline):
    runtime, store, streams = pipeline
    streams.max_sessions = 3
    store.max_records = 5
    records = []
    for index in range(12):
        records.extend([observation(seq=99, flags=2, sport=43000+index),
                        observation(("connection-"+str(index)).encode(), seq=100, sport=43000+index)])
    saved = runtime.ingest_packets(records)
    assert streams.list_sessions()["total"] == 3
    assert store.stats()["retained"] == 5
    assert store.stats()["captured_total"] == len(records)
    for index in range(9, 12):
        sid = saved[2*index]["tcp_session_id"]
        assert streams.body_path(sid, "client").read_bytes() == ("connection-"+str(index)).encode()
        assert streams.session_id_for_record(saved[2*index]["id"]) == sid
    assert streams.get(saved[0]["tcp_session_id"]) is None
    assert streams.session_id_for_record(saved[0]["id"]) is None


def test_store_batch_preserves_pending_and_active_http_and_counts_unique_ids(pipeline):
    _, store, _ = pipeline
    store.max_records = 2
    store.save({"id": "pending", "state": "pending"})
    store.save({"id": "live-http", "source": "http", "http_in_flight": True})
    batch = [{"id": str(index), "source": "packet", "created_at": time.time()+index} for index in range(20)]
    batch.append({**batch[-1], "payload_text": "last value for the same ID"})
    saved = store.save_many(batch)
    assert len(saved) == 21
    assert store.get("pending") and store.get("live-http")
    assert store.stats()["retained"] == 2
    assert store.stats()["captured_total"] == 22 and store.stats()["evicted_total"] == 20


def test_store_invalid_batch_is_atomic(pipeline):
    _, store, _ = pipeline
    before = store.stats()["captured_total"]
    with pytest.raises(TypeError):
        store.save_many([{"id": "good", "payload_text": "keep"}, {"id": "invalid", "not_json": object()}])
    assert store.get("good") is None
    assert store.stats()["captured_total"] == before


def test_tcp_batch_failure_rolls_back_metadata_and_retry_keeps_correct_bytes(pipeline, monkeypatch):
    _, _, streams = pipeline
    original = streams._append
    first = observation(b"hello", seq=100)
    second = observation(b"world", seq=105)
    broken = observation(b"fail", seq=110)
    def append(sid, direction, start, payload):
        if payload == b"fail":
            raise OSError("simulated spool write failure")
        return original(sid, direction, start, payload)
    monkeypatch.setattr(streams, "_append", append)
    with pytest.raises(OSError):
        streams.ingest_many([first, second, broken])
    assert streams.list_sessions()["total"] == 0 and streams._batch is None
    assert streams.session_id_for_record(first["id"]) is None
    ids = streams.ingest_many([first, second])
    assert ids[0] == ids[1]
    assert streams.body_path(ids[0], "client").read_bytes() == b"helloworld"
    assert streams.get(ids[0])["packet_count"] == 2


def test_concurrent_batches_keep_counts_and_tcp_byte_order(pipeline):
    runtime, store, streams = pipeline
    chunks = [index.to_bytes(4, "big") * 16 for index in range(300)]
    records = [observation(chunk, seq=100+64*index) for index, chunk in enumerate(chunks)]
    batches = [records[index:index+25] for index in range(0, len(records), 25)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        saved = list(pool.map(runtime.ingest_packets, batches))
    sid = saved[0][0]["tcp_session_id"]
    assert all(item["tcp_session_id"] == sid for batch in saved for item in batch)
    assert streams.body_path(sid, "client").read_bytes() == b"".join(chunks)
    assert store.stats()["retained"] == store.stats()["captured_total"] == 300
    assert streams.get(sid)["packet_count"] == 300


def test_batch_cannot_import_interactive_or_http_records(pipeline):
    runtime, store, _ = pipeline
    for record in ({"source": "http"}, {"source": "packet", "state": "pending"}):
        with pytest.raises(ValueError):
            runtime.ingest_packets([record])
    assert store.stats()["captured_total"] == 0
    assert runtime.ingest_packets([]) == []


def test_batch_conflicting_overlap_remains_flagged_and_first_observed_wins(pipeline):
    runtime, _, streams = pipeline
    saved = runtime.ingest_packets([observation(b"abcdefghij", seq=100), observation(b"DEFG", seq=103),
                                    observation(b"klmn", seq=110)])
    sid = saved[0]["tcp_session_id"]
    assert streams.body_path(sid, "client").read_bytes() == b"abcdefghijklmn"
    assert streams.get(sid)["directions"]["client"]["overlap_conflicts"] == 4



@pytest.mark.parametrize("failure", ["before_commit", "commit_denied"])
def test_retention_rollback_preserves_previously_committed_spool(pipeline, monkeypatch, failure):
    import sqlite3
    _, _, streams = pipeline
    streams.max_sessions = 1
    old_record = observation(b"already-committed-body", sport=42001)
    old_id = streams.ingest(old_record)
    old_path = streams._spool(old_id, "client")
    expected = old_path.read_bytes()
    new_record = observation(b"new-uncommitted-body", sport=42002)
    if failure == "before_commit":
        trim = streams._trim_batch
        def broken_trim():
            trim()
            raise OSError("after SQL trim before commit")
        monkeypatch.setattr(streams, "_trim_batch", broken_trim)
        error = OSError
    else:
        def authorizer(action, name, value, database, trigger):
            if action == sqlite3.SQLITE_TRANSACTION and name == "COMMIT":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        streams.db.set_authorizer(authorizer)
        error = sqlite3.DatabaseError
    try:
        with pytest.raises(error):
            streams.ingest(new_record)
    finally:
        streams.db.set_authorizer(None)
    assert streams.get(old_id) is not None
    assert streams.session_id_for_record(old_record["id"]) == old_id
    assert streams.session_id_for_record(new_record["id"]) is None
    assert old_path.read_bytes() == expected
    assert streams.body_path(old_id, "client").read_bytes() == expected
    assert streams._batch is None


def test_cleanup_failure_after_commit_does_not_fail_successful_batch(pipeline, monkeypatch):
    _, _, streams = pipeline
    streams.max_sessions = 1
    old_id = streams.ingest(observation(b"old-body", sport=42001))
    def failed_cleanup(*args):
        raise OSError("temporary filesystem cleanup failure")
    monkeypatch.setattr(streams, "_cleanup_retired", failed_cleanup)
    record = observation(b"committed-new-body", sport=42002)
    new_id = streams.ingest(record)
    assert streams.get(old_id) is None
    assert streams.session_id_for_record(record["id"]) == new_id
    assert streams.body_path(new_id, "client").read_bytes() == b"committed-new-body"
    assert streams.get(new_id)["packet_count"] == 1
