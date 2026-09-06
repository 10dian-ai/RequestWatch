import base64
from concurrent.futures import ThreadPoolExecutor
import json
import os
import sqlite3

import pytest

from requestwatch.store import Store


def assert_exact_counts(store):
    expected = store.db.execute("SELECT COUNT(*),COALESCE(SUM(state IN ('pending','resolving')),0),"
                                "COALESCE(SUM(source='http'),0),COALESCE(SUM(source='packet'),0) FROM records").fetchone()
    stats = store.stats()
    assert tuple(stats[key] for key in ('total', 'pending', 'http', 'packets')) == tuple(expected)
    assert store.db.execute("SELECT COUNT(*) FROM record_summaries").fetchone()[0] == expected[0]


def test_navigation_and_idle_maintenance_never_read_complete_record_json(tmp_path):
    store = Store(tmp_path / 'records.sqlite3')
    raw = b'full-raw-packet-' * 20000
    body = '完整 prompt\n' * 20000 + 'HTTP-END'
    packet = store.save({'source': 'packet', 'raw_b64': base64.b64encode(raw).decode(),
                         'payload_text': raw.decode(), 'payload_hex': raw.hex(),
                         'src_container_id': 'newapi', 'dst_container_id': None})
    http = store.save({'source': 'http', 'protocol': 'HTTP', 'container_id': 'newapi',
                       'request_body_text': body, 'response_body_text': body[::-1],
                       'request_headers': {'x-test': 'request-header'},
                       'response_headers': {'x-test': 'response-header'}})
    def block_full_data(action, table, column, *unused):
        if action == sqlite3.SQLITE_READ and table == 'records' and column == 'data':
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    store.db.set_authorizer(block_full_data)
    try:
        result = store.query(container_id='newapi')
        assert result['total'] == 2
        assert store.query(source='http')['items'][0]['id'] == http['id']
        assert store.stats()['http'] == store.stats()['packets'] == 1
        assert store.expire_http() == []
        store.gc_bodies()
        assert all(item['detail_level'] == 'summary' for item in result['items'])
        assert all(len(item['payload_text']) <= 240 for item in result['items'])
        assert all('raw_b64' not in item and 'request_headers' not in item for item in result['items'])
    finally:
        store.db.set_authorizer(None)
    assert base64.b64decode(store.get(packet['id'])['raw_b64']) == raw
    assert store.bodies.read_text(store.get(http['id']), 'request') == body
    assert store.bodies.read_text(store.get(http['id']), 'response') == body[::-1]
    store.close()


def test_search_matches_full_body_tail_and_packet_content_without_reading_record_json(tmp_path, monkeypatch):
    store = Store(tmp_path / 'records.sqlite3')
    request = 'x' * 200000 + '末尾独有 Prompt STRASSE'
    response = 'y' * 180000 + '响应最末端-Complete'
    first = store.save({'id': 'first', 'created_at': 1, 'source': 'http', 'container_id': 'newapi',
                        'request_body_text': request, 'response_body_text': response})
    store.save({**first, 'id': 'second', 'created_at': 2, 'src_container_id': 'other'})
    raw = 'z' * 50000 + 'PACKET-BODY-END'
    store.save({'id': 'packet', 'source': 'packet', 'payload_text': raw})
    seen = []
    contains = store.bodies.contains
    def spy(record, needle):
        seen.append(record)
        assert not store.lock._is_owned()
        return contains(record, needle)
    monkeypatch.setattr(store.bodies, 'contains', spy)
    def block_full_data(action, table, column, *unused):
        if action == sqlite3.SQLITE_READ and table == 'records' and column == 'data':
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    store.db.set_authorizer(block_full_data)
    try:
        result = store.query(q='末尾独有 prompt straße', container_id='newapi', limit=1, offset=1)
        assert result['total'] == 2 and result['items'][0]['id'] == 'first'
        assert len(seen) == 1  # Identical immutable snapshots need one full-file search.
        assert store.query(q='响应最末端-complete', source='http')['total'] == 2
        assert store.query(q='packet-body-end')['items'][0]['id'] == 'packet'
        assert store.query(q='absent-exact-word')['total'] == 0
    finally:
        store.db.set_authorizer(None)
    store.close()


def test_counter_and_summary_updates_are_atomic_with_retention_and_commit_failure(tmp_path):
    store = Store(tmp_path / 'records.sqlite3', max_records=2)
    original = store.save({'id': 'old', 'created_at': 1, 'source': 'packet', 'payload_text': 'original'})
    store.save({'id': 'pending', 'created_at': 2, 'state': 'pending'})
    before = store.stats()
    def deny_commit(action, name, *unused):
        return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_TRANSACTION and name == 'COMMIT' else sqlite3.SQLITE_OK
    store.db.set_authorizer(deny_commit)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            store.save_many([{'id': 'old', 'created_at': 3, 'source': 'http', 'payload_text': 'changed'},
                             {'id': 'new', 'created_at': 4}])
    finally:
        store.db.set_authorizer(None)
    assert store.get('old') == original and store.get('new') is None
    assert store.stats() == before
    assert store.query(q='original')['total'] == 1
    assert_exact_counts(store)
    store.save_many([{'id': 'old', 'created_at': 3, 'source': 'http'}, {'id': 'new', 'created_at': 4}])
    assert store.get('old') is None and store.get('pending')
    assert_exact_counts(store)
    assert store.stats()['pending'] == 1 and store.stats()['evicted_total'] == 1
    store.close()


def test_old_database_migration_preserves_all_bytes_references_and_counts(tmp_path):
    path = tmp_path / 'old.sqlite3'
    store = Store(path)
    full = store.save({'id': 'complete', 'source': 'http', 'protocol': 'HTTP',
                       'request_body_text': 'request' * 20000, 'response_body_text': 'response' * 21000,
                       'src_container_id': None, 'dst_container_id': 'newapi'})
    store.save({'id': 'pending', 'source': 'packet', 'state': 'pending'})
    store.save({'id': 'active', 'source': 'http', 'http_in_flight': True, 'response_body_text': 'unfinished'})
    captured = store.stats()['captured_total']
    store.close()
    # Recreate the pre-index schema state without altering any full capture rows.
    with sqlite3.connect(path) as old:
        old.execute('DROP TRIGGER records_delete_summary')
        old.execute('DROP TABLE record_summaries')
        old.execute('DROP TABLE record_totals')
    migrated = Store(path)
    assert migrated.get('complete') == full
    assert migrated.query(container_id='newapi')['items'][0]['id'] == 'complete'
    assert migrated.get('active')['response_body_complete'] is False
    assert migrated.query(state='error')['total'] == 2
    assert migrated.stats()['captured_total'] == captured
    assert migrated.stats()['pending'] == 0
    assert_exact_counts(migrated)
    migrated.close()
    reopened = Store(path)
    assert_exact_counts(reopened)
    assert reopened.stats()['captured_total'] == captured
    assert reopened.bodies.read_text(reopened.get('complete'), 'request') == 'request' * 20000
    reopened.close()


def test_indexed_activity_keeps_full_record_and_list_state_in_sync(tmp_path, monkeypatch):
    monkeypatch.setattr('requestwatch.store.time.time', lambda: 1000)
    store = Store(tmp_path / 'records.sqlite3')
    store.save({'id': 'active', 'source': 'http', 'state': 'pending', 'http_in_flight': True,
                'response_body_text': 'preserved response'})
    monkeypatch.setattr('requestwatch.store.time.time', lambda: 1100)
    assert store.touch_http(['active', 'absent']) == 1
    assert store.query()['items'][0]['http_activity_at'] == store.get('active')['http_activity_at'] == 1100
    assert store.expire_http() == []
    monkeypatch.setattr('requestwatch.store.time.time', lambda: 1300)
    assert store.expire_http() == ['active']
    result = store.query()['items'][0]
    assert result['state'] == 'error' and result['response_body_complete'] is False
    assert store.bodies.read_text(store.get('active'), 'response') == 'preserved response'
    assert_exact_counts(store)
    assert store.stats()['pending'] == 0 and store.touch_http(['active']) == 0
    store.close()


def test_gc_reads_live_body_index_outside_capture_lock_and_collects_only_retired_blobs(tmp_path, monkeypatch):
    store = Store(tmp_path / 'records.sqlite3', max_records=1)
    old = store.save({'id': 'old', 'source': 'http', 'request_body_text': 'retired-body'})
    kept = store.save({'id': 'kept', 'source': 'http', 'request_body_text': 'kept-body'})
    for item in (old, kept):
        os.utime(store.bodies.path(item['request_body_ref']), (1, 1))
    loads = json.loads
    def outside_lock(value, *args, **kwargs):
        assert not store.lock._is_owned()
        return loads(value, *args, **kwargs)
    monkeypatch.setattr('requestwatch.store.json.loads', outside_lock)
    store.gc_bodies(grace_seconds=0)
    assert not store.bodies.path(old['request_body_ref']).exists()
    assert store.bodies.path(kept['request_body_ref']).read_bytes() == b'kept-body'
    store.close()


def test_concurrent_counter_changes_keep_exact_categories_and_summary_records(tmp_path):
    store = Store(tmp_path / 'records.sqlite3', max_records=200)
    def write(number):
        store.save_many([{'id': str(i), 'state': 'pending' if (i+number)%2 else 'captured',
                          'source': 'http' if number%2 else 'packet', 'payload_text': str(number)}
                         for i in range(number*10, number*10+20)])
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(write, range(20)))
    assert_exact_counts(store)
    assert store.query()['total'] == store.stats()['retained']
    for item in store.query()['items']:
        full = store.get(item['id'])
        assert item['state'] == full['state'] and item['source'] == full['source']
    store.close()
