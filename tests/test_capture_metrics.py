import sqlite3
from concurrent.futures import ThreadPoolExecutor

from requestwatch.store import Store


def test_retention_cap_does_not_freeze_cumulative_capture_count(tmp_path):
    store = Store(tmp_path / "metrics.sqlite3", max_records=3)
    for number in range(8):
        store.save({"id": str(number), "source": "packet", "protocol": "TCP", "payload_text": str(number)})
    stats = store.stats()
    assert stats["total"] == stats["retained"] == 3
    assert stats["captured_total"] == 8 and stats["evicted_total"] == 5
    assert stats["last_capture_at"] and not stats["history_before_counter_unknown"]
    last_capture = stats["last_capture_at"]
    store.update("7", {"payload_text": "new state"})
    stats = store.stats()
    assert stats["captured_total"] == 8
    assert stats["last_capture_at"] == last_capture
    assert stats["last_activity_at"] >= last_capture
    store.close()
    resumed = Store(tmp_path / "metrics.sqlite3", max_records=3)
    resumed.save({"id": "after-restart"})
    assert resumed.stats()["captured_total"] == 9
    assert resumed.stats()["evicted_total"] == 6
    resumed.close()


def test_old_database_counter_migration_is_explicit_and_once_only(tmp_path):
    path = tmp_path / "old.sqlite3"
    store = Store(path, max_records=2)
    for number in range(7):
        store.save({"id": str(number)})
    store.close()
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE capture_metrics")
    migrated = Store(path, max_records=2)
    stats = migrated.stats()
    assert stats["captured_total"] == stats["counter_baseline"] == 2
    assert stats["evicted_total"] == 0
    assert stats["history_before_counter_unknown"]
    migrated.save({"id": "new"})
    assert migrated.stats()["captured_total"] == 3
    migrated.close()
    reopened = Store(path)
    assert reopened.stats()["captured_total"] == 3
    assert reopened.stats()["counter_baseline"] == 2
    reopened.close()


def test_concurrent_updates_count_only_one_insert(tmp_path):
    store = Store(tmp_path / "concurrent.sqlite3", max_records=5)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda i: store.save({"id": f"id-{i % 20}", "state": "pending"}), range(100)))
    stats = store.stats()
    assert stats["captured_total"] == stats["retained"] == 20
    assert stats["evicted_total"] == 0
    store.close()
