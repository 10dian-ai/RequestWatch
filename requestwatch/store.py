from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from .body_store import BodyStore


def searchable(record: dict) -> str:
    keys = ("protocol", "summary", "src_ip", "dst_ip", "container_name", "container_id",
            "url", "method", "payload_text", "request_headers", "request_body_text",
            "response_headers", "response_body_text", "error")
    return "\n".join(json.dumps(record[k], ensure_ascii=False) if isinstance(record.get(k), (list, dict))
                     else str(record.get(k, "")) for k in keys).casefold()


class Store:
    def __init__(self, path: Path | str, max_records: int = 10000, body_dir: Path | str | None = None):
        self.lock = threading.RLock()
        self.bodies = BodyStore(body_dir if body_dir is not None else Path(path).parent)
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.max_records = max_records
        with self.db:
            self.db.executescript("""
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=NORMAL;
                CREATE TABLE IF NOT EXISTS records (
                    id TEXT PRIMARY KEY, created_at REAL NOT NULL, source TEXT NOT NULL,
                    protocol TEXT NOT NULL, state TEXT NOT NULL, container_id TEXT NOT NULL,
                    search_text TEXT NOT NULL, data TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS records_time ON records(created_at DESC);
                CREATE INDEX IF NOT EXISTS records_filter ON records(state, source, protocol, container_id);
                CREATE TABLE IF NOT EXISTS rules (id TEXT PRIMARY KEY, created_at REAL NOT NULL, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS capture_metrics (
                    id INTEGER PRIMARY KEY CHECK(id=1), captured_total INTEGER NOT NULL,
                    evicted_total INTEGER NOT NULL, started_at REAL NOT NULL,
                    baseline INTEGER NOT NULL, last_capture_at REAL, last_activity_at REAL
                );
            """)
            # Older versions kept only the retained count; never invent the missing history.
            self.db.execute("""INSERT OR IGNORE INTO capture_metrics
                SELECT 1,COUNT(*),0,?,COUNT(*),MAX(created_at),MAX(created_at) FROM records""", (time.time(),))
            # Kernel queues and mitmproxy flow objects cannot survive an application restart.
            for row in self.db.execute("SELECT id, data FROM records WHERE state IN ('pending','resolving') OR json_extract(data,'$.http_in_flight')=1").fetchall():
                record = json.loads(row["data"])
                if record.get("http_in_flight"):
                    record.update(http_in_flight=False, response_streaming=False, response_body_complete=False,
                                  response_truncated=True, response_body_error="服务重启，响应未完成；保留重启前已保存的内容")
                message = "服务重启，原拦截对象已失效，无法再放行或丢弃" if record["state"] in {"pending", "resolving"} else "服务重启，原连接已结束；响应仅包含已保存部分"
                record.update(state="error", error=message)
                self.db.execute("UPDATE records SET state='error',data=? WHERE id=?", (json.dumps(record, ensure_ascii=False), row["id"]))

    def save(self, record: dict) -> dict:
        return self.save_many([record])[0]

    def save_many(self, records: list[dict]) -> list[dict]:
        """Persist a capture batch in one transaction, counting each new ID once.

        Prepare complete records before entering SQLite so invalid input cannot
        leave a partly committed batch. Retention and counters run once per batch.
        """
        prepared = []
        for original in records:
            record = self.bodies.externalize(original)
            if "id" not in record:
                record["id"] = uuid.uuid4().hex
            record.setdefault("created_at", time.time())
            record.setdefault("state", "captured")
            record.setdefault("container_id", "")
            if record.get("source") == "http" and record.get("http_in_flight"):
                record["http_activity_at"] = time.time()
            prepared.append(record)
        if not prepared:
            return []
        rows = [(record["id"], record["created_at"], record.get("source", "packet"), record.get("protocol", "TCP"),
                 record["state"], record["container_id"], searchable(record), json.dumps(record, ensure_ascii=False))
                for record in prepared]
        ids = list(dict.fromkeys(record["id"] for record in prepared))
        with self.lock, self.db:
            existing = set()
            for offset in range(0, len(ids), 500):
                batch = ids[offset:offset+500]
                existing.update(row[0] for row in self.db.execute(
                    "SELECT id FROM records WHERE id IN (" + ",".join("?" for _ in batch) + ")", batch))
            new_count = len(ids) - len(existing)
            self.db.executemany("""INSERT INTO records VALUES (?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET created_at=excluded.created_at,
                source=excluded.source,protocol=excluded.protocol,state=excluded.state,
                container_id=excluded.container_id,search_text=excluded.search_text,data=excluded.data""", rows)
            now = time.time()
            self.db.execute("UPDATE capture_metrics SET captured_total=captured_total+?, "
                            "last_capture_at=CASE WHEN ? THEN ? ELSE last_capture_at END,last_activity_at=? WHERE id=1",
                            (new_count, new_count, now, now))
            # Keep pending decisions and unfinished HTTP responses; packet traffic must
            # not evict a long-lived response before its final body can be saved.
            excess = self.db.execute("SELECT MAX(COUNT(*)-?,0) FROM records", (self.max_records,)).fetchone()[0]
            if excess:
                evicted = self.db.execute("DELETE FROM records WHERE id IN (SELECT id FROM records WHERE state NOT IN ('pending','resolving') AND NOT (source='http' AND COALESCE(json_extract(data,'$.http_in_flight'),0)=1) ORDER BY created_at ASC LIMIT ?)", (excess,)).rowcount
                self.db.execute("UPDATE capture_metrics SET evicted_total=evicted_total+? WHERE id=1", (evicted,))
        return prepared

    def touch_http(self, record_ids: list[str]) -> int:
        """Renew active capture leases without reviving completed HTTP records."""
        ids = list(dict.fromkeys(record_ids))
        if not ids:
            return 0
        touched, now = 0, time.time()
        with self.lock, self.db:
            for start in range(0, len(ids), 250):
                batch = ids[start:start + 250]
                cursor = self.db.execute(
                    "UPDATE records SET data=json_set(data,'$.http_activity_at',?) "
                    "WHERE source='http' AND json_extract(data,'$.http_in_flight')=1 "
                    "AND id IN (" + ",".join("?" for _ in batch) + ")", (now, *batch))
                touched += cursor.rowcount
        return touched

    def expire_http(self, age_seconds: float = 120) -> list[str]:
        """Release leases from a disconnected capture agent, preserving every blob.

        Return the IDs actually changed so Runtime can invalidate pending decisions
        under its own lock. Heartbeats only renew active leases, so neither a late
        heartbeat nor this housekeeping operation can resurrect a terminal state.
        """
        if age_seconds < 0:
            raise ValueError("HTTP lease age cannot be negative")
        message = "采集代理失联，响应未确认完成；已保留最后收到的内容"
        with self.lock, self.db:
            cursor = self.db.execute(
                "UPDATE records SET state='error', "
                "data=json_set(data,'$.state','error','$.error',?, "
                "'$.http_in_flight',json('false'),'$.response_streaming',json('false'), "
                "'$.response_body_complete',json('false'),'$.response_truncated',json('true'), "
                "'$.response_body_error',?) "
                "WHERE source='http' AND json_extract(data,'$.http_in_flight')=1 "
                "AND COALESCE(json_extract(data,'$.http_activity_at'),created_at)<=? RETURNING id",
                (message, message, time.time()-age_seconds))
            return [row[0] for row in cursor.fetchall()]

    def get(self, record_id: str) -> dict | None:
        with self.lock:
            row = self.db.execute("SELECT data FROM records WHERE id=?", (record_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def update(self, record_id: str, changes: dict) -> dict | None:
        with self.lock:
            record = self.get(record_id)
            if record is None:
                return None
            for prefix in ("request", "response"):
                if any(prefix + suffix in changes for suffix in ("_body_text", "_body_b64")) and prefix + "_body_ref" not in changes:
                    for suffix in ("_body_ref", "_text_ref", "_body_complete", "_truncated", "_body_size"):
                        record.pop(prefix + suffix, None)
                    if prefix + "_body_b64" not in changes:
                        record.pop(prefix + "_body_b64", None)
                    if prefix + "_body_b64" in changes and prefix + "_body_text" not in changes:
                        record.pop(prefix + "_body_text", None)
            record.update({k: v for k, v in changes.items() if k not in {"id", "created_at"}})
            return self.save(record)

    def query(self, *, q="", protocol="", container_id="", state="", source="", limit=100, offset=0) -> dict:
        clauses, values = [], []
        for key, value in (("protocol", protocol), ("state", state), ("source", source)):
            if value and value != "any":
                clauses.append(f"{key}=?")
                values.append(value)
        if container_id and container_id != "any":
            clauses.append("(container_id=? OR json_extract(data,'$.src_container_id')=? OR json_extract(data,'$.dst_container_id')=?)")
            values.extend([container_id] * 3)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        if q:
            # Snapshot metadata briefly; large file searches must not block capture/verdict writes.
            with self.lock:
                candidate_ids = [r[0] for r in self.db.execute("SELECT id FROM records" + where + " ORDER BY created_at DESC", values)]
            rows, total = [], 0
            needle = q.casefold()
            for start in range(0, len(candidate_ids), 32):
                batch = candidate_ids[start:start + 32]
                with self.lock:
                    fetched = self.db.execute("SELECT data,search_text,id FROM records WHERE id IN (" + ",".join("?" for _ in batch) + ")", batch).fetchall()
                by_id = {r[2]: r for r in fetched}
                for record_id in batch:
                    candidate = by_id.get(record_id)
                    if candidate is None:  # Retention may evict records during a long search.
                        continue
                    item = json.loads(candidate[0])
                    if needle in candidate[1] or self.bodies.contains(item, needle):
                        if offset <= total < offset + limit:
                            rows.append(candidate)
                        total += 1
        else:
            with self.lock:
                total = self.db.execute("SELECT COUNT(*) FROM records" + where, values).fetchone()[0]
                rows = self.db.execute("SELECT data FROM records" + where + " ORDER BY created_at DESC LIMIT ? OFFSET ?", (*values, limit, offset)).fetchall()
        items = []
        for row in rows:
            item = json.loads(row[0])
            # List responses must remain small even when bodies contain megabytes.
            for key in ("raw_b64", "request_body_b64", "response_body_b64", "payload_hex", "request_headers", "response_headers", "request_body_text", "response_body_text"):
                item.pop(key, None)
            item["detail_level"] = "summary"
            item["payload_preview_truncated"] = len(item.get("payload_text", "")) > 240
            item["payload_text"] = item.get("payload_text", "")[:240]
            items.append(item)
        return {"items": items, "total": total}

    def stats(self) -> dict:
        with self.lock:
            row = self.db.execute("SELECT COUNT(*),COALESCE(SUM(state IN ('pending','resolving')),0),COALESCE(SUM(source='http'),0),COALESCE(SUM(source='packet'),0) FROM records").fetchone()
            metrics = self.db.execute("SELECT * FROM capture_metrics WHERE id=1").fetchone()
        result = dict(zip(("total", "pending", "http", "packets"), row))
        result.update(retained=result["total"], captured_total=metrics["captured_total"],
                      evicted_total=metrics["evicted_total"], counter_started_at=metrics["started_at"],
                      counter_baseline=metrics["baseline"], last_capture_at=metrics["last_capture_at"],
                      last_activity_at=metrics["last_activity_at"],
                      history_before_counter_unknown=metrics["baseline"] > 0)
        return result

    def rules(self) -> list[dict]:
        with self.lock:
            return [json.loads(row[0]) for row in self.db.execute("SELECT data FROM rules ORDER BY created_at,id")]

    def save_rule(self, rule: dict) -> dict:
        rule = dict(rule)
        rule.setdefault("id", uuid.uuid4().hex)
        with self.lock, self.db:
            self.db.execute("INSERT INTO rules VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", (rule["id"], time.time(), json.dumps(rule, ensure_ascii=False)))
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        with self.lock, self.db:
            return self.db.execute("DELETE FROM rules WHERE id=?", (rule_id,)).rowcount > 0

    def gc_bodies(self, grace_seconds=600):
        """Evict blobs after record retention; grace protects proxy writes before ingest."""
        with self.lock:
            live = set()
            for row in self.db.execute("SELECT data FROM records"):
                record = json.loads(row[0])
                for prefix in ("request", "response"):
                    for kind in ("body", "text"):
                        if ref := record.get(prefix + "_" + kind + "_ref"):
                            live.add(ref)
        cutoff = time.time() - grace_seconds
        for path in self.bodies.root.glob("*.blob"):
            if path.stem not in live and not path.is_symlink():
                try:
                    if path.stat().st_mtime < cutoff:
                        path.unlink()
                except FileNotFoundError:
                    pass

    def close(self):
        with self.lock:
            self.db.close()
