from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path


def searchable(record: dict) -> str:
    keys = ("protocol", "summary", "src_ip", "dst_ip", "container_name", "container_id",
            "url", "method", "payload_text", "request_headers", "request_body_text",
            "response_headers", "response_body_text", "error")
    return "\n".join(json.dumps(record[k], ensure_ascii=False) if isinstance(record.get(k), (list, dict))
                     else str(record.get(k, "")) for k in keys).casefold()


class Store:
    def __init__(self, path: Path | str, max_records: int = 10000):
        self.lock = threading.RLock()
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
            """)
            # Kernel queues and mitmproxy flow objects cannot survive an application restart.
            for row in self.db.execute("SELECT id, data FROM records WHERE state IN ('pending','resolving')").fetchall():
                record = json.loads(row["data"])
                record.update(state="error", error="服务重启，原拦截对象已失效，无法再放行或丢弃")
                self.db.execute("UPDATE records SET state='error',data=? WHERE id=?", (json.dumps(record, ensure_ascii=False), row["id"]))

    def save(self, record: dict) -> dict:
        record = dict(record)
        record.setdefault("id", uuid.uuid4().hex)
        record.setdefault("created_at", time.time())
        record.setdefault("state", "captured")
        record.setdefault("container_id", "")
        with self.lock, self.db:
            self.db.execute("""INSERT INTO records VALUES (?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET created_at=excluded.created_at,
                source=excluded.source,protocol=excluded.protocol,state=excluded.state,
                container_id=excluded.container_id,search_text=excluded.search_text,data=excluded.data""",
                (record["id"], record["created_at"], record.get("source", "packet"), record.get("protocol", "TCP"),
                 record["state"], record["container_id"], searchable(record), json.dumps(record, ensure_ascii=False)))
            # Keep pending decisions reviewable; completed records are evicted oldest first.
            excess = self.db.execute("SELECT MAX(COUNT(*)-?,0) FROM records", (self.max_records,)).fetchone()[0]
            if excess:
                self.db.execute("DELETE FROM records WHERE id IN (SELECT id FROM records WHERE state NOT IN ('pending','resolving') ORDER BY created_at ASC LIMIT ?)", (excess,))
        return record

    def get(self, record_id: str) -> dict | None:
        with self.lock:
            row = self.db.execute("SELECT data FROM records WHERE id=?", (record_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def update(self, record_id: str, changes: dict) -> dict | None:
        with self.lock:
            record = self.get(record_id)
            if record is None:
                return None
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
        if q:
            clauses.append("search_text LIKE ? ESCAPE '\\'")
            values.append("%" + q.casefold().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        with self.lock:
            total = self.db.execute("SELECT COUNT(*) FROM records" + where, values).fetchone()[0]
            rows = self.db.execute("SELECT data FROM records" + where + " ORDER BY created_at DESC LIMIT ? OFFSET ?", (*values, limit, offset)).fetchall()
        items = []
        for row in rows:
            item = json.loads(row[0])
            # List responses must remain small even when bodies contain megabytes.
            for key in ("raw_b64", "request_body_b64", "response_body_b64", "payload_hex", "request_headers", "response_headers", "request_body_text", "response_body_text"):
                item.pop(key, None)
            item["payload_text"] = item.get("payload_text", "")[:240]
            items.append(item)
        return {"items": items, "total": total}

    def stats(self) -> dict:
        with self.lock:
            row = self.db.execute("SELECT COUNT(*),COALESCE(SUM(state IN ('pending','resolving')),0),COALESCE(SUM(source='http'),0),COALESCE(SUM(source='packet'),0) FROM records").fetchone()
        return dict(zip(("total", "pending", "http", "packets"), row))

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

    def close(self):
        with self.lock:
            self.db.close()
