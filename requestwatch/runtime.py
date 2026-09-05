from __future__ import annotations

import logging
import threading
import time
import uuid

from .rules import matches


class Runtime:
    def __init__(self, store, config, inventory=None, streams=None):
        self.store, self.config, self.inventory = store, config, inventory
        self.streams = streams
        self._pending: dict[str, dict] = {}
        self._lock = threading.RLock()
        self._rules = store.rules()

    def rules(self):
        with self._lock:
            return [dict(rule) for rule in self._rules]

    def refresh_rules(self):
        rules = self.store.rules()
        with self._lock:
            self._rules = rules

    def ingest(self, record: dict, can_intercept: bool = False) -> dict:
        record = dict(record)
        record.setdefault("id", uuid.uuid4().hex)
        record.setdefault("created_at", time.time())
        record.setdefault("state", "captured")
        if self.inventory and not record.get("container_id") and record.get("attribution") != "host-replay":
            record.update(self.inventory.identify(record.get("src_ip", ""), record.get("dst_ip", "")))
        if self.streams and record.get("source") == "packet" and record.get("protocol") == "TCP":
            try:
                session_id = self.streams.ingest(record)
                if session_id:
                    record["tcp_session_id"] = session_id
            except Exception as exc:
                logging.getLogger(__name__).exception("TCP session capture failed")
                record["tcp_session_error"] = str(exc)
        with self._lock:
            if can_intercept:
                rule = next((r for r in self._rules if matches(r, record, self.store.bodies)), None)
                if rule and len(self._pending) < self.config.pending_limit:
                    seconds = rule["timeout_seconds"]
                    record.update(state="pending", rule_id=rule["id"], rule_name=rule["name"], timeout_seconds=seconds,
                                  deadline=time.time() + seconds)
                    self._pending[record["id"]] = {"deadline": time.monotonic() + seconds, "decision": None}
                elif rule:
                    record["detail"] = "等待队列已满，已自动放行"
            try:
                return self.store.save(record)
            except Exception:
                # A failed persistence cannot leave an unpollable queue slot behind.
                self._pending.pop(record["id"], None)
                raise

    def update(self, record_id: str, changes: dict):
        with self._lock:
            if changes.get("state") and changes["state"] not in {"pending", "resolving"}:
                self._pending.pop(record_id, None)
            return self.store.update(record_id, changes)

    def pending_count(self):
        with self._lock:
            return len(self._pending)

    def expire_http(self, age_seconds: float = 120) -> int:
        with self._lock:
            expired = self.store.expire_http(age_seconds)
            for record_id in expired:
                self._pending.pop(record_id, None)
            return len(expired)

    def resolve(self, record_id: str, action: str, edits: dict):
        with self._lock:
            record = self.store.get(record_id)
            if not record or record.get("state") not in {"pending", "resolving"}:
                self._pending.pop(record_id, None)
                raise ValueError("此请求已处理或已失效，请刷新列表")
            entry = self._pending.get(record_id)
            if not entry or entry["decision"] is not None:
                raise ValueError("此请求已处理或已失效，请刷新列表")
            if time.monotonic() >= entry["deadline"]:
                raise ValueError("拦截已超时，将自动放行")
            entry["decision"] = {"action": action, "edits": edits}
            self.store.update(record_id, {"state": "resolving"})

    def take_decision(self, record_id: str):
        with self._lock:
            record = self.store.get(record_id)
            if not record or record.get("state") not in {"pending", "resolving"}:
                self._pending.pop(record_id, None)
                return None
            entry = self._pending.get(record_id)
            if not entry:
                return None
            decision = entry["decision"]
            if decision is None and time.monotonic() >= entry["deadline"]:
                decision = {"action": "accept", "edits": {}}
                self.store.update(record_id, {"state": "resolving", "detail": "拦截超时，自动放行原始内容"})
            if decision is not None:
                self._pending.pop(record_id, None)
            return decision

    def demo_tick(self):
        if not self.config.demo:
            return
        with self._lock:
            ids = list(self._pending)
        for record_id in ids:
            decision = self.take_decision(record_id)
            if decision:
                from .demo import apply_demo_edits
                record = self.store.get(record_id)
                if record and decision["action"] == "accept":
                    self.store.save(apply_demo_edits(record, decision.get("edits", {}), self.store.bodies))
                self.update(record_id, {"state": "dropped" if decision["action"] == "drop" else "forwarded",
                                        "detail": "演示操作：未发送真实网络流量", "modified": bool(decision["edits"])})
