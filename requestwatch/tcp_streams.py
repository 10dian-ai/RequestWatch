"""Disk-backed TCP observation reassembly, never a claim to decrypted application data.

First-observed bytes win on conflicting overlaps. Missing sequence ranges are
reported separately; exported files concatenate observed ranges without invented
padding. This is a capture of observed packets, not proof of endpoint delivery.
"""
from __future__ import annotations

import base64
import codecs
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
import uuid

from .network import parse_packet


class TCPStreamStore:
    def __init__(self, data_dir, max_sessions=1000, idle_timeout=300):
        self.root = Path(data_dir).resolve() / "tcp_sessions"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.max_sessions = max(1, int(max_sessions))
        self.idle_timeout = idle_timeout
        self.lock = threading.RLock()
        self._last_gc = 0.0
        self.db = sqlite3.connect(str(self.root / "sessions.sqlite3"), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self.db:
            self.db.executescript("""
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=NORMAL;
                PRAGMA foreign_keys=ON;
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, flow TEXT NOT NULL, updated_at REAL NOT NULL,
                    state TEXT NOT NULL, data TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS sessions_flow ON sessions(flow,updated_at DESC);
                CREATE INDEX IF NOT EXISTS sessions_time ON sessions(updated_at DESC);
                CREATE TABLE IF NOT EXISTS ranges (
                    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    direction TEXT NOT NULL, start INTEGER NOT NULL, end INTEGER NOT NULL,
                    file_offset INTEGER NOT NULL,
                    PRIMARY KEY(session_id,direction,start));
                CREATE TABLE IF NOT EXISTS seen (
                    record_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE);
            """)
            for row in self.db.execute("SELECT data FROM sessions WHERE state='open'").fetchall():
                item = json.loads(row[0])
                item["state"] = "interrupted"
                self._save(item)
        for path in (self.root, self.root / "sessions.sqlite3"):
            try:
                path.chmod(0o700 if path.is_dir() else 0o600)
            except OSError:
                pass

    @staticmethod
    def _direction():
        return {"anchor": None, "high_end": 0, "start_offset": None,
                "fin_offset": None, "byte_count": 0, "segment_count": 0,
                "syn_seen": False, "fin_seen": False, "overlap_conflicts": 0,
                "truncated_packets": 0, "fragmented_packets": 0, "sequence_anomalies": 0, "revision": 0}

    @staticmethod
    def _position(seq, data):
        delta = (seq - data["anchor"]) & 0xffffffff
        near = data["high_end"]
        return delta + ((near - delta + (1 << 31)) // (1 << 32)) * (1 << 32)

    def _save(self, item):
        self.db.execute("INSERT INTO sessions VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                        "updated_at=excluded.updated_at,state=excluded.state,data=excluded.data",
                        (item["id"], item["flow"], item["updated_at"], item["state"],
                         json.dumps(item, ensure_ascii=False)))

    def _spool(self, session_id, direction):
        return self.root / f"{session_id}-{direction}.spool"

    def _new(self, info, now, flow):
        # A SYN-ACK identifies the other endpoint as the client even if its SYN was missed.
        reverse = bool(info.flags & 2 and info.flags & 16)
        client = (info.dst_ip, info.dst_port) if reverse else (info.src_ip, info.src_port)
        server = (info.src_ip, info.src_port) if reverse else (info.dst_ip, info.dst_port)
        return {"id": uuid.uuid4().hex, "flow": flow, "created_at": now, "updated_at": now,
                "client_ip": client[0], "client_port": client[1],
                "server_ip": server[0], "server_port": server[1],
                "container_id": "", "container_name": "", "container_ids": [],
                "container_names": [], "packet_count": 0, "state": "open",
                "midstream": not bool(info.flags & 2 and not info.flags & 16),
                "direction_inferred": not bool(info.flags & 2),
                "directions": {"client": self._direction(), "server": self._direction()}}

    def _append(self, session_id, direction, start, payload):
        """Append only new ranges, comparing overlaps in packet-sized bounded memory."""
        end = start + len(payload)
        path = self._spool(session_id, direction)
        overlaps = self.db.execute("SELECT start,end,file_offset FROM ranges WHERE session_id=? "
                                  "AND direction=? AND end>? AND start<? ORDER BY start",
                                  (session_id, direction, start, end)).fetchall()
        uncovered, cursor, conflicts = [], start, 0
        if overlaps:
            with path.open("rb") as stream:
                for row in overlaps:
                    left, right = max(start, row["start"]), min(end, row["end"])
                    if cursor < left:
                        uncovered.append((cursor, left))
                    stream.seek(row["file_offset"] + left - row["start"])
                    old = stream.read(right - left)
                    conflicts += sum(a != b for a, b in zip(old, payload[left-start:right-start]))
                    cursor = max(cursor, right)
        if cursor < end:
            uncovered.append((cursor, end))
        added = 0
        if uncovered:
            with path.open("ab") as stream:
                for left, right in uncovered:
                    offset = stream.tell()
                    stream.write(payload[left-start:right-start])
                    # Common in-order traffic stays a single range; no per-packet full-file rewrite.
                    previous = self.db.execute("SELECT start,end,file_offset FROM ranges WHERE "
                                               "session_id=? AND direction=? AND end=?",
                                               (session_id, direction, left)).fetchone()
                    if previous and previous["file_offset"] + previous["end"] - previous["start"] == offset:
                        self.db.execute("UPDATE ranges SET end=? WHERE session_id=? AND direction=? AND start=?",
                                        (right, session_id, direction, previous["start"]))
                    else:
                        self.db.execute("INSERT INTO ranges VALUES(?,?,?,?,?)",
                                        (session_id, direction, left, right, offset))
                    added += right-left
            try:
                path.chmod(0o600)
            except OSError:
                pass
        return added, conflicts

    def ingest(self, record):
        if record.get("protocol") != "TCP" or record.get("source", "packet") != "packet":
            return None
        try:
            info = parse_packet(base64.b64decode(record.get("raw_b64", ""), validate=True))
        except (ValueError, TypeError):
            return None
        if info.protocol != "TCP" or info.src_port is None or info.dst_port is None:
            return None
        now = float(record.get("created_at", time.time()))
        flow = json.dumps(sorted(((info.src_ip, info.src_port), (info.dst_ip, info.dst_port))))
        with self.lock, self.db:
            if record.get("id"):
                duplicate = self.db.execute("SELECT session_id FROM seen WHERE record_id=?",
                                            (str(record["id"]),)).fetchone()
                if duplicate:
                    return duplicate[0]
            row = self.db.execute("SELECT data FROM sessions WHERE flow=? ORDER BY updated_at DESC LIMIT 1",
                                  (flow,)).fetchone()
            item = json.loads(row[0]) if row else None
            initial_syn = bool(info.flags & 2 and not info.flags & 16)
            if item:
                direction = "client" if (info.src_ip, info.src_port) == (item["client_ip"], item["client_port"]) else "server"
                data = item["directions"][direction]
                same_syn = data["syn_seen"] and ((info.sequence + 1) & 0xffffffff) == data["anchor"]
                expired = now - item["updated_at"] > self.idle_timeout
                new_syn = initial_syn and (not same_syn or item["state"] != "open")
                # Payload beyond an observed close belongs to an unobserved new incarnation;
                # ordinary final ACKs and retransmissions within the old ranges stay with it.
                closed_reuse = False
                if item["state"] in ("closed", "reset") and info.payload and data["anchor"] is not None:
                    incoming = self._position(info.sequence, data)
                    lower_bound = data["start_offset"]
                    if lower_bound is None:
                        # Midstream/out-of-order capture may extend before the
                        # initial anchor. Those negative offsets are still part
                        # of this connection, including late retransmissions.
                        lower_bound = self.db.execute(
                            "SELECT MIN(start) FROM ranges WHERE session_id=? AND direction=?",
                            (item["id"], direction)).fetchone()[0]
                    closed_reuse = (incoming < (lower_bound if lower_bound is not None else 0)
                                    or (data["fin_offset"] is not None
                                        and incoming + len(info.payload) > data["fin_offset"])
                                    or (item["state"] == "reset"
                                        and incoming + len(info.payload) > data["high_end"]))
                if expired or new_syn or closed_reuse or item["state"] == "interrupted":
                    if item["state"] == "open":
                        item["state"] = "interrupted"
                        self._save(item)
                    item = None
            is_new = item is None
            if item is None:
                item = self._new(info, now, flow)
                self._save(item)  # Foreign-key target for ranges.
            direction = "client" if (info.src_ip, info.src_port) == (item["client_ip"], item["client_port"]) else "server"
            data = item["directions"][direction]
            payload_seq = (info.sequence + int(bool(info.flags & 2))) & 0xffffffff
            if data["anchor"] is None:
                data["anchor"] = payload_seq
            position = self._position(payload_seq, data)
            data["high_end"] = max(data["high_end"], position + len(info.payload))
            if info.flags & 2:
                data["syn_seen"] = True
                data["start_offset"] = position
                if direction == "client" and not info.flags & 16:
                    item["midstream"] = False
            data["truncated_packets"] += int(info.truncated)
            data["fragmented_packets"] += int(info.fragmented)
            # Fragmented transport payload cannot be distinguished safely from a complete segment.
            if info.payload and not info.fragmented:
                added, conflicts = self._append(item["id"], direction, position, info.payload)
                data["byte_count"] += added
                data["overlap_conflicts"] += conflicts
                data["segment_count"] += 1
                if added:
                    data["revision"] += 1
            if ((info.payload or info.flags & 3) and data["start_offset"] is not None
                    and position < data["start_offset"]):
                data["sequence_anomalies"] = data.get("sequence_anomalies", 0) + 1
            if info.flags & 1:
                if position + len(info.payload) < data["high_end"]:
                    data["sequence_anomalies"] = data.get("sequence_anomalies", 0) + 1
                data["fin_seen"] = True
                data["fin_offset"] = position + len(info.payload)
            if info.flags & 4:
                item["state"] = "reset"
            elif all(d["fin_seen"] for d in item["directions"].values()):
                item["state"] = "closed"
            item["packet_count"] += 1
            item["updated_at"] = max(now, item["updated_at"])
            for side in ("", "src_", "dst_"):
                cid, name = record.get(side + "container_id", ""), record.get(side + "container_name", "")
                if cid and cid not in item["container_ids"]:
                    item["container_ids"].append(cid)
                if name and name not in item["container_names"]:
                    item["container_names"].append(name)
            item["container_id"] = item["container_ids"][0] if item["container_ids"] else ""
            item["container_name"] = item["container_names"][0] if item["container_names"] else ""
            self._save(item)
            if record.get("id"):
                self.db.execute("INSERT INTO seen VALUES(?,?)", (str(record["id"]), item["id"]))
            # Record IDs only deduplicate a bounded recent window, including duplicate capture paths.
            self.db.execute("DELETE FROM seen WHERE rowid <= (SELECT MAX(rowid)-65536 FROM seen)")
            # Retention is needed only when adding a session, not for every packet.
            expired_rows = (self.db.execute("SELECT id FROM sessions ORDER BY updated_at DESC LIMIT -1 OFFSET ?",
                                            (self.max_sessions,)).fetchall() if is_new else [])
            for old in expired_rows:
                self.db.execute("DELETE FROM sessions WHERE id=?", (old[0],))
                for path in self.root.glob(old[0] + "-*"):
                    if path.is_file() and (path.suffix == ".spool" or time.time() - path.stat().st_mtime > 600):
                        try:
                            path.unlink()
                        except OSError:
                            pass  # A download may still hold it on Windows.
            if is_new and time.monotonic() - self._last_gc > 60:
                self._last_gc = time.monotonic()
                retained = {row[0] for row in self.db.execute("SELECT id FROM sessions")}
                for path in self.root.iterdir():
                    match = re.fullmatch(r"([0-9a-f]{32})-(client|server)-.*\.(raw|text|latin1|tmp)", path.name)
                    if match and match[1] not in retained and time.time() - path.stat().st_mtime > 600:
                        try:
                            path.unlink()
                        except OSError:
                            pass
            return item["id"]

    def _describe_direction(self, session_id, direction, data):
        result = {k: v for k, v in data.items() if k not in ("anchor", "high_end", "start_offset", "fin_offset", "revision")}
        rows = self.db.execute("SELECT start,end FROM ranges WHERE session_id=? AND direction=? ORDER BY start",
                               (session_id, direction))
        cursor, first, gaps, missing, gap_count = data["start_offset"], None, [], 0, 0
        for row in rows:
            if first is None:
                first = row["start"]
            if cursor is None:
                cursor = row["start"]
            if row["start"] > cursor:
                size = row["start"] - cursor
                if len(gaps) < 256:
                    gaps.append({"start": cursor, "end": row["start"], "size": size})
                missing += size
                gap_count += 1
            cursor = max(cursor, row["end"])
        if cursor is None:
            cursor = data["start_offset"] or 0
        if data["fin_offset"] is not None and data["fin_offset"] > cursor:
            size = data["fin_offset"] - cursor
            if len(gaps) < 256:
                gaps.append({"start": cursor, "end": data["fin_offset"], "size": size})
            missing += size
            gap_count += 1
        outside_fin = data["fin_offset"] is not None and cursor > data["fin_offset"]
        result.update(missing_bytes=missing, gap_count=gap_count, gaps=gaps,
                      gaps_truncated=gap_count > len(gaps), first_offset=first,
                      complete=bool(data["syn_seen"] and data["fin_seen"] and not missing
                                    and not data["truncated_packets"] and not data["fragmented_packets"]
                                    and not data["overlap_conflicts"] and not outside_fin
                                    and not data.get("sequence_anomalies", 0)))
        return result

    def session_id_for_record(self, record_id):
        """Resolve an exact recent observation without confusing reused TCP tuples.

        The bounded deduplication index can expire independently of a retained
        record. A missing entry must stay unknown, never guess from IP/ports.
        """
        if not isinstance(record_id, str) or not record_id:
            return None
        with self.lock:
            row = self.db.execute("SELECT session_id FROM seen WHERE record_id=?", (record_id,)).fetchone()
            return row[0] if row else None

    def get(self, session_id):
        with self.lock:
            row = self.db.execute("SELECT data FROM sessions WHERE id=?", (session_id,)).fetchone()
            if not row:
                return None
            item = json.loads(row[0])
            item.pop("flow", None)
            item["directions"] = {side: self._describe_direction(session_id, side, data)
                                  for side, data in item["directions"].items()}
            item["complete"] = item["state"] == "closed" and not item["midstream"] and all(d["complete"] for d in item["directions"].values())
            item["export_semantics"] = "observed-bytes-in-sequence-order; missing ranges omitted; first-observed overlap wins"
            return item

    def _range_snapshot(self, session_id, direction):
        # Ranges point to immutable bytes in an append-only spool. Copy the small
        # index entries under the DB lock, never hold that lock while reading bodies.
        with self.lock:
            return tuple(tuple(row) for row in self.db.execute(
                "SELECT start,end,file_offset FROM ranges WHERE session_id=? "
                "AND direction=? ORDER BY start", (session_id, direction)).fetchall())

    @staticmethod
    def _read_chunks(path, rows, gap_events=False):
        if not rows:
            return
        # Retention can remove a spool after its metadata snapshot. Let callers
        # distinguish that FileNotFoundError from real I/O errors or corruption.
        with path.open("rb") as stream:
            previous_end = None
            for start, end, file_offset in rows:
                if gap_events and previous_end is not None and start > previous_end:
                    yield None
                previous_end = end
                stream.seek(file_offset)
                remaining = end - start
                while remaining:
                    chunk = stream.read(min(65536, remaining))
                    if not chunk:
                        raise OSError("TCP spool is shorter than its recorded ranges")
                    yield chunk
                    remaining -= len(chunk)

    def _chunks(self, session_id, direction, gap_events=False):
        rows = self._range_snapshot(session_id, direction)
        yield from self._read_chunks(self._spool(session_id, direction), rows, gap_events)

    def _contains(self, session_id, query):
        for side in ("client", "server"):
            # Incremental UTF-8 handles characters crossing packet boundaries; latin1 preserves every byte.
            for encoding in ("utf-8", "latin-1"):
                decoder = codecs.getincrementaldecoder(encoding)(errors="replace")
                tail = ""
                for chunk in self._chunks(session_id, side, gap_events=True):
                    if chunk is None:
                        decoder = codecs.getincrementaldecoder(encoding)(errors="replace")
                        tail = ""
                        continue
                    text = tail + decoder.decode(chunk).casefold()
                    if query in text:
                        return True
                    tail = text[-max(1, len(query)-1):]
                if query in tail + decoder.decode(b"", final=True).casefold():
                    return True
        return False

    def list_sessions(self, container_id="", q="", limit=100, offset=0):
        limit, offset = max(1, min(500, int(limit))), max(0, int(offset))
        with self.lock:
            rows = self.db.execute("SELECT id,data FROM sessions ORDER BY updated_at DESC").fetchall()
        ids, total, query = [], 0, q.casefold()
        for row in rows:
            item = json.loads(row["data"])
            if container_id and container_id != "any" and container_id not in item["container_ids"]:
                continue
            try:
                if query and query not in json.dumps(item, ensure_ascii=False).casefold() and not self._contains(row["id"], query):
                    continue
            except FileNotFoundError:
                continue  # Concurrent retention removed this snapshot's spool.
            if offset <= total < offset + limit:
                ids.append(row["id"])
            total += 1
        # A session may be evicted during a long search; avoid returning null rows.
        items = [item for sid in ids if (item := self.get(sid)) is not None]
        return {"items": items, "total": total - (len(ids) - len(items))}

    def body_path(self, session_id, direction, view="raw", *, with_metadata=False):
        if not re.fullmatch(r"[0-9a-f]{32}", session_id or "") or direction not in ("client", "server"):
            raise ValueError("Invalid TCP session or direction")
        if view not in ("raw", "text", "latin1"):
            raise ValueError("view must be raw, text, or latin1")
        with self.lock:
            row = self.db.execute("SELECT data FROM sessions WHERE id=?", (session_id,)).fetchone()
            if not row:
                raise KeyError(session_id)
            data = json.loads(row[0])["directions"][direction]
            revision = data["revision"]
            snapshot_metadata = self._describe_direction(session_id, direction, data) if with_metadata else None
            # Invalidate older UTF-8 exports which could decode a character
            # across a missing sequence range.
            suffix = "-utf8-v2" if view == "text" else ""
            path = self.root / f"{session_id}-{direction}-{revision}{suffix}.{view}"
            if path.exists():
                path.touch()  # Extend the download grace period before handing the path to the API.
                return (path, snapshot_metadata) if with_metadata else path
            rows = self._range_snapshot(session_id, direction)
        # Snapshot revision and ranges are immutable even while capture appends data.
        # Export the snapshot without blocking ingest or substituting a newer revision.
        temporary = self.root / f"{session_id}-{direction}-{uuid.uuid4().hex}.tmp"
        decoder_factory = codecs.getincrementaldecoder("utf-8" if view == "text" else "latin-1")
        decoder = decoder_factory(errors="replace")
        try:
            with temporary.open("xb") as output:
                for chunk in self._read_chunks(self._spool(session_id, direction), rows, gap_events=view == "text"):
                    if chunk is None:
                        # A missing byte range cannot join two partial UTF-8
                        # sequences into a character that was never captured.
                        output.write(decoder.decode(b"", final=True).encode("utf-8"))
                        decoder = decoder_factory(errors="replace")
                        continue
                    output.write(chunk if view == "raw" else decoder.decode(chunk).encode("utf-8"))
                if view != "raw":
                    output.write(decoder.decode(b"", final=True).encode("utf-8"))
            temporary.chmod(0o600)
            with self.lock:
                if path.exists():
                    path.touch()  # Another exporter already wrote this same immutable revision.
                else:
                    os.replace(temporary, path)
            # Brief locks protect the download grace period against a concurrent touch.
            for old in self.root.glob(f"{session_id}-{direction}-*.{view}"):
                if old == path:
                    continue
                with self.lock:
                    try:
                        if time.time() - old.stat().st_mtime > 600:
                            old.unlink()
                    except FileNotFoundError:
                        pass
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        return (path, snapshot_metadata) if with_metadata else path

    def close(self):
        with self.lock:
            self.db.close()
