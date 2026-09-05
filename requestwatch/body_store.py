"""Complete HTTP body storage, independent of the web/proxy dependencies."""
from __future__ import annotations

import base64
import hashlib
import os
import re
import tempfile
from pathlib import Path

PREVIEW_BYTES = 64 * 1024
REFERENCE = re.compile(r"[0-9a-f]{64}")


class BodyStore:
    def __init__(self, data_dir):
        self.root = Path(data_dir).resolve() / "body_blobs"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def path(self, ref: str) -> Path:
        if not isinstance(ref, str) or not REFERENCE.fullmatch(ref):
            raise ValueError("无效的正文引用")
        path = self.root / (ref + ".blob")
        if path.is_symlink() or path.resolve().parent != self.root:
            raise ValueError("正文引用不能指向存储目录之外")
        return path

    def put(self, data: bytes) -> str:
        ref = hashlib.sha256(data).hexdigest()
        target = self.path(ref)
        if target.is_file():
            os.utime(target, None)
            return ref
        fd, temporary = tempfile.mkstemp(prefix=".body-", dir=self.root)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return ref

    def snapshot(self, prefix: str, raw: bytes, text: str) -> dict:
        encoded = text.encode("utf-8", errors="replace")
        return {
            prefix + "_body_ref": self.put(raw),
            prefix + "_text_ref": self.put(encoded),
            prefix + "_body_size": len(raw),
            prefix + "_text_size": len(encoded),
            prefix + "_body_text": encoded[:PREVIEW_BYTES].decode("utf-8", errors="ignore"),
            prefix + "_body_b64": base64.b64encode(raw).decode("ascii") if len(raw) <= PREVIEW_BYTES else None,
            prefix + "_body_complete": True,
            prefix + "_truncated": False,
            prefix + "_preview_truncated": len(raw) > PREVIEW_BYTES or len(encoded) > PREVIEW_BYTES,
        }

    def read(self, ref: str) -> bytes:
        return self.path(ref).read_bytes()

    def read_body(self, record: dict, prefix: str = "request") -> bytes:
        ref = record.get(prefix + "_body_ref")
        if ref:
            return self.read(ref)
        encoded = record.get(prefix + "_body_b64")
        if encoded is not None:
            return base64.b64decode(encoded, validate=True)
        return record.get(prefix + "_body_text", "").encode("utf-8")

    def read_text(self, record: dict, prefix: str = "request") -> str:
        ref = record.get(prefix + "_text_ref")
        if ref:
            return self.read(ref).decode("utf-8", errors="replace")
        return record.get(prefix + "_body_text", "")

    def contains(self, record: dict, needle: str) -> bool:
        needle = needle.casefold()
        if not needle:
            return True
        for prefix in ("request", "response"):
            ref = record.get(prefix + "_text_ref")
            if not ref:
                continue
            try:
                with self.path(ref).open("r", encoding="utf-8", errors="replace", newline="") as stream:
                    overlap = ""
                    while chunk := stream.read(PREVIEW_BYTES):
                        combined = overlap + chunk.casefold()
                        if needle in combined:
                            return True
                        overlap = combined[-(len(needle) - 1):] if len(needle) > 1 else ""
            except (OSError, ValueError):
                continue
        return False

    def externalize(self, record: dict) -> dict:
        record = dict(record)
        if record.get("source") != "http":
            return record
        for prefix in ("request", "response"):
            if record.get(prefix + "_body_ref"):
                for kind in ("body", "text"):
                    ref = record.get(prefix + "_" + kind + "_ref")
                    if ref:
                        if not self.path(ref).is_file():
                            raise ValueError("完整正文文件不存在，请重新抓取")
                        os.utime(self.path(ref), None)
                continue
            if not any(prefix + key in record for key in ("_body_text", "_body_b64")):
                continue
            raw = self.read_body(record, prefix)
            text = record.get(prefix + "_body_text")
            if text is None:
                text = raw.decode("utf-8", errors="replace")
            complete = not record.get(prefix + "_truncated", False) and record.get(prefix + "_body_complete", True)
            original_size = record.get(prefix + "_body_size", len(raw))
            snapshot = self.snapshot(prefix, raw, text)
            if not complete:
                snapshot.update({prefix + "_body_complete": False, prefix + "_truncated": True,
                                 prefix + "_body_size": original_size})
            record.update(snapshot)
        record["payload_text"] = record.get("payload_text", "")[:PREVIEW_BYTES]
        return record
