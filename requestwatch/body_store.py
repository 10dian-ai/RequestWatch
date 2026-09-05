"""Complete HTTP body storage, independent of the web/proxy dependencies."""
from __future__ import annotations

import base64
import codecs
import hashlib
import os
import re
import tempfile
import zlib
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

    def put_file(self, source, size=None) -> str:
        """Copy an immutable prefix without loading the full capture into memory."""
        source = Path(source)
        size = source.stat().st_size if size is None else size
        digest = hashlib.sha256()
        fd, temporary = tempfile.mkstemp(prefix=".body-", dir=self.root)
        try:
            with source.open("rb") as incoming, os.fdopen(fd, "wb") as output:
                remaining = size
                while remaining:
                    chunk = incoming.read(min(PREVIEW_BYTES, remaining))
                    if not chunk:
                        raise OSError("Body spool is shorter than its snapshot")
                    digest.update(chunk)
                    output.write(chunk)
                    remaining -= len(chunk)
                output.flush()
                os.fsync(output.fileno())
            ref = digest.hexdigest()
            target = self.path(ref)
            if target.is_file():
                target.touch()
            else:
                os.replace(temporary, target)
            return ref
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def snapshot_file(self, prefix, source, *, size=None, complete=True,
                      content_type="", content_encoding="", infer_encoding=None):
        """Save full raw bytes and a bounded-memory decoded text snapshot.

        Open streams may end in a compressed block or a multibyte character.
        Those undecidable suffix bytes remain in raw storage until more arrive.
        """
        raw_ref = self.put_file(source, size)
        raw_path = self.path(raw_ref)
        raw_size = raw_path.stat().st_size
        with raw_path.open("rb") as incoming:
            preview = incoming.read(PREVIEW_BYTES)
        result = {prefix + "_body_ref": raw_ref, prefix + "_body_size": raw_size,
                  prefix + "_body_b64": base64.b64encode(preview).decode("ascii") if raw_size <= PREVIEW_BYTES else None,
                  prefix + "_body_complete": complete, prefix + "_truncated": False,
                  prefix + "_preview_truncated": raw_size > PREVIEW_BYTES,
                  prefix + "_body_error": None, prefix + "_body_decode_error": None,
                  prefix + "_body_binary": False, prefix + "_sse_utf8": False}
        with tempfile.TemporaryDirectory(prefix=".decode-body-", dir=self.root) as folder:
            work = Path(folder)
            current = raw_path
            try:
                codings = [x.strip().lower() for x in content_encoding.split(",") if x.strip()]
                for number, coding in enumerate(reversed(codings)):
                    if coding == "identity":
                        continue
                    decoded = work / (str(number) + ".bin")
                    _decode_compressed_file(current, decoded, coding, complete)
                    current = decoded
                with current.open("rb") as incoming:
                    sample = incoming.read(PREVIEW_BYTES)
                if "text/event-stream" in content_type.lower():
                    encoding = "utf-8-sig"
                elif infer_encoding is not None:
                    encoding = infer_encoding(content_type, sample)
                else:
                    declared = re.search(r"charset\s*=\s*[\"']?([\w.:-]+)", content_type, re.I)
                    encoding = declared.group(1) if declared else "utf-8-sig"
                text_path = work / "text.txt"
                decoder = codecs.getincrementaldecoder(encoding)(errors="strict")
                with current.open("rb") as incoming, text_path.open("wb") as output:
                    while chunk := incoming.read(PREVIEW_BYTES):
                        text = decoder.decode(chunk)
                        result[prefix + "_body_binary"] |= "\x00" in text or "\ufffd" in text
                        output.write(text.encode("utf-8"))
                    final = decoder.decode(b"", final=complete)
                    result[prefix + "_body_binary"] |= "\x00" in final or "\ufffd" in final
                    output.write(final.encode("utf-8"))
                text_ref = self.put_file(text_path)
                text_size = text_path.stat().st_size
                with text_path.open("rb") as incoming:
                    text_preview = incoming.read(PREVIEW_BYTES).decode("utf-8", errors="ignore")
                result.update({prefix + "_text_ref": text_ref, prefix + "_text_size": text_size,
                               prefix + "_sse_utf8": "text/event-stream" in content_type.lower(),
                               prefix + "_body_text": text_preview,
                               prefix + "_preview_truncated": raw_size > PREVIEW_BYTES or text_size > PREVIEW_BYTES})
            except (ValueError, LookupError, UnicodeError, zlib.error, ImportError) as exc:
                # Preserve raw capture even when its encoding is unsupported or invalid.
                result.update({prefix + "_text_ref": None, prefix + "_text_size": 0,
                               prefix + "_body_text": "", prefix + "_body_binary": True,
                               prefix + "_body_decode_error": str(exc)})
        return result

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
                snapshot.update({prefix + "_body_complete": False,
                                 prefix + "_truncated": record.get(prefix + "_truncated", True),
                                 prefix + "_body_size": original_size})
            record.update(snapshot)
        record["payload_text"] = record.get("payload_text", "")[:PREVIEW_BYTES]
        return record


def _decode_compressed_file(source, target, coding, complete):
    if not source.stat().st_size:
        target.write_bytes(b"")
        return
    if coding in {"gzip", "x-gzip", "deflate"}:
        modes = [47] if coding in {"gzip", "x-gzip"} else [15, -15]
        for number, mode in enumerate(modes):
            try:
                decoder = zlib.decompressobj(mode)
                with source.open("rb") as incoming, target.open("wb") as output:
                    while chunk := incoming.read(PREVIEW_BYTES):
                        if decoder.eof:
                            if coding == "deflate":
                                raise zlib.error("Extra bytes after deflate stream")
                            decoder = zlib.decompressobj(mode)
                        pending = chunk
                        while pending:
                            output.write(decoder.decompress(pending, PREVIEW_BYTES))
                            pending = decoder.unconsumed_tail
                            if decoder.eof:
                                pending = decoder.unused_data
                                if pending:
                                    if coding == "deflate":
                                        raise zlib.error("Extra bytes after deflate stream")
                                    decoder = zlib.decompressobj(mode)
                    if complete and not decoder.eof:
                        raise ValueError("Compressed response ended before its checksum/trailer")
                return
            except zlib.error:
                if number == len(modes)-1:
                    raise
    elif coding == "br":
        import brotli
        decoder = brotli.Decompressor()
        try:
            with source.open("rb") as incoming, target.open("wb") as output:
                while chunk := incoming.read(PREVIEW_BYTES):
                    decoded = decoder.process(chunk, output_buffer_limit=PREVIEW_BYTES)
                    output.write(decoded)
                    while len(decoded) >= PREVIEW_BYTES or not decoder.can_accept_more_data():
                        decoded = decoder.process(b"", output_buffer_limit=PREVIEW_BYTES)
                        output.write(decoded)
            if complete and not decoder.is_finished():
                raise ValueError("Brotli response ended before the compressed stream completed")
        except brotli.error as exc:
            raise ValueError("Invalid Brotli response: " + str(exc)) from exc
    elif coding == "zstd":
        import zstandard
        decoder = zstandard.ZstdDecompressor().decompressobj()
        try:
            with source.open("rb") as incoming, target.open("wb") as output:
                # Small compressed input slices bound each decompression call;
                # Zstandard decoded blocks are at most 128 KiB.
                while chunk := incoming.read(64):
                    if decoder.eof:
                        decoder = zstandard.ZstdDecompressor().decompressobj()
                    output.write(decoder.decompress(chunk))
                    while decoder.unused_data:
                        remaining = decoder.unused_data
                        decoder = zstandard.ZstdDecompressor().decompressobj()
                        output.write(decoder.decompress(remaining))
            if complete and not decoder.eof:
                raise ValueError("Zstandard response ended before the compressed stream completed")
        except zstandard.ZstdError as exc:
            raise ValueError("Invalid Zstandard response: " + str(exc)) from exc
    else:
        raise ValueError("Unsupported Content-Encoding: " + coding)
