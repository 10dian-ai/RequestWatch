"""Short-lived, immutable readable views; original captures remain untouched."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import threading
import time
import uuid

from .stream_decode import DECODER_VERSION, decode_stream_file


class ReadableCache:
    def __init__(self, data_dir):
        self.root = Path(data_dir).resolve() / "readable_cache"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()

    def _path(self, revision, suffix):
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{64}", revision):
            raise ValueError("无效的解析版本")
        path = self.root / (revision + suffix)
        if path.is_symlink() or path.resolve().parent != self.root:
            raise ValueError("无效的解析文件")
        return path

    def get(self, owner, revision):
        with self.lock:
            meta_path = self._path(revision, ".json")
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            if meta.pop("owner", None) != owner:
                raise ValueError("解析内容不属于此记录")
            path = self._path(revision, ".txt")
            if not path.is_file():
                raise FileNotFoundError()
            meta_path.touch()
            path.touch()
            return meta, path

    def build(self, owner, source, **options):
        source = Path(source)
        signature = json.dumps([owner, str(source.resolve()), source.stat().st_size, DECODER_VERSION, options], sort_keys=True)
        revision = hashlib.sha256(signature.encode()).hexdigest()
        try:
            return self.get(owner, revision)[0]
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        temporary = self.root / (".decode-" + uuid.uuid4().hex)
        meta_tmp = temporary.with_suffix(".json")
        try:
            result = decode_stream_file(source, temporary, **options)
            temporary.chmod(0o600)
            result.update(revision=revision, content_size=temporary.stat().st_size)
            meta_tmp.write_text(json.dumps({**result, "owner": owner}, ensure_ascii=False), encoding="utf-8")
            meta_tmp.chmod(0o600)
            with self.lock:
                os.replace(temporary, self._path(revision, ".txt"))
                os.replace(meta_tmp, self._path(revision, ".json"))
            return result
        finally:
            temporary.unlink(missing_ok=True)
            meta_tmp.unlink(missing_ok=True)

    def gc(self, age_seconds=600):
        with self.lock:
            cutoff = time.time() - age_seconds
            for path in self.root.iterdir():
                if path.is_symlink():
                    continue
                try:
                    if path.is_file() and path.stat().st_mtime < cutoff:
                        path.unlink()
                except FileNotFoundError:
                    pass
