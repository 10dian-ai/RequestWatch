from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


def env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).lower() in {"true", "1", "yes", "on"}


@dataclass
class Config:
    host: str = field(default_factory=lambda: os.getenv("RW_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.getenv("RW_PORT", "7030")))
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("RW_DATA_DIR", "data")))
    token: str = field(default_factory=lambda: os.getenv("RW_TOKEN", ""))
    capture_enabled: bool = field(default_factory=lambda: env_bool("RW_CAPTURE", True))
    interfaces: str = field(default_factory=lambda: os.getenv("RW_INTERFACES", "any"))
    queue_num: int = field(default_factory=lambda: int(os.getenv("RW_QUEUE_NUM", "7030")))
    protected_ports: tuple[int, ...] = (22, 7030, 8080)
    pending_limit: int = 128
    max_records: int = field(default_factory=lambda: int(os.getenv("RW_MAX_RECORDS", "10000")))
    proxy_enabled: bool = field(default_factory=lambda: env_bool("RW_PROXY", True))
    proxy_host: str = field(default_factory=lambda: os.getenv("RW_PROXY_HOST", "127.0.0.1"))
    proxy_port: int = field(default_factory=lambda: int(os.getenv("RW_PROXY_PORT", "8080")))
    proxy_auth: str = field(default_factory=lambda: os.getenv("RW_PROXY_AUTH", ""))
    demo: bool = False

    def prepare(self) -> None:
        self.data_dir = Path(self.data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        extra = os.getenv("RW_PROTECTED_PORTS", "22").split(",")
        self.protected_ports = tuple(sorted({self.port, self.proxy_port, *(int(p) for p in extra if p.strip())}))
        if not all(1 <= p <= 65535 for p in self.protected_ports):
            raise ValueError("端口必须在 1–65535 范围内")
        if not 1 <= self.queue_num <= 65535 or self.max_records < 100:
            raise ValueError("队列编号无效，或保留记录数小于 100")
        token_file = self.data_dir / "admin-token"
        if not self.token:
            if token_file.exists():
                self.token = token_file.read_text(encoding="utf-8").strip()
            else:
                self.token = secrets.token_urlsafe(32)
                fd = os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    stream.write(self.token + "\n")
        if len(self.token) < 16:
            raise ValueError("RW_TOKEN 至少需要 16 个字符")
