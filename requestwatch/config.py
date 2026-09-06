from __future__ import annotations

import os
import secrets
import tempfile
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
    inspection_profile: str = field(default_factory=lambda: os.getenv("RW_INSPECTION_PROFILE", "newapi"))
    newapi_upstream: str = field(default_factory=lambda: os.getenv("RW_NEWAPI_UPSTREAM", ""))
    newapi_reverse_port: int = field(default_factory=lambda: int(os.getenv("RW_NEWAPI_REVERSE_PORT", "8081")))
    capture_enabled: bool = field(default_factory=lambda: env_bool("RW_CAPTURE", True))
    passive_only: bool = field(default_factory=lambda: env_bool("RW_PASSIVE_ONLY", True))
    interfaces: str = field(default_factory=lambda: os.getenv("RW_INTERFACES", "any"))
    queue_num: int = field(default_factory=lambda: int(os.getenv("RW_QUEUE_NUM", "7030")))
    protected_ports: tuple[int, ...] = field(default_factory=lambda: tuple(int(p) for p in os.getenv("RW_PROTECTED_PORTS", "22").split(",") if p.strip()))
    extra_protected_ports: tuple[int, ...] = field(default=(), init=False)
    pending_limit: int = field(default_factory=lambda: int(os.getenv("RW_PENDING_LIMIT", "128")))
    default_timeout_seconds: int = field(default_factory=lambda: int(os.getenv("RW_DEFAULT_TIMEOUT", "30")))
    tcp_idle_timeout: int = field(default_factory=lambda: int(os.getenv("RW_TCP_IDLE_TIMEOUT", "300")))
    mitmdump: str = field(default_factory=lambda: os.getenv("RW_MITMDUMP", ""))
    max_records: int = field(default_factory=lambda: int(os.getenv("RW_MAX_RECORDS", "10000")))
    proxy_enabled: bool = field(default_factory=lambda: env_bool("RW_PROXY", True))
    proxy_host: str = field(default_factory=lambda: os.getenv("RW_PROXY_HOST", "127.0.0.1"))
    proxy_port: int = field(default_factory=lambda: int(os.getenv("RW_PROXY_PORT", "8080")))
    proxy_auth: str = field(default_factory=lambda: os.getenv("RW_PROXY_AUTH", ""))
    demo: bool = False

    def prepare(self) -> None:
        self.data_dir = Path(self.data_dir).resolve()
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        from .settings import SettingsStore, validate_settings, reverse_proxy_enabled
        settings_store = SettingsStore(self.data_dir / "demo" if self.demo else self.data_dir)
        self._settings_store = settings_store
        saved = settings_store.load()
        base = self.settings_values()
        if not base["token"]:
            base.pop("token")
        validate_settings(saved, base)
        validate_settings({**base, **saved})
        if not self.demo:
            for name, value in saved.items():
                setattr(self, name, value)
        self.extra_protected_ports = tuple(self.protected_ports)
        ports = {self.port, self.proxy_port, *self.extra_protected_ports}
        if reverse_proxy_enabled(self.settings_values()):
            ports.add(self.newapi_reverse_port)
        self.protected_ports = tuple(sorted(ports))
        self._settings_prepared = True
        if not all(1 <= p <= 65535 for p in self.protected_ports):
            raise ValueError("端口必须在 1–65535 范围内")
        if not 1 <= self.queue_num <= 65535 or self.max_records < 100:
            raise ValueError("队列编号无效，或保留记录数小于 100")
        token_dir = self.data_dir / "demo" if self.demo else self.data_dir
        token_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        token_file = token_dir / "admin-token"
        if not self.token:
            if token_file.exists():
                self.token = token_file.read_text(encoding="utf-8").strip()
            else:
                self.token = secrets.token_urlsafe(32)
        if len(self.token) < 16:
            raise ValueError("RW_TOKEN 至少需要 16 个字符")

        # The panel and the initial install always expose the same token file location.
        if token_file.is_symlink():
            raise ValueError("令牌文件不能是符号链接")
        if not token_file.exists() or token_file.read_text(encoding="utf-8").strip() != self.token:
            fd, temporary = tempfile.mkstemp(prefix=".admin-token-", dir=token_dir)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    stream.write(self.token + "\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, token_file)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)

    def settings_values(self):
        names = ("host", "port", "inspection_profile", "newapi_upstream", "newapi_reverse_port", "capture_enabled", "passive_only", "interfaces", "queue_num", "pending_limit",
                 "max_records", "proxy_enabled", "proxy_host", "proxy_port", "proxy_auth", "token",
                 "default_timeout_seconds", "tcp_idle_timeout", "mitmdump")
        result = {name: getattr(self, name) for name in names}
        result["protected_ports"] = list(self.extra_protected_ports if getattr(self, "_settings_prepared", False) else self.protected_ports)
        return result
