"""Validated Web settings persisted independently of deployment environment files.

The JSON file contains private values. Only ``public_settings`` / ``public``
should be returned by read-only APIs; they never return tokens or passwords.
"""
from __future__ import annotations

from collections.abc import Mapping
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import threading
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator


MAX_SETTINGS_BYTES = 64 * 1024
SENSITIVE_FIELDS = frozenset({"token", "proxy_auth"})
HOT_RELOAD_FIELDS = frozenset({"max_records", "pending_limit", "default_timeout_seconds", "tcp_idle_timeout"})
Port = Annotated[int, Field(strict=True, ge=1, le=65535)]
_INTERFACE = re.compile(r"[A-Za-z0-9_.-]{1,15}")
_HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


class SettingsError(ValueError):
    """Explicit settings-file failure; messages must not include secret values."""


def _controls(value: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def _listen_host(value: str) -> str:
    if value != value.strip() or any(char.isspace() for char in value) or _controls(value):
        raise ValueError("监听地址不能包含空白或控制字符")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        # Do not accept malformed IPv4 addresses as numeric DNS names.
        if all(char in "0123456789." for char in value):
            raise ValueError("监听 IP 地址无效") from None
        hostname = value[:-1] if value.endswith(".") else value
        labels = hostname.split(".")
        if not labels or not all(_HOST_LABEL.fullmatch(label) for label in labels):
            raise ValueError("监听地址必须是有效的 IPv4、IPv6 或主机名") from None
    else:
        if isinstance(address, ipaddress.IPv6Address) and address.scope_id:
            if not _INTERFACE.fullmatch(address.scope_id):
                raise ValueError("IPv6 接口作用域无效")
    return value


def reverse_proxy_enabled(values: Mapping) -> bool:
    return (values.get("proxy_enabled", True) and values.get("inspection_profile", "newapi") == "newapi"
            and bool(values.get("newapi_upstream", "")))


def _check_listener_conflicts(values: Mapping) -> None:
    web_port, forward_port = values.get("port", 7030), values.get("proxy_port", 8080)
    if web_port == forward_port:
        raise ValueError("Web 端口和 HTTP 代理端口不能相同")
    if not reverse_proxy_enabled(values):
        return
    reverse_port = values.get("newapi_reverse_port", 8081)
    if reverse_port in {web_port, forward_port}:
        raise ValueError("已启用的 New API 入站代理端口不能与 Web 或上游代理端口相同")
    upstream = urlsplit(values["newapi_upstream"])
    upstream_host = (upstream.hostname or "").lower().rstrip(".")
    upstream_port = upstream.port or (443 if upstream.scheme == "https" else 80)
    local_names = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "::", "host.docker.internal"}
    local_names.update(str(values.get(name, "127.0.0.1")).lower().rstrip(".") for name in ("host", "proxy_host"))
    try:
        loopback = ipaddress.ip_address(upstream_host).is_loopback
    except ValueError:
        loopback = False
    if upstream_port in {web_port, forward_port, reverse_port} and (loopback or upstream_host in local_names):
        raise ValueError("New API 源站不能指向 RequestWatch 自身的 Web、上游代理或入站代理监听端口")


class SettingsInput(BaseModel):
    """Partial settings update. Omitted fields are unchanged; null is rejected."""

    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)

    host: str | None = Field(default=None, min_length=1, max_length=253)
    port: Port | None = None
    interfaces: str | list[str] | None = Field(default=None, max_length=2048)
    inspection_profile: Literal["newapi", "network"] | None = None
    newapi_upstream: str | None = Field(default=None, max_length=2048)
    newapi_reverse_port: Port | None = None
    capture_enabled: bool | None = None
    passive_only: bool | None = None
    queue_num: Port | None = None
    protected_ports: list[Port] | None = Field(default=None, max_length=1024)
    proxy_enabled: bool | None = None
    proxy_host: str | None = Field(default=None, min_length=1, max_length=253)
    proxy_port: Port | None = None
    proxy_auth: str | None = Field(default=None, max_length=4096, repr=False)
    max_records: int | None = Field(default=None, ge=100, le=1_000_000)
    pending_limit: int | None = Field(default=None, ge=1, le=10_000)
    mitmdump: str | None = Field(default=None, max_length=4096)
    token: str | None = Field(default=None, min_length=16, max_length=512, repr=False)
    default_timeout_seconds: int | None = Field(default=None, ge=5, le=120)
    tcp_idle_timeout: int | None = Field(default=None, ge=30, le=86400)

    @field_validator("*", mode="before")
    @classmethod
    def reject_explicit_null(cls, value: Any):
        if value is None:
            raise ValueError("设置值不能为 null；不修改的字段请省略")
        return value

    @field_validator("host", "proxy_host")
    @classmethod
    def validate_host(cls, value: str):
        return _listen_host(value)

    @field_validator("newapi_upstream")
    @classmethod
    def validate_newapi_upstream(cls, value: str):
        if not value:
            return ""
        message = "New API 地址仅支持 http/https 源站地址，不能包含账号密码、路径、查询参数或片段"
        try:
            if any(char.isspace() for char in value) or _controls(value) or "\\" in value or "?" in value or "#" in value:
                raise ValueError(message)
            parsed = urlsplit(value)
            if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                    or parsed.username is not None or parsed.password is not None
                    or parsed.path not in {"", "/"}):
                raise ValueError(message)
            _listen_host(parsed.hostname)
            if parsed.port is not None and parsed.port < 1:
                raise ValueError(message)
        except ValueError:
            raise ValueError(message) from None
        return value.rstrip("/")

    @field_validator("interfaces")
    @classmethod
    def validate_interfaces(cls, value: str | list[str]):
        if isinstance(value, str):
            if _controls(value):
                raise ValueError("网卡名称不能包含控制字符")
            names = [part.strip() for part in value.split(",")]
        else:
            if any(_controls(part) for part in value):
                raise ValueError("网卡名称不能包含控制字符")
            names = [part.strip() for part in value]
        if not names or len(names) > 64 or any(not name for name in names):
            raise ValueError("请选择 any/all，或最多 64 个有效网卡名称")
        if any(name in {"all", "any"} for name in names):
            if len(names) != 1:
                raise ValueError("any/all 不能与具体网卡同时使用")
            return "any"
        if not all(_INTERFACE.fullmatch(name) for name in names):
            raise ValueError("网卡名称仅支持 1–15 位字母、数字、点、横线或下划线")
        return ",".join(dict.fromkeys(names))

    @field_validator("protected_ports")
    @classmethod
    def normalize_protected_ports(cls, value: list[int]):
        return sorted(set(value))

    @field_validator("proxy_auth")
    @classmethod
    def validate_proxy_auth(cls, value: str):
        if not value:
            return ""
        username, separator, password = value.partition(":")
        if _controls(value) or not separator or not username or not password:
            raise ValueError("代理认证应为 用户名:密码；空字符串表示关闭认证")
        return value

    @field_validator("token")
    @classmethod
    def validate_token(cls, value: str):
        if not value.isascii() or _controls(value) or any(char.isspace() for char in value):
            raise ValueError("访问令牌仅支持可见 ASCII 字符，不能包含空白或控制字符")
        return value

    @field_validator("mitmdump")
    @classmethod
    def validate_executable(cls, value: str):
        if _controls(value) or value != value.strip():
            raise ValueError("mitmdump 路径不能包含首尾空白或控制字符")
        if value.startswith("-"):
            raise ValueError("请填写 mitmdump 可执行文件路径，不要填写命令选项")
        if value and not any(char in value for char in "/\\") and any(char.isspace() for char in value):
            raise ValueError("仅填写可执行文件名或路径，不要附加命令参数")
        return value

    @model_validator(mode="after")
    def distinct_ports(self):
        # Partial updates are merged with running settings in validate_settings.
        # Only compare explicitly present ports here; disabled reverse settings
        # must not claim an unused port in upgraded installations.
        values = self.model_dump(exclude_unset=True)
        if self.port is not None and self.proxy_port is not None and self.port == self.proxy_port:
            raise ValueError("Web 端口和 HTTP 代理端口不能相同")
        if reverse_proxy_enabled(values):
            reverse_port = self.newapi_reverse_port if self.newapi_reverse_port is not None else 8081
            if reverse_port in {self.port, self.proxy_port}:
                raise ValueError("已启用的 New API 入站代理端口不能与 Web 或上游代理端口相同")
        return self


SETTING_NAMES = frozenset(SettingsInput.model_fields)
RESTART_FIELDS = SETTING_NAMES - HOT_RELOAD_FIELDS


def _updates(values: Mapping | SettingsInput) -> dict:
    if isinstance(values, SettingsInput):
        return values.model_dump(exclude_unset=True)
    return SettingsInput.model_validate(values).model_dump(exclude_unset=True)


def _validated_updates(values: Mapping | SettingsInput) -> dict:
    try:
        return _updates(values)
    except ValidationError as exc:
        # Pydantic's structured errors normally include input values. Summarize
        # only field locations and messages so API errors cannot expose secrets.
        details = []
        for error in exc.errors(include_input=False, include_context=False, include_url=False):
            location = ".".join(str(part) for part in error["loc"]) or "settings"
            details.append(location + ": " + error["msg"])
        raise SettingsError("设置值无效；" + "；".join(details)) from exc


def validate_settings(values: Mapping | SettingsInput, base: Mapping | None = None) -> dict:
    """Validate an update against effective defaults without persisting defaults.

    ``base`` should contain the currently effective settings (including environment
    defaults). Returned values are the normalized update, never the base mapping.
    """
    result = _validated_updates(values)
    effective = {"port": 7030, "proxy_port": 8080, "newapi_reverse_port": 8081,
                 "inspection_profile": "newapi", "newapi_upstream": "", "proxy_enabled": True}
    if base is not None:
        effective.update({key: value for key, value in base.items() if key in SETTING_NAMES})
    effective.update(result)
    try:
        _check_listener_conflicts(effective)
    except ValueError as exc:
        raise SettingsError(str(exc)) from exc
    return result


def public_settings(values: Mapping | SettingsInput) -> dict:
    """Whitelist a settings view, including only presence flags for secrets."""
    if isinstance(values, SettingsInput):
        values = values.model_dump(exclude_unset=True)
    public = {key: (list(value) if isinstance(value, (list, tuple)) else value)
              for key, value in values.items() if key in SETTING_NAMES - SENSITIVE_FIELDS}
    public["token_configured"] = bool(values.get("token"))
    public["proxy_auth_configured"] = bool(values.get("proxy_auth"))
    return public


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SettingsError("设置文件包含重复字段")
        result[key] = value
    return result


class SettingsStore:
    """Atomic settings.json storage. A single app instance owns each data directory."""

    def __init__(self, data_dir):
        self.root = Path(data_dir).resolve()
        self.path = self.root / "settings.json"
        self.lock = threading.RLock()

    def _check_path(self):
        if self.path.is_symlink() or self.path.resolve().parent != self.root:
            raise SettingsError("设置文件不能是符号链接或指向数据目录之外")
        if self.path.exists() and not self.path.is_file():
            raise SettingsError("设置文件路径不是普通文件")

    def load(self) -> dict:
        """Return private persisted overrides; malformed files fail explicitly."""
        with self.lock:
            self._check_path()
            try:
                fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            except FileNotFoundError:
                return {}
            except OSError as exc:
                raise SettingsError("无法读取设置文件") from exc
            try:
                with os.fdopen(fd, "rb") as stream:
                    metadata = os.fstat(stream.fileno())
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_SETTINGS_BYTES:
                        raise SettingsError("设置文件类型无效或超过 64 KiB")
                    raw = stream.read(MAX_SETTINGS_BYTES + 1)
                if len(raw) > MAX_SETTINGS_BYTES:
                    raise SettingsError("设置文件超过 64 KiB")
                value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
                # Persisted values are partial overrides. Conflicts against the
                # environment are validated when Config applies those overrides.
                return _updates(value)
            except SettingsError:
                raise
            except (OSError, UnicodeError, ValueError, TypeError) as exc:
                raise SettingsError("设置文件损坏或包含无效配置，请修复后重新启动") from exc

    def save(self, values: Mapping | SettingsInput, base: Mapping | None = None) -> dict:
        """Merge, validate, then atomically replace settings.json with mode 0600."""
        update = _validated_updates(values)
        with self.lock:
            merged = {**self.load(), **update}
            validate_settings(merged, base)
            payload = (json.dumps(merged, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
            if len(payload) > MAX_SETTINGS_BYTES:
                raise SettingsError("设置内容超过 64 KiB")
            temporary = None
            fd = None
            try:
                self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
                self._check_path()
                fd, temporary = tempfile.mkstemp(prefix=".settings-", suffix=".tmp", dir=self.root)
                if hasattr(os, "fchmod"):
                    os.fchmod(fd, 0o600)
                else:
                    os.chmod(temporary, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    fd = None
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                self._check_path()
                os.replace(temporary, self.path)
                temporary = None
                if os.name == "posix":
                    try:
                        directory = os.open(self.root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                        try:
                            os.fsync(directory)
                        finally:
                            os.close(directory)
                    except OSError:
                        # Some filesystems do not support directory fsync; the
                        # complete data file was already synced before replacement.
                        pass
            except OSError as exc:
                raise SettingsError("无法保存设置文件；原配置保持不变") from exc
            finally:
                if fd is not None:
                    os.close(fd)
                if temporary is not None:
                    try:
                        os.unlink(temporary)
                    except FileNotFoundError:
                        pass
            return merged

    def public(self, values: Mapping | SettingsInput | None = None) -> dict:
        return public_settings(self.load() if values is None else values)
