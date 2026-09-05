from __future__ import annotations

import ipaddress
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .store import searchable


class RuleInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    enabled: bool = True
    source: Literal["any", "packet", "http"] = "any"
    protocol: Literal["any", "TCP", "UDP", "HTTP", "HTTPS"] = "any"
    container_id: str = Field(default="", max_length=128)
    host: str = Field(default="", max_length=253)
    port: int | None = Field(default=None, ge=1, le=65535)
    keyword: str = Field(default="", max_length=512)
    timeout_seconds: int = Field(default=30, ge=5, le=120)

    @model_validator(mode="after")
    def constraints(self):
        self.name = self.name.strip()
        self.host = self.host.strip()
        self.container_id = self.container_id.strip()
        if not self.name:
            raise ValueError("规则名称不能为空")
        if not any((self.container_id, self.host, self.port, self.keyword)):
            raise ValueError("至少填写容器、目标地址、端口或关键词之一，避免暂停全部网络")
        if self.source == "packet" and self.protocol in {"HTTP", "HTTPS"}:
            raise ValueError("原始包规则请选择 TCP / UDP；HTTP / HTTPS 请选择代理请求")
        if self.source == "http" and self.protocol in {"TCP", "UDP"}:
            raise ValueError("代理请求规则请选择 HTTP / HTTPS")
        return self


def matches(rule: dict, record: dict, body_store=None) -> bool:
    if not rule.get("enabled", True):
        return False
    if rule.get("source", "any") not in {"any", record.get("source")}:
        return False
    if rule.get("protocol", "any") not in {"any", record.get("protocol")}:
        return False
    container = rule.get("container_id")
    if container and container not in {record.get("container_id"), record.get("src_container_id"), record.get("dst_container_id")}:
        return False
    if rule.get("port") and rule["port"] != record.get("dst_port"):
        return False
    host = rule.get("host", "").casefold()
    if host:
        target = record.get("dst_ip", "")
        url_host = urlsplit(record.get("url", "")).hostname or ""
        try:
            network = ipaddress.ip_network(host, strict=False)
            if ipaddress.ip_address(target) not in network:
                return False
        except ValueError:
            if host not in target.casefold() and host not in url_host.casefold():
                return False
    # A pause is decided before a response exists. Response-only keywords are searchable later.
    needle = rule.get("keyword", "").casefold()
    return not needle or needle in searchable(record) or bool(body_store and body_store.contains(record, needle))
