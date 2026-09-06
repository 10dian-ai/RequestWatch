"""Read-only Docker inventory; packet attribution is a best-effort IP lookup."""
from __future__ import annotations

import ipaddress
import threading
import time
from typing import Any


class DockerInventory:
    def __init__(self, socket_path: str = "/var/run/docker.sock", *, client_factory=None):
        self.socket_path = socket_path
        self._client_factory = client_factory
        self._lock = threading.RLock()
        self._containers: list[dict[str, Any]] = []
        self._error: str | None = None
        self._refreshed_at: float | None = None

    def refresh(self) -> list[dict[str, Any]]:
        try:
            if self._client_factory is None:
                import httpx
                client = httpx.Client(transport=httpx.HTTPTransport(uds=self.socket_path),
                                      base_url="http://docker", timeout=3.0)
            else:
                client = self._client_factory()
            with client:
                response = client.get("/containers/json", params={"all": "0"})
                response.raise_for_status()
                data = response.json()
            if not isinstance(data, list):
                raise ValueError("Docker returned an invalid container list")
            containers = []
            for item in data:
                networks = (item.get("NetworkSettings") or {}).get("Networks") or {}
                addresses = set()
                for network in networks.values():
                    for field in ("IPAddress", "GlobalIPv6Address"):
                        address = network.get(field)
                        if address:
                            try:
                                addresses.add(str(ipaddress.ip_address(address)))
                            except ValueError:
                                pass
                names = item.get("Names") or []
                containers.append({
                    "id": str(item.get("Id", "")),
                    "name": str(names[0]).lstrip("/") if names else str(item.get("Id", ""))[:12],
                    "image": str(item.get("Image", "")),
                    "status": str(item.get("State") or item.get("Status") or "unknown"),
                    "network_mode": str((item.get("HostConfig") or {}).get("NetworkMode", "unknown")),
                    "ips": sorted(addresses),
                    "ports": [{"private_port": entry.get("PrivatePort"), "public_port": entry.get("PublicPort"),
                               "ip": entry.get("IP", ""), "type": entry.get("Type", "tcp")}
                              for entry in item.get("Ports", []) if isinstance(entry, dict)
                              and isinstance(entry.get("PrivatePort"), int)],
                })
            with self._lock:
                self._containers = sorted(containers, key=lambda row: row["name"])
                self._error = None
                self._refreshed_at = time.time()
        except Exception as exc:
            # Never attribute a newly observed packet using possibly recycled IPs.
            with self._lock:
                self._containers = []
                self._error = str(exc)
                self._refreshed_at = time.time()
        return self.list()

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            return [{**item, "ips": list(item["ips"]), "ports": [dict(port) for port in item.get("ports", [])]} for item in self._containers]

    def identify(self, src_ip: str, dst_ip: str) -> dict[str, Any]:
        def normalize(value):
            try:
                return str(ipaddress.ip_address(value))
            except ValueError:
                return value

        src_ip, dst_ip = normalize(src_ip), normalize(dst_ip)
        with self._lock:
            source = [c for c in self._containers if src_ip in c["ips"] and c["network_mode"] != "host"]
            target = [c for c in self._containers if dst_ip in c["ips"] and c["network_mode"] != "host"]
        src = source[0] if len(source) == 1 else None
        dst = target[0] if len(target) == 1 else None
        chosen = src or dst
        result: dict[str, Any] = {
            "container_id": chosen["id"] if chosen else "",
            "container_name": chosen["name"] if chosen else "",
            "attribution": "ip" if chosen else "unknown",
            "src_container_id": src["id"] if src else "",
            "src_container_name": src["name"] if src else "",
            "dst_container_id": dst["id"] if dst else "",
            "dst_container_name": dst["name"] if dst else "",
            "container_ids": list(dict.fromkeys(c["id"] for c in (src, dst) if c)),
        }
        if len(source) > 1 or len(target) > 1:
            result["attribution_note"] = "IP address is shared by multiple containers; ambiguous endpoints are not assigned."
        elif not chosen:
            result["attribution_note"] = "No unique container IP match; host-network containers share the host network."
        return result

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {"available": self._refreshed_at is not None and self._error is None,
                    "error": self._error, "refreshed_at": self._refreshed_at,
                    "container_count": len(self._containers), "socket_path": self.socket_path}
