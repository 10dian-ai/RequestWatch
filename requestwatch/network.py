"""Ubuntu packet capture and bounded NFQUEUE interception.

TCP edits preserve payload length. Cached bytes remain authoritative for
retransmissions for five minutes (128 directional flows, 32 segments per flow).
A packet DROP is not cancellation of a request the sender may retransmit.
"""
from __future__ import annotations

import base64
from collections import OrderedDict
from dataclasses import dataclass, field
import hashlib
import ipaddress
import queue
import select
import shlex
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Any
import uuid


@dataclass
class PacketInfo:
    raw: bytes
    version: int
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int | None
    dst_port: int | None
    transport_offset: int
    payload_offset: int
    expected_length: int
    truncated: bool = False
    fragmented: bool = False
    sequence: int = 0
    flags: int = 0
    edit_reason: str = ""

    @property
    def payload(self):
        return self.raw[self.payload_offset:min(self.expected_length, len(self.raw))]

    @property
    def flow_key(self):
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port)


def parse_packet(raw: bytes) -> PacketInfo:
    raw = bytes(raw)
    if not raw:
        raise ValueError("Empty IP packet")
    version = raw[0] >> 4
    fragmented = noninitial = False
    edit_reason = ""
    if version == 4:
        if len(raw) < 20:
            raise ValueError("Truncated IPv4 header")
        offset = (raw[0] & 15) * 4
        expected = int.from_bytes(raw[2:4], "big")
        if offset < 20 or offset > len(raw) or expected < offset:
            raise ValueError("Invalid IPv4 header length")
        proto = raw[9]
        fragment = int.from_bytes(raw[6:8], "big")
        fragmented, noninitial = bool(fragment & 0x3fff), bool(fragment & 0x1fff)
        source = socket.inet_ntop(socket.AF_INET, raw[12:16])
        target = socket.inet_ntop(socket.AF_INET, raw[16:20])
    elif version == 6:
        if len(raw) < 40:
            raise ValueError("Truncated IPv6 header")
        expected = 40 + int.from_bytes(raw[4:6], "big")
        if expected == 40:
            raise ValueError("IPv6 jumbograms are not editable or decoded")
        proto, offset = raw[6], 40
        source = socket.inet_ntop(socket.AF_INET6, raw[8:24])
        target = socket.inet_ntop(socket.AF_INET6, raw[24:40])
        for _ in range(16):
            if proto not in (0, 43, 44, 51, 60):
                break
            if len(raw) < offset + 8:
                raise ValueError("Truncated IPv6 extension header")
            next_proto = raw[offset]
            if proto in (43, 51):
                edit_reason = "IPv6 routing/authentication headers cannot be edited"
            if proto == 44:
                fragmented = True
                noninitial = bool(int.from_bytes(raw[offset + 2:offset + 4], "big") & 0xfff8)
                length = 8
            elif proto == 51:
                length = (raw[offset + 1] + 2) * 4
            else:
                length = (raw[offset + 1] + 1) * 8
            offset += length
            proto = next_proto
            if offset > len(raw) or offset > expected:
                raise ValueError("Invalid IPv6 extension header length")
            if noninitial:
                break
        else:
            raise ValueError("Too many IPv6 extension headers")
    else:
        raise ValueError("Only IPv4 and IPv6 packets are supported")
    if proto not in (6, 17):
        raise ValueError("Only TCP and UDP packets are supported")
    protocol = "TCP" if proto == 6 else "UDP"
    truncated = len(raw) < expected
    raw = raw[:expected]
    if noninitial:
        return PacketInfo(raw, version, protocol, source, target, None, None, offset, offset,
                          expected, truncated, True, edit_reason=edit_reason)
    minimum = 20 if proto == 6 else 8
    if len(raw) < offset + minimum:
        raise ValueError("Truncated transport header")
    src_port, dst_port = struct.unpack_from("!HH", raw, offset)
    sequence = flags = 0
    if proto == 6:
        length = (raw[offset + 12] >> 4) * 4
        if length < 20 or offset + length > len(raw):
            raise ValueError("Invalid TCP header length")
        sequence = int.from_bytes(raw[offset + 4:offset + 8], "big")
        flags = raw[offset + 13]
    else:
        length = 8
        udp_length = int.from_bytes(raw[offset + 4:offset + 6], "big")
        if udp_length < 8:
            raise ValueError("Invalid UDP length")
        if not fragmented and udp_length != expected - offset:
            truncated = True
    return PacketInfo(raw, version, protocol, source, target, src_port, dst_port, offset,
                      offset + length, expected, truncated, fragmented, sequence, flags, edit_reason)


def _checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def edit_packet_payload(raw: bytes, payload_hex: str) -> bytes:
    info = parse_packet(raw)
    if info.truncated:
        raise ValueError("Captured packet is truncated; payload editing is disabled")
    if info.fragmented:
        raise ValueError("Fragmented IP packets cannot be edited")
    if info.edit_reason:
        raise ValueError(info.edit_reason)
    if not isinstance(payload_hex, str):
        raise ValueError("payload_hex must be a hexadecimal string")
    try:
        payload = bytes.fromhex(payload_hex)
    except ValueError as exc:
        raise ValueError("payload_hex contains invalid hexadecimal data") from exc
    if info.protocol == "TCP" and len(payload) != len(info.payload):
        raise ValueError("TCP payload edits must preserve the original byte length")
    result = bytearray(info.raw[:info.payload_offset] + payload)
    offset = info.transport_offset
    segment_length = len(result) - offset
    if len(result) > 65535 + (40 if info.version == 6 else 0) or segment_length > 65535:
        raise ValueError("Edited packet exceeds supported IP/transport length")
    proto = 6 if info.protocol == "TCP" else 17
    checksum_offset = offset + (16 if proto == 6 else 6)
    result[checksum_offset:checksum_offset + 2] = b"\x00\x00"
    if proto == 17:
        result[offset + 4:offset + 6] = segment_length.to_bytes(2, "big")
    if info.version == 4:
        result[2:4] = len(result).to_bytes(2, "big")
        result[10:12] = b"\x00\x00"
        result[10:12] = _checksum(bytes(result[:offset])).to_bytes(2, "big")
        pseudo = bytes(result[12:20]) + struct.pack("!BBH", 0, proto, segment_length)
    else:
        result[4:6] = (len(result) - 40).to_bytes(2, "big")
        pseudo = bytes(result[8:40]) + struct.pack("!I3xB", segment_length, proto)
    checksum = _checksum(pseudo + bytes(result[offset:]))
    if proto == 17 and checksum == 0:
        checksum = 0xffff
    result[checksum_offset:checksum_offset + 2] = checksum.to_bytes(2, "big")
    return bytes(result)


def validate_packet_edit(record: dict, edits: dict) -> dict:
    if not isinstance(edits, dict) or set(edits) - {"payload_hex"}:
        raise ValueError("Packet edits accept only payload_hex")
    if "payload_hex" not in edits:
        return {}
    try:
        raw = base64.b64decode(record["raw_b64"], validate=True)
    except (KeyError, ValueError) as exc:
        raise ValueError("Original packet bytes are unavailable") from exc
    edited = edit_packet_payload(raw, edits["payload_hex"])
    return {"payload_hex": parse_packet(edited).payload.hex()}


def packet_record(raw: bytes, interface: str = "", *, capture_path: str = "sniff") -> dict:
    packet = parse_packet(raw)
    return {"id": str(uuid.uuid4()), "source": "packet", "protocol": packet.protocol,
            "created_at": time.time(), "src_ip": packet.src_ip, "dst_ip": packet.dst_ip,
            "src_port": packet.src_port, "dst_port": packet.dst_port, "interface": interface,
            "summary": f"{packet.src_ip}:{packet.src_port or '*'} → {packet.dst_ip}:{packet.dst_port or '*'}",
            "payload_text": packet.payload.decode("utf-8", errors="replace"),
            "payload_hex": packet.payload.hex(), "payload_size": len(packet.payload),
            "raw_b64": base64.b64encode(packet.raw).decode("ascii"), "state": "captured",
            "truncated": packet.truncated, "fragmented": packet.fragmented,
            "editable": not packet.truncated and not packet.fragmented and not packet.edit_reason,
            "edit_error": packet.edit_reason, "capture_path": capture_path, "ip_version": packet.version}


@dataclass
class _Pending:
    record_id: str
    raw: bytes
    packets: list[Any] = field(default_factory=list)
    fingerprint: tuple | None = None


class NetworkEngine:
    def __init__(self, runtime, config, *, runner=None, sniffer_factory=None, queue_factory=None,
                 platform_name=None, interface_provider=None):
        self.runtime, self.config = runtime, config
        self._runner = runner or subprocess.run
        self._sniffer_factory = sniffer_factory
        self._queue_factory = queue_factory
        self._platform = platform_name or sys.platform
        self._interface_provider = interface_provider
        self._capture_interfaces = []
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread = self._sniffer = self._nfqueue = None
        self._managed_families: list[str] = []
        self._pending: dict[str, _Pending] = {}
        self._pending_fingerprints: dict[tuple, str] = {}
        self._observations = queue.Queue(maxsize=4096)
        self._observations_ready = threading.Event()
        self._recent_queue: dict[bytes, float] = {}
        self._patches: OrderedDict[tuple, list[tuple[float, int, bytes, bytes]]] = OrderedDict()
        self._capture_error = self._queue_error = None
        self._capture_running = self._queue_active = False
        self._passive_dropped = 0
        self._passive_write_failed = 0
        self._chain = f"RWATCH_{int(config.queue_num)}"
        self._comment = f"requestwatch-managed-{int(config.queue_num)}"
        self._retry_at = 0.0

    def start(self):
        if getattr(self.config, "inspection_profile", "network") == "newapi":
            return  # HTTP listeners capture both New API legs without host sniffing.
        if not self.config.capture_enabled or (self._thread and self._thread.is_alive()):
            return
        if self._platform != "linux":
            self._capture_error = "Live capture requires Linux; the web console can still run."
            return
        self._stop.clear()
        try:
            self._start_sniffer()
        except Exception as exc:
            self._capture_error = str(exc)
        self._thread = threading.Thread(target=self._run, name="requestwatch-network", daemon=True)
        self._thread.start()

    def _desired_interfaces(self):
        selected = [name.strip() for name in self.config.interfaces.split(",") if name.strip()]
        if not selected or selected == ["any"]:
            provider = self._interface_provider
            if provider is None:
                from scapy.all import get_if_list
                provider = get_if_list
            selected = list(provider())
        selected = sorted(set(selected))
        if not selected:
            raise RuntimeError("No network interfaces are available")
        return selected

    def _start_sniffer(self):
        desired = self._desired_interfaces()
        factory = self._sniffer_factory
        if factory is None:
            from scapy.all import AsyncSniffer
            factory = AsyncSniffer
        if self._sniffer is not None and getattr(self._sniffer, "running", False):
            self._sniffer.stop()
        self._sniffer = factory(iface=desired, filter="ip or ip6", store=False, prn=self._on_sniff)
        self._sniffer.start()
        self._capture_interfaces = desired
        self._capture_running = True
        self._capture_error = None

    def _refresh_interfaces(self):
        try:
            if self._desired_interfaces() != self._capture_interfaces or not getattr(self._sniffer, "running", False):
                self._start_sniffer()
        except Exception as exc:
            self._capture_error = str(exc)
            self._capture_running = bool(self._sniffer and getattr(self._sniffer, "running", False))

    def stop(self):
        self._stop.set()
        # Stop producers before draining the observation queue. Otherwise the
        # sniffer can enqueue more bytes after the worker's final flush.
        if self._sniffer:
            try:
                if getattr(self._sniffer, "running", False):
                    self._sniffer.stop()
            except Exception as exc:
                self._capture_error = str(exc)
        if self._thread and self._thread is not threading.current_thread():
            self._thread.join(timeout=12)
        if not self._thread or not self._thread.is_alive():
            # Also cover observations queued while the worker was entering its
            # final flush, before sniffer.stop() completed.
            self._flush_passive(force=True)
        self._capture_running = False

    def status(self):
        if self._sniffer is not None and not getattr(self._sniffer, "running", True):
            exception = getattr(self._sniffer, "exception", None)
            if exception:
                self._capture_error = str(exception)
                self._capture_running = False
        newapi = getattr(self.config, "inspection_profile", "network") == "newapi"
        return {"enabled": bool(self.config.capture_enabled) and not newapi,
                "configured_enabled": bool(self.config.capture_enabled),
                "inspection_profile": getattr(self.config, "inspection_profile", "network"),
                "message": "New API 专注模式：使用 HTTP 代理捕获完整请求和响应，全机抓包已停用。" if newapi else "",
                "capture_running": self._capture_running,
                "interception_running": self._queue_active,
                "pending_packets": sum(len(p.packets) for p in list(self._pending.values())),
                "capture_error": self._capture_error, "interception_error": self._queue_error,
                "interfaces": self.config.interfaces, "active_interfaces": list(self._capture_interfaces),
                "protected_ports": list(self.config.protected_ports), "queue_num": self.config.queue_num,
                "capture_mode": "newapi" if newapi else ("passive" if getattr(self.config, "passive_only", False) else "intercept"),
                "passive_only": bool(getattr(self.config, "passive_only", False)),
                "passive_dropped": self._passive_dropped,
                "observation_dropped": self._passive_dropped,
                "observation_write_failed": self._passive_write_failed,
                "observation_backlog": self._observations.qsize(),
                "observation_capacity": self._observations.maxsize,
                "observation_drop_semantics": "capture copies not saved; original network packets are unaffected",
                "limitations": ["Protected ports are excluded from both passive capture and interception.",
                                "TCP edits must preserve byte length; DROP is a packet verdict, not request cancellation.",
                                "TCP retransmission edits use a bounded five-minute cache.",
                                "Container-local loopback and some bridge paths require capture inside that network namespace.",
                                "The Python NFQUEUE binding may truncate large packets; truncated packets cannot be edited.",
                                "queue-bypass applies when no listener exists, not when the kernel queue is full."]}

    def _command(self, binary, *args, check=True):
        result = self._runner([binary, "-w", "2", "-t", "mangle", *args], capture_output=True,
                              text=True, timeout=5, check=False)
        if check and result.returncode:
            raise RuntimeError(f"{binary} {' '.join(args)}: {(result.stderr or result.stdout).strip()}")
        return result

    def _cleanup_family(self, binary):
        for parent in ("INPUT", "OUTPUT", "FORWARD"):
            args = [parent, "-m", "comment", "--comment", self._comment, "-j", self._chain]
            for _ in range(8):
                if self._command(binary, "-C", *args, check=False).returncode:
                    break
                self._command(binary, "-D", *args)
        result = self._command(binary, "-S", self._chain, check=False)
        if result.returncode:
            return
        lines = [line for line in result.stdout.splitlines() if line.startswith("-A ")]
        def owned_rule(line):
            tokens = shlex.split(line)
            return (len(tokens) > 2 and tokens[:2] == ["-A", self._chain]
                    and "--comment" in tokens
                    and tokens.index("--comment") + 1 < len(tokens)
                    and tokens[tokens.index("--comment") + 1] == self._comment)

        if any(not owned_rule(line) for line in lines):
            raise RuntimeError(f"Refusing to alter non-RequestWatch rules in {self._chain}")
        self._command(binary, "-F", self._chain)
        self._command(binary, "-X", self._chain)

    def _install_family(self, binary):
        self._cleanup_family(binary)
        self._command(binary, "-N", self._chain)
        self._managed_families.append(binary)
        # Mangle queue verdicts leave subsequent filter/Docker hooks in control.
        for proto in ("tcp", "udp"):
            for port in self.config.protected_ports:
                for direction in ("--sport", "--dport"):
                    self._command(binary, "-A", self._chain, "-p", proto, direction, str(port),
                                  "-m", "comment", "--comment", self._comment, "-j", "RETURN")
            self._command(binary, "-A", self._chain, "-p", proto, "-m", "comment", "--comment", self._comment,
                          "-j", "NFQUEUE", "--queue-num", str(self.config.queue_num), "--queue-bypass")
        for parent in ("INPUT", "OUTPUT", "FORWARD"):
            self._command(binary, "-I", parent, "1", "-m", "comment", "--comment", self._comment, "-j", self._chain)

    def _enable_queue(self):
        if getattr(self.config, "passive_only", False) or getattr(self.config, "inspection_profile", "network") == "newapi":
            return
        try:
            factory = self._queue_factory
            if factory is None:
                from netfilterqueue import NetfilterQueue
                factory = NetfilterQueue
            self._nfqueue = factory()
            self._nfqueue.bind(int(self.config.queue_num), self._on_queued,
                               max_len=max(1024, int(self.config.pending_limit) * 4), range=65535)
            for binary in ("iptables", "ip6tables"):
                self._install_family(binary)
            self._queue_active = True
            self._queue_error = None
        except Exception as exc:
            self._queue_error = str(exc)
            self._disable_queue()

    def _disable_queue(self):
        self._queue_active = False
        errors = []
        for binary in list(self._managed_families):
            try:
                self._cleanup_family(binary)
            except Exception as exc:
                errors.append(str(exc))
        self._managed_families.clear()
        for pending in list(self._pending.values()):
            self._resolve(pending, {"action": "accept", "edits": {}}, stopped=True)
        if self._nfqueue is not None:
            try:
                self._nfqueue.unbind()
            except Exception as exc:
                errors.append(str(exc))
            self._nfqueue = None
        if errors:
            self._queue_error = "; ".join(errors)

    def _rules_need_queue(self):
        if getattr(self.config, "passive_only", False) or getattr(self.config, "inspection_profile", "network") == "newapi":
            return False
        return any(rule.get("enabled", True) and rule.get("source", "any") in ("any", "packet")
                   and str(rule.get("protocol", "any")).upper() in ("ANY", "TCP", "UDP")
                   for rule in self.runtime.rules())

    def _run(self):
        next_sync = 0.0
        next_interfaces = time.monotonic() + 10
        try:
            while not self._stop.is_set():
                now = time.monotonic()
                if now >= next_interfaces:
                    self._refresh_interfaces()
                    next_interfaces = now + 10
                if now >= next_sync:
                    needed = self._rules_need_queue()
                    if needed and not self._queue_active and now >= self._retry_at:
                        self._enable_queue()
                        self._retry_at = now + 10
                    elif not needed and self._nfqueue is not None:
                        self._disable_queue()
                    next_sync = now + 1
                if self._nfqueue is not None:
                    # Backlogged observations must not pay a fixed sleep for
                    # every batch, while NFQUEUE still gets polled each loop.
                    timeout = 0.0 if not self._observations.empty() else 0.04
                    readable, _, _ = select.select([self._nfqueue.get_fd()], [], [], timeout)
                    if readable:
                        self._nfqueue.run(False)
                elif self._observations.empty():
                    self._observations_ready.wait(0.04)
                    self._observations_ready.clear()
                self._process_decisions()
                processed = self._flush_passive()
                if not processed and not self._observations.empty():
                    # A young NFQUEUE copy may still be within its coalescing
                    # window. Do not spin while waiting for that bounded delay.
                    self._stop.wait(0.004)
                self._recent_queue = {key: timestamp for key, timestamp in self._recent_queue.items()
                                      if now - timestamp < 1.0}
        except Exception as exc:
            self._queue_error = str(exc)
        finally:
            self._disable_queue()
            self._flush_passive(force=True)

    def _ignore_passive(self, raw):
        """Cheap common-IP checks keep control traffic out of the copy queue.

        Decode neither payload text nor records on the sniffer callback. IPv6
        extension chains use the existing validated parser as the rare fallback.
        """
        if not raw:
            return True
        version = raw[0] >> 4
        if version == 4 and len(raw) >= 20:
            if raw[9] not in (6, 17):
                return True
            if int.from_bytes(raw[6:8], "big") & 0x1fff:
                return False  # Preserve noninitial fragments, whose ports are unknown.
            offset = (raw[0] & 15) * 4
            if offset < 20 or len(raw) < offset + 4:
                return False  # Worker reports invalid/truncated packet structure.
        elif version == 6 and len(raw) >= 40 and raw[6] in (6, 17):
            offset = 40
            if len(raw) < offset + 4:
                return False
        else:
            try:
                info = parse_packet(raw)
                return info.src_port in self.config.protected_ports or info.dst_port in self.config.protected_ports
            except ValueError:
                return True
        source, target = struct.unpack_from("!HH", raw, offset)
        return source in self.config.protected_ports or target in self.config.protected_ports

    def _on_sniff(self, packet):
        try:
            layer = packet.getlayer("IP") or packet.getlayer("IPv6")
            if layer is None:
                return
            # Scapy already retains the received wire bytes. Re-serializing its
            # dissected protocol tree for every packet adds avoidable CPU work.
            original = getattr(layer, "original", None)
            raw = original if isinstance(original, bytes) and original else bytes(layer)
            if self._ignore_passive(raw):
                return
            self._observations.put_nowait((time.monotonic(), raw, str(getattr(packet, "sniffed_on", ""))))
            self._observations_ready.set()
        except queue.Full:
            self._passive_dropped += 1
        except (ValueError, AttributeError):
            return

    def _flush_passive(self, force=False):
        # Pure observation does not wait for, hash, or consult NFQUEUE copies.
        coalesce = bool(self._queue_active or self._recent_queue)
        budget = self._observations.qsize() if force else 512
        processed, batch_bytes, batch = 0, 0, []

        def save_batch():
            nonlocal batch_bytes
            if not batch:
                return
            try:
                ingest_packets = getattr(self.runtime, "ingest_packets", None)
                if ingest_packets is not None:
                    ingest_packets(batch)
                else:  # Standalone embedders/test doubles preserve the old API.
                    for record in batch:
                        self.runtime.ingest(record, can_intercept=False)
            except Exception:
                # A malformed item or transient batch failure must not discard
                # the remaining records. Stable IDs make these retries safe if
                # another storage stage committed before the batch failed.
                for record in batch:
                    try:
                        self.runtime.ingest(record, can_intercept=False)
                    except Exception as exc:
                        self._passive_write_failed += 1
                        self._capture_error = str(exc)
            finally:
                batch.clear()
                batch_bytes = 0

        for _ in range(budget):
            with self._observations.mutex:
                if not self._observations.queue:
                    break
                when, raw, interface = self._observations.queue[0]
            if coalesce and not force and time.monotonic() - when < 0.12:
                break
            self._observations.get_nowait()
            processed += 1
            if coalesce:
                fingerprint = hashlib.blake2s(raw).digest()
                if abs(self._recent_queue.get(fingerprint, -100) - when) < 0.8:
                    continue
            try:
                batch.append(packet_record(raw, interface))
                batch_bytes += len(raw)
            except (ValueError, TypeError) as exc:
                self._capture_error = str(exc)
            # GSO/GRO captures may contain 64KiB IP packets; cap bytes as well
            # as record count so a batch cannot multiply their transient memory.
            if len(batch) >= 512 or batch_bytes >= 4 * 1024 * 1024:
                save_batch()
        save_batch()
        return processed

    def _on_queued(self, packet):
        if getattr(self.config, "passive_only", False) or getattr(self.config, "inspection_profile", "network") == "newapi":
            packet.accept()
            return
        retained = False
        try:
            raw = packet.get_payload()
            info = parse_packet(raw)
            interfaces = self._packet_interfaces(packet)
            selected = {name.strip() for name in self.config.interfaces.split(",") if name.strip()}
            if selected and selected != {"any"} and not selected.intersection(interfaces):
                packet.accept()
                return
            self._recent_queue[hashlib.blake2s(raw).digest()] = time.monotonic()
            if info.src_port in self.config.protected_ports or info.dst_port in self.config.protected_ports:
                packet.accept()
                return
            # Local traffic to any of the host's addresses travels through lo,
            # even when the destination is not in 127/8 or ::1. Pause only at INPUT.
            if getattr(packet, "hook", None) == 3 and (
                    "lo" in interfaces or ipaddress.ip_address(info.dst_ip).is_loopback):
                packet.accept()
                return
            pending_key = self._pending_key(info)
            original = self._pending_fingerprints.get(pending_key) if pending_key is not None else None
            if original and original in self._pending:
                entry = self._pending[original]
                if len(entry.packets) >= 8:
                    packet.drop()
                    return
                packet.retain()
                entry.packets.append(packet)
                return
            patched = self._apply_patches(raw)
            if patched != raw:
                packet.set_payload(patched)
                packet.accept()
                record = packet_record(patched, self._packet_interface(packet), capture_path="nfqueue")
                record.update(state="forwarded", modified=True, detail="Applied cached TCP retransmission edit")
                self.runtime.ingest(record, can_intercept=False)
                return
            record = packet_record(raw, self._packet_interface(packet), capture_path="nfqueue")
            capacity = len(self._pending) < int(self.config.pending_limit)
            result = self.runtime.ingest(record, can_intercept=capacity)
            if result.get("state") in ("pending", "paused", "intercepted") and capacity:
                packet.retain()
                retained = True
                record_id = str(result.get("id", record["id"]))
                self._pending[record_id] = _Pending(record_id, raw, [packet], pending_key)
                if pending_key is not None:
                    self._pending_fingerprints[pending_key] = record_id
            else:
                packet.accept()
        except Exception as exc:
            self._queue_error = str(exc)
            if not retained:
                try:
                    packet.accept()
                except Exception:
                    pass

    @staticmethod
    def _pending_key(info):
        if info.protocol != "TCP" or not info.payload or info.truncated or info.fragmented:
            return None
        # ID, timestamp, ACK and PSH can change on retransmit. SYN/FIN/RST cannot.
        return (*info.flow_key, info.sequence, info.flags & 0x07, info.payload)

    @staticmethod
    def _packet_interfaces(packet):
        names = []
        for field_name in ("physindev", "indev", "physoutdev", "outdev"):
            index = getattr(packet, field_name, 0)
            if index:
                try:
                    names.append(socket.if_indextoname(index))
                except OSError:
                    continue
        return names

    @classmethod
    def _packet_interface(cls, packet):
        return next(iter(cls._packet_interfaces(packet)), "host")

    def _process_decisions(self):
        for pending in list(self._pending.values()):
            decision = self.runtime.take_decision(pending.record_id)
            if decision is not None:
                self._resolve(pending, decision)

    def _resolve(self, pending, decision, stopped=False):
        action = decision.get("action", "accept")
        if action not in ("accept", "drop"):
            action = "accept"
        edits = decision.get("edits") or {}
        modified = False
        try:
            raw = pending.raw
            conflict = False
            prepared = []
            if action == "accept":
                if "payload_hex" in edits:
                    raw = edit_packet_payload(raw, edits["payload_hex"])
                requested = raw
                # An overlapping queued segment may have been released while this waited.
                raw = self._apply_patches(raw)
                conflict = raw != requested and bool(edits)
                modified = raw != pending.raw
                payload_hex = parse_packet(raw).payload.hex()
                for packet in pending.packets:
                    original = packet.get_payload()
                    replacement = (edit_packet_payload(original, payload_hex) if modified
                                   else self._apply_patches(original))
                    prepared.append((packet, original, replacement))
                if modified:
                    self._remember_patch(pending.raw, raw)
            if action == "drop":
                for packet in pending.packets:
                    packet.drop()
            for packet, original, replacement in prepared:
                if replacement != original:
                    packet.set_payload(replacement)
                packet.accept()
            changes = {"state": "dropped" if action == "drop" else "forwarded", "modified": modified}
            if modified:
                changes.update({key: value for key, value in packet_record(raw).items()
                                if key in ("raw_b64", "payload_hex", "payload_text", "payload_size")})
            if conflict:
                changes["detail"] = "Previously released TCP bytes retained in overlapping retransmission"
            if stopped:
                changes["detail"] = ("Capture stopped; pending packet released with prior TCP edits" if modified
                                     else "Capture stopped; pending packet was released unchanged")
            self.runtime.update(pending.record_id, changes)
        except Exception as exc:
            # Reject invalid edits but preserve earlier bytes in this TCP stream.
            fallback = self._apply_patches(pending.raw)
            for packet in pending.packets:
                try:
                    original = packet.get_payload()
                    replacement = self._apply_patches(original)
                    if replacement != original:
                        packet.set_payload(replacement)
                    packet.accept()
                except Exception:
                    pass
            changes = {"state": "forwarded", "error": str(exc), "modified": fallback != pending.raw,
                       "detail": "Invalid edit rejected; packet released with existing stream edits preserved"}
            if fallback != pending.raw:
                changes.update({key: value for key, value in packet_record(fallback).items()
                                if key in ("raw_b64", "payload_hex", "payload_text", "payload_size")})
            self.runtime.update(pending.record_id, changes)
        finally:
            self._pending.pop(pending.record_id, None)
            self._pending_fingerprints.pop(pending.fingerprint, None)

    def _remember_patch(self, original, edited):
        info, replacement = parse_packet(original), parse_packet(edited)
        if info.protocol != "TCP" or info.fragmented or info.truncated or info.edit_reason:
            return
        patches = self._patches.setdefault(info.flow_key, [])
        patches.append((time.monotonic(), info.sequence, info.payload, replacement.payload))
        self._patches.move_to_end(info.flow_key)
        del patches[:-32]
        while len(self._patches) > 128:
            self._patches.popitem(last=False)

    def _apply_patches(self, raw):
        info = parse_packet(raw)
        if info.protocol != "TCP" or info.fragmented or info.truncated or info.edit_reason:
            return raw
        if info.flags & 2:
            self._patches.pop(info.flow_key, None)
            self._patches.pop((info.dst_ip, info.dst_port, info.src_ip, info.src_port), None)
            return raw
        patches = self._patches.get(info.flow_key, [])
        patches[:] = [patch for patch in patches if time.monotonic() - patch[0] < 300]
        result = bytearray(info.payload)
        for _, sequence, _before, after in patches:
            # All bytes in an edited-and-released segment, including its unchanged
            # bytes, must agree if a later queued packet overlaps that segment.
            for index, new in enumerate(after):
                position = (sequence + index - info.sequence) & 0xffffffff
                if position < len(result):
                    result[position] = new
        return edit_packet_payload(raw, result.hex()) if result != info.payload else raw
