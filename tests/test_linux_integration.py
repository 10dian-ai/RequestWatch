"""Opt-in Linux NFQUEUE integration test, always isolated from the caller's network.

Run on Ubuntu after installing .[linux,test]:
    sudo env RW_RUN_LINUX_INTEGRATION=1 .venv/bin/python -m unittest discover -s tests -p test_linux_integration.py -v

The parent only launches unshare --net. Every socket and firewall mutation runs
inside that fresh, unconnected network namespace. No named host namespace or
veth pair is created. The namespace disappears when the child process exits.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

_ENABLED = (os.getenv("RW_RUN_LINUX_INTEGRATION") == "1" and sys.platform == "linux"
            and hasattr(os, "geteuid") and os.geteuid() == 0)


@unittest.skipUnless(_ENABLED, "Set RW_RUN_LINUX_INTEGRATION=1 on Linux as root to run the isolated NFQUEUE test")
class LinuxNamespaceIntegration(unittest.TestCase):
    def test_udp_pause_edit_drop_timeout_stop_and_tcp_edit(self):
        for executable in ("unshare", "ip", "iptables", "ip6tables"):
            self.assertIsNotNone(shutil.which(executable), f"Missing integration prerequisite: {executable}")
        for module in ("scapy", "netfilterqueue", "pydantic"):
            self.assertIsNotNone(importlib.util.find_spec(module), f"Install integration prerequisite: {module}")
        original_namespace = os.readlink("/proc/self/ns/net")
        result = subprocess.run(
            [shutil.which("unshare"), "--net", sys.executable, str(Path(__file__).resolve()),
             "--namespace-worker", original_namespace],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stdout + "\n" + result.stderr)
        self.assertIn("NFQUEUE namespace integration passed", result.stdout)


def _namespace_worker(parent_namespace: str):
    # This check precedes all networking imports, sockets, and firewall commands.
    if not _ENABLED:
        raise RuntimeError("Integration worker requires explicit opt-in, root, and Linux")
    current_namespace = os.readlink("/proc/self/ns/net")
    if current_namespace == parent_namespace or not parent_namespace.startswith("net:["):
        raise RuntimeError("Refusing network mutations: network namespace is not isolated")

    import json
    import queue
    import runpy
    import socket
    import tempfile
    import threading
    import time
    from types import SimpleNamespace

    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from requestwatch.network import NetworkEngine
    from requestwatch.runtime import Runtime
    from requestwatch.store import Store

    def guarded_run(command, **kwargs):
        if os.readlink("/proc/self/ns/net") != current_namespace:
            raise RuntimeError("Integration worker changed network namespace unexpectedly")
        return subprocess.run(command, **kwargs)

    def command(*args):
        return guarded_run(list(args), capture_output=True, text=True, check=True, timeout=5)

    links = json.loads(command("ip", "-j", "link", "show").stdout)
    if any(link["ifname"] != "lo" for link in links):
        raise RuntimeError("Refusing to use a namespace containing a non-loopback interface")
    command("ip", "link", "set", "lo", "up")
    # Sentinels prove that teardown preserves other chains and firewall policy.
    command("iptables", "-w", "2", "-t", "mangle", "-N", "RW_TEST_SENTINEL")
    command("iptables", "-w", "2", "-t", "mangle", "-A", "RW_TEST_SENTINEL",
            "-m", "comment", "--comment", "unrelated-integration-rule", "-j", "RETURN")
    command("iptables", "-w", "2", "-t", "filter", "-P", "FORWARD", "DROP")

    stopping = threading.Event()
    received_udp, received_tcp = queue.Queue(), queue.Queue()
    udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_server.bind(("127.0.0.1", 0))
    udp_server.settimeout(0.1)
    tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server.bind(("127.0.0.1", 0))
    tcp_server.listen(1)
    tcp_server.settimeout(0.1)

    def udp_echo():
        while not stopping.is_set():
            try:
                data, peer = udp_server.recvfrom(65535)
                received_udp.put(data)
                udp_server.sendto(data, peer)
            except socket.timeout:
                continue
            except OSError:
                break

    def tcp_echo():
        while not stopping.is_set():
            try:
                peer, _ = tcp_server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with peer:
                peer.settimeout(0.1)
                while not stopping.is_set():
                    try:
                        data = peer.recv(65535)
                        if not data:
                            break
                        received_tcp.put(data)
                        peer.sendall(data)
                    except socket.timeout:
                        continue
                    except OSError:
                        break

    threads = [threading.Thread(target=target, daemon=True) for target in (udp_echo, tcp_echo)]
    for thread in threads:
        thread.start()
    udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_client.settimeout(3)
    tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_client.settimeout(3)
    worker = None

    def wait_for(predicate, timeout=6, message="Condition timed out"):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.025)
        raise AssertionError(message)

    def assert_not_delivered(received):
        try:
            unexpected = received.get(timeout=0.2)
        except queue.Empty:
            return
        raise AssertionError(f"Packet reached the echo server before its verdict: {unexpected!r}")

    try:
        with tempfile.TemporaryDirectory(prefix="requestwatch-netns-") as temporary:
            store = Store(Path(temporary) / "integration.sqlite3")
            for proto, server in (("UDP", udp_server), ("TCP", tcp_server)):
                store.save_rule({"id": proto.lower(), "name": f"integration {proto}", "enabled": True,
                                 "source": "packet", "protocol": proto,
                                 "port": server.getsockname()[1], "keyword": "rw-original",
                                 "timeout_seconds": 2})
            config = SimpleNamespace(capture_enabled=True, interfaces="any", queue_num=27030,
                                     protected_ports=(22, 7030, 8080), pending_limit=16)
            runtime = Runtime(store, config)
            worker = NetworkEngine(runtime, config, runner=guarded_run)
            worker.start()
            wait_for(lambda: worker.status()["interception_running"], timeout=12,
                     message=f"NFQUEUE did not start; inspect capabilities/modules: {worker.status()}")
            if not worker.status()["capture_running"]:
                raise AssertionError(f"Passive capture did not start: {worker.status()}")

            def pending_for(payload):
                rows = store.query(state="pending", q=payload.decode(), limit=50)["items"]
                if len(rows) > 1:
                    raise AssertionError("Loopback packet was paused more than once")
                return rows[0] if rows else None

            # UDP: retained packet must not reach its server until the edited verdict.
            original, modified = b"rw-original-edit", b"rw-modified-edit-longer"
            udp_client.sendto(original, udp_server.getsockname())
            record = wait_for(lambda: pending_for(original))
            assert_not_delivered(received_udp)
            runtime.resolve(record["id"], "accept", {"payload_hex": modified.hex()})
            if received_udp.get(timeout=3) != modified or udp_client.recvfrom(65535)[0] != modified:
                raise AssertionError("UDP payload or echo differs from the edited bytes")
            wait_for(lambda: store.get(record["id"])["state"] == "forwarded")

            # UDP: DROP discards this datagram. UDP does not hide failure with TCP retransmission.
            original = b"rw-original-drop"
            udp_client.sendto(original, udp_server.getsockname())
            record = wait_for(lambda: pending_for(original))
            assert_not_delivered(received_udp)
            runtime.resolve(record["id"], "drop", {})
            wait_for(lambda: store.get(record["id"])["state"] == "dropped")
            assert_not_delivered(received_udp)

            # Real Runtime deadline automatically releases the unchanged datagram.
            original = b"rw-original-timeout"
            udp_client.sendto(original, udp_server.getsockname())
            record = wait_for(lambda: pending_for(original))
            assert_not_delivered(received_udp)
            if received_udp.get(timeout=4) != original or udp_client.recvfrom(65535)[0] != original:
                raise AssertionError("Timeout did not release the original UDP datagram")
            wait_for(lambda: store.get(record["id"])["state"] == "forwarded")

            # TCP: handshake passes; the matching application bytes pause and retain length.
            tcp_client.connect(tcp_server.getsockname())
            original, modified = b"rw-original-tcp", b"rw-modified-tcp"
            if len(original) != len(modified):
                raise AssertionError("TCP integration payloads must be equally sized")
            tcp_client.sendall(original)
            record = wait_for(lambda: pending_for(original))
            assert_not_delivered(received_tcp)
            runtime.resolve(record["id"], "accept", {"payload_hex": modified.hex()})
            if received_tcp.get(timeout=3) != modified or tcp_client.recv(65535) != modified:
                raise AssertionError("TCP payload or echo differs from the edited bytes")
            wait_for(lambda: store.get(record["id"])["state"] == "forwarded")

            # Stopping releases a held packet, removes only owned chains, and leaves policy alone.
            original = b"rw-original-stop"
            udp_client.sendto(original, udp_server.getsockname())
            record = wait_for(lambda: pending_for(original))
            assert_not_delivered(received_udp)
            worker.stop()
            if worker._thread.is_alive():
                raise AssertionError("Network worker did not terminate during stop")
            if received_udp.get(timeout=3) != original or udp_client.recvfrom(65535)[0] != original:
                raise AssertionError("Stopping did not release the pending original datagram")

            # Exercise ExecStopPost's crash cleanup against freshly installed orphan rules.
            worker._install_family("iptables")
            cleanup_module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "cleanup_firewall.py"))
            cleanup_module["cleanup"](config.queue_num)
            for binary in ("iptables", "ip6tables"):
                result = guarded_run([binary, "-w", "2", "-t", "mangle", "-S", worker._chain],
                                     capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    raise AssertionError(f"Owned firewall chain remains after cleanup: {binary}")
            sentinel = command("iptables", "-w", "2", "-t", "mangle", "-S", "RW_TEST_SENTINEL").stdout
            if "unrelated-integration-rule" not in sentinel:
                raise AssertionError("Cleanup removed an unrelated firewall rule")
            if "-P FORWARD DROP" not in command("iptables", "-w", "2", "-t", "filter", "-S", "FORWARD").stdout:
                raise AssertionError("Capture changed the existing FORWARD policy")
            store.close()
    finally:
        if worker is not None:
            worker.stop()
        stopping.set()
        for connection in (udp_client, tcp_client, udp_server, tcp_server):
            connection.close()
        for thread in threads:
            thread.join(timeout=1)
    print("NFQUEUE namespace integration passed")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--namespace-worker":
        _namespace_worker(sys.argv[2])
    else:
        unittest.main()
