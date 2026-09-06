import socket
import struct
import unittest
from types import SimpleNamespace

from requestwatch.network import (NetworkEngine, _checksum, edit_packet_payload,
                                  packet_record, parse_packet, validate_packet_edit)


def make_packet(payload=b"hello", protocol="TCP", version=4, seq=100,
                src_port=32100, dst_port=8000, flags=0x18):
    if protocol == "TCP":
        transport = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, 1, 5 << 4, flags, 65535, 0, 0)
        number = 6
    else:
        transport = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
        number = 17
    if version == 4:
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport) + len(payload),
                             42, 0, 64, number, 0, socket.inet_aton("10.0.0.2"), socket.inet_aton("10.0.0.3"))
    else:
        header = struct.pack("!IHBB16s16s", 6 << 28, len(transport) + len(payload), number, 64,
                             socket.inet_pton(socket.AF_INET6, "fd00::2"), socket.inet_pton(socket.AF_INET6, "fd00::3"))
    return edit_packet_payload(header + transport + payload, payload.hex())


class FakePacket:
    hook = 2
    indev = outdev = physindev = physoutdev = 0

    def __init__(self, raw):
        self.raw, self.retained, self.verdicts = raw, False, []

    def get_payload(self):
        return self.raw

    def retain(self):
        self.retained = True

    def set_payload(self, raw):
        self.raw = raw

    def accept(self):
        self.verdicts.append("accept")

    def drop(self):
        self.verdicts.append("drop")


class FakeRuntime:
    def __init__(self, intercept=True):
        self.records, self.decisions, self.intercept = {}, {}, intercept

    def ingest(self, record, can_intercept=False):
        record = dict(record)
        if can_intercept and self.intercept:
            record["state"] = "pending"
        self.records[record["id"]] = record
        return record

    def update(self, record_id, changes):
        self.records[record_id].update(changes)

    def take_decision(self, record_id):
        return self.decisions.pop(record_id, None)

    def rules(self):
        return [{"enabled": self.intercept, "source": "packet", "protocol": "any"}]


def engine(runtime=None, **kwargs):
    config = SimpleNamespace(capture_enabled=True, interfaces="any", queue_num=7030,
                             protected_ports=(22, 7030, 8080), pending_limit=4)
    return NetworkEngine(runtime or FakeRuntime(), config, **kwargs)


class PacketEditingTests(unittest.TestCase):
    def test_tcp_equal_length_edit_has_valid_ip_and_tcp_checksums(self):
        for version in (4, 6):
            raw = make_packet(version=version)
            edited = edit_packet_payload(raw, b"world".hex())
            info = parse_packet(edited)
            self.assertEqual(info.payload, b"world")
            self.assertEqual(len(raw), len(edited))
            if version == 4:
                self.assertEqual(_checksum(edited[:20]), 0)
                pseudo = edited[12:20] + struct.pack("!BBH", 0, 6, len(edited) - 20)
            else:
                pseudo = edited[8:40] + struct.pack("!I3xB", len(edited) - 40, 6)
            self.assertEqual(_checksum(pseudo + edited[info.transport_offset:]), 0)
            with self.assertRaisesRegex(ValueError, "preserve"):
                edit_packet_payload(raw, b"longer".hex())

    def test_udp_resize_updates_lengths_and_checksum(self):
        for version in (4, 6):
            edited = edit_packet_payload(make_packet(protocol="UDP", version=version), b"longer message".hex())
            info = parse_packet(edited)
            self.assertFalse(info.truncated)
            self.assertEqual(info.payload, b"longer message")
            length = len(edited) - info.transport_offset
            self.assertEqual(int.from_bytes(edited[info.transport_offset + 4:info.transport_offset + 6], "big"), length)
            pseudo = (edited[12:20] + struct.pack("!BBH", 0, 17, length) if version == 4
                      else edited[8:40] + struct.pack("!I3xB", length, 17))
            self.assertEqual(_checksum(pseudo + edited[info.transport_offset:]), 0)

    def test_truncated_packet_is_visible_but_not_editable(self):
        raw = make_packet(b"x" * 8000)[:4096]
        record = packet_record(raw)
        self.assertTrue(record["truncated"])
        self.assertFalse(record["editable"])
        with self.assertRaisesRegex(ValueError, "truncated"):
            edit_packet_payload(raw, record["payload_hex"])

    def test_fragment_is_not_editable(self):
        raw = bytearray(make_packet())
        raw[6:8] = (0x2000).to_bytes(2, "big")
        self.assertTrue(parse_packet(raw).fragmented)
        with self.assertRaisesRegex(ValueError, "Fragmented"):
            edit_packet_payload(raw, b"world".hex())

    def test_ipv6_extension_header_transport_is_parsed(self):
        base = bytearray(make_packet(protocol="UDP", version=6))
        base[6] = 0
        base[4:6] = (len(base) - 40 + 8).to_bytes(2, "big")
        raw = bytes(base[:40]) + bytes([17, 0, 0, 0, 0, 0, 0, 0]) + bytes(base[40:])
        edited = edit_packet_payload(raw, b"changed".hex())
        self.assertEqual(parse_packet(edited).payload, b"changed")
        self.assertEqual(parse_packet(edited).transport_offset, 48)

    def test_ipv6_authentication_header_is_visible_but_editing_is_rejected(self):
        base = bytearray(make_packet(protocol="UDP", version=6))
        base[6] = 51
        base[4:6] = (len(base) - 40 + 8).to_bytes(2, "big")
        raw = bytes(base[:40]) + bytes([17, 0, 0, 0, 0, 0, 0, 0]) + bytes(base[40:])
        self.assertFalse(packet_record(raw)["editable"])
        with self.assertRaisesRegex(ValueError, "authentication"):
            edit_packet_payload(raw, b"changed".hex())

    def test_validation_uses_original_bytes_and_rejects_other_fields(self):
        record = packet_record(make_packet())
        self.assertEqual(validate_packet_edit(record, {"payload_hex": "77 6f 72 6c 64"}),
                         {"payload_hex": b"world".hex()})
        for value in ("xyz", 3):
            with self.assertRaises(ValueError):
                validate_packet_edit(record, {"payload_hex": value})
        with self.assertRaises(ValueError):
            validate_packet_edit(record, {"src_ip": "1.1.1.1"})


class NetworkQueueTests(unittest.TestCase):
    def test_retained_packet_is_edited_after_callback(self):
        worker = engine()
        packet = FakePacket(make_packet())
        worker._on_queued(packet)
        self.assertTrue(packet.retained)
        self.assertEqual(packet.verdicts, [])
        record_id = next(iter(worker._pending))
        worker.runtime.decisions[record_id] = {"action": "accept", "edits": {"payload_hex": b"world".hex()}}
        worker._process_decisions()
        self.assertEqual(packet.verdicts, ["accept"])
        self.assertEqual(parse_packet(packet.raw).payload, b"world")
        self.assertEqual(worker.runtime.records[record_id]["state"], "forwarded")

    def test_drop_and_shutdown_release(self):
        worker = engine()
        first, second = FakePacket(make_packet(seq=100)), FakePacket(make_packet(seq=200))
        worker._on_queued(first)
        worker._on_queued(second)
        first_id = next(iter(worker._pending))
        worker.runtime.decisions[first_id] = {"action": "drop"}
        worker._process_decisions()
        worker._disable_queue()
        self.assertEqual(first.verdicts, ["drop"])
        self.assertEqual(second.verdicts, ["accept"])
        self.assertEqual(worker._pending, {})

    def test_protected_connections_are_never_intercepted(self):
        worker = engine()
        for src, dst in ((22, 32100), (32100, 7030), (8080, 32100)):
            packet = FakePacket(make_packet(src_port=src, dst_port=dst))
            worker._on_queued(packet)
            self.assertEqual(packet.verdicts, ["accept"])
        self.assertEqual(worker.runtime.records, {})

    def test_duplicate_tcp_retransmissions_share_pending_decision(self):
        worker = engine()
        first, duplicate = FakePacket(make_packet()), FakePacket(make_packet())
        worker._on_queued(first)
        worker._on_queued(duplicate)
        self.assertEqual(len(worker._pending), 1)
        pending = next(iter(worker._pending.values()))
        worker._resolve(pending, {"action": "accept", "edits": {"payload_hex": b"world".hex()}})
        for packet in (first, duplicate):
            self.assertEqual(parse_packet(packet.raw).payload, b"world")
            self.assertEqual(packet.verdicts, ["accept"])

    def test_identical_udp_datagrams_remain_separate(self):
        worker = engine()
        worker._on_queued(FakePacket(make_packet(protocol="UDP")))
        worker._on_queued(FakePacket(make_packet(protocol="UDP")))
        self.assertEqual(len(worker._pending), 2)

    def test_resegmented_retransmit_uses_cached_changes_and_syn_resets_cache(self):
        worker = engine()
        worker._remember_patch(make_packet(b"hello", seq=100), make_packet(b"world", seq=100))
        self.assertEqual(parse_packet(worker._apply_patches(make_packet(b"ell", seq=101))).payload, b"orl")
        worker._apply_patches(make_packet(b"", seq=1, flags=2))
        self.assertEqual(parse_packet(worker._apply_patches(make_packet(b"hello", seq=100))).payload, b"hello")

    def test_capacity_releases_additional_packets(self):
        worker = engine()
        for index in range(5):
            packet = FakePacket(make_packet(seq=index))
            worker._on_queued(packet)
        self.assertEqual(len(worker._pending), 4)
        self.assertEqual(packet.verdicts, ["accept"])

    def test_invalid_worker_edit_releases_original_with_error(self):
        worker = engine()
        packet = FakePacket(make_packet())
        worker._on_queued(packet)
        pending = next(iter(worker._pending.values()))
        worker._resolve(pending, {"action": "accept", "edits": {"payload_hex": "aa"}})
        self.assertEqual(parse_packet(packet.raw).payload, b"hello")
        self.assertIn("error", worker.runtime.records[pending.record_id])

    def test_windows_reports_unavailable_capture(self):
        worker = engine(platform_name="win32")
        worker.start()
        self.assertIn("Linux", worker.status()["capture_error"])

    def test_firewall_commands_preserve_existing_filter_policy(self):
        calls = []
        def runner(command, **kwargs):
            calls.append(command)
            return SimpleNamespace(returncode=1 if "-C" in command or "-S" in command else 0, stdout="", stderr="")
        worker = engine(runner=runner)
        worker._install_family("iptables")
        self.assertTrue(all(command[3:5] == ["-t", "mangle"] for command in calls))
        self.assertEqual(sum("--queue-bypass" in command for command in calls), 2)
        self.assertEqual(sum("-I" in command for command in calls), 3)
        self.assertFalse(any("DOCKER" in " ".join(command) for command in calls))
        self.assertFalse(any("-P" in command for command in calls))
        self.assertTrue(any("--sport" in command and "7030" in command for command in calls))

    def test_any_explicitly_selects_all_interfaces_and_refreshes(self):
        created = []
        interfaces = ["lo", "eth0", "docker0"]
        class Sniffer:
            def __init__(self, **kwargs):
                self.options, self.running = kwargs, False
                created.append(self)
            def start(self):
                self.running = True
            def stop(self):
                self.running = False
        worker = engine(sniffer_factory=Sniffer, interface_provider=lambda: interfaces)
        worker._start_sniffer()
        self.assertEqual(set(created[0].options["iface"]), {"lo", "eth0", "docker0"})
        interfaces.append("veth-new")
        worker._refresh_interfaces()
        self.assertEqual(len(created), 2)
        self.assertFalse(created[0].running)
        self.assertIn("veth-new", created[1].options["iface"])

    def test_passive_capture_excludes_control_ports_and_does_not_intercept(self):
        class Layer:
            def __init__(self, raw):
                self.raw = raw
            def __bytes__(self):
                return self.raw
        class Sniffed:
            sniffed_on = "eth0"
            def __init__(self, raw):
                self.layer = Layer(raw)
            def getlayer(self, name):
                return self.layer if name == "IP" else None
        worker = engine()
        for port in (22, 7030, 8080):
            worker._on_sniff(Sniffed(make_packet(dst_port=port)))
            worker._on_sniff(Sniffed(make_packet(src_port=port)))
        self.assertEqual(worker._observations.qsize(), 0)
        worker._on_sniff(Sniffed(make_packet()))
        worker._flush_passive(force=True)
        self.assertEqual(len(worker.runtime.records), 1)
        self.assertEqual(next(iter(worker.runtime.records.values()))["state"], "captured")
        self.assertEqual(worker._pending, {})

    def test_queue_start_failure_reports_error_and_unbinds(self):
        class Queue:
            def __init__(self):
                self.unbound = False
            def bind(self, *args, **kwargs):
                pass
            def unbind(self):
                self.unbound = True
        queue_instance = Queue()
        def runner(command, **kwargs):
            raise OSError("iptables unavailable")
        worker = engine(runner=runner, queue_factory=lambda: queue_instance)
        worker._enable_queue()
        self.assertFalse(worker.status()["interception_running"])
        self.assertIn("iptables unavailable", worker.status()["interception_error"])
        self.assertTrue(queue_instance.unbound)

    def test_invalid_nfqueue_bytes_release_unchanged(self):
        worker = engine()
        packet = FakePacket(b"\x45")
        worker._on_queued(packet)
        self.assertEqual(packet.verdicts, ["accept"])
        self.assertIn("Truncated", worker.status()["interception_error"])

    def test_cached_retransmission_handles_sequence_wrap(self):
        worker = engine()
        worker._remember_patch(make_packet(b"hello", seq=0xfffffffe),
                               make_packet(b"world", seq=0xfffffffe))
        self.assertEqual(parse_packet(worker._apply_patches(make_packet(b"llo", seq=0))).payload, b"rld")

    def test_local_non_loopback_addresses_pause_only_at_input(self):
        from unittest.mock import patch
        for version in (4, 6):
            with self.subTest(version=version):
                worker = engine()
                outgoing = FakePacket(make_packet(version=version))
                outgoing.hook, outgoing.outdev = 3, 123
                incoming = FakePacket(make_packet(version=version))
                incoming.hook, incoming.indev = 1, 123
                with patch("requestwatch.network.socket.if_indextoname", return_value="lo"):
                    worker._on_queued(outgoing)
                    worker._on_queued(incoming)
                self.assertEqual(outgoing.verdicts, ["accept"])
                self.assertFalse(outgoing.retained)
                self.assertTrue(incoming.retained)
                self.assertEqual(len(worker._pending), 1)

    def test_retransmits_with_changed_ip_id_and_timestamp_share_decision_and_keep_headers(self):
        def timestamped(identifier, timestamp):
            raw = bytearray(make_packet())
            transport = parse_packet(raw).transport_offset
            options = b"\x01\x01\x08\x0a" + struct.pack("!II", timestamp, 987)
            expanded = raw[:transport + 20] + options + raw[transport + 20:]
            expanded[2:4] = len(expanded).to_bytes(2, "big")
            expanded[4:6] = identifier.to_bytes(2, "big")
            expanded[transport + 12] = 8 << 4
            return edit_packet_payload(expanded, b"hello".hex())
        first_raw, repeat_raw = timestamped(100, 1000), timestamped(101, 2000)
        worker = engine()
        first, repeat = FakePacket(first_raw), FakePacket(repeat_raw)
        worker._on_queued(first)
        worker._on_queued(repeat)
        self.assertEqual(len(worker._pending), 1)
        worker._resolve(next(iter(worker._pending.values())),
                        {"action": "accept", "edits": {"payload_hex": b"world".hex()}})
        for packet, original in ((first, first_raw), (repeat, repeat_raw)):
            self.assertEqual(parse_packet(packet.raw).payload, b"world")
            self.assertEqual(packet.raw[4:6], original[4:6])
            self.assertEqual(packet.raw[40:52], original[40:52])
            self.assertEqual(packet.verdicts, ["accept"])
        self.assertNotEqual(first.raw[40:52], repeat.raw[40:52])

    def test_pending_resegmented_copy_reapplies_earlier_edit_on_accept(self):
        worker = engine()
        first = FakePacket(make_packet(b"hello", seq=100))
        overlap = FakePacket(make_packet(b"ell", seq=101))
        worker._on_queued(first)
        worker._on_queued(overlap)
        first_pending, overlap_pending = list(worker._pending.values())
        worker._resolve(first_pending, {"action": "accept", "edits": {"payload_hex": b"world".hex()}})
        worker._resolve(overlap_pending, {"action": "accept", "edits": {}})
        self.assertEqual(parse_packet(overlap.raw).payload, b"orl")
        self.assertTrue(worker.runtime.records[overlap_pending.record_id]["modified"])

    def test_conflicting_pending_edit_cannot_change_previously_released_bytes(self):
        worker = engine()
        first = FakePacket(make_packet(b"hello", seq=100))
        overlap = FakePacket(make_packet(b"ell", seq=101))
        worker._on_queued(first)
        worker._on_queued(overlap)
        first_pending, overlap_pending = list(worker._pending.values())
        worker._resolve(first_pending, {"action": "accept", "edits": {"payload_hex": b"world".hex()}})
        worker._resolve(overlap_pending, {"action": "accept", "edits": {"payload_hex": b"bad".hex()}})
        self.assertEqual(parse_packet(overlap.raw).payload, b"orl")
        self.assertIn("Previously released", worker.runtime.records[overlap_pending.record_id]["detail"])

    def test_stop_release_keeps_edits_for_previously_queued_overlap(self):
        worker = engine()
        first = FakePacket(make_packet(b"hello", seq=100))
        overlap = FakePacket(make_packet(b"ell", seq=101))
        worker._on_queued(first)
        worker._on_queued(overlap)
        worker._resolve(next(iter(worker._pending.values())),
                        {"action": "accept", "edits": {"payload_hex": b"world".hex()}})
        worker._disable_queue()
        self.assertEqual(parse_packet(overlap.raw).payload, b"orl")
        self.assertEqual(overlap.verdicts, ["accept"])

    def test_invalid_pending_edit_fallback_keeps_earlier_stream_edits(self):
        worker = engine()
        first = FakePacket(make_packet(b"hello", seq=100))
        overlap = FakePacket(make_packet(b"ell", seq=101))
        worker._on_queued(first)
        worker._on_queued(overlap)
        first_pending, overlap_pending = list(worker._pending.values())
        worker._resolve(first_pending, {"action": "accept", "edits": {"payload_hex": b"world".hex()}})
        worker._resolve(overlap_pending, {"action": "accept", "edits": {"payload_hex": "ff"}})
        self.assertEqual(parse_packet(overlap.raw).payload, b"orl")
        self.assertIn("error", worker.runtime.records[overlap_pending.record_id])

    def test_cleanup_rejects_prefixed_or_suffixed_foreign_comment(self):
        for marker in ("foreign-requestwatch-managed-7030", "requestwatch-managed-7030-foreign"):
            with self.subTest(marker=marker):
                calls = []
                def runner(command, **kwargs):
                    calls.append(command)
                    if "-C" in command:
                        return SimpleNamespace(returncode=1, stdout="", stderr="")
                    if "-S" in command:
                        return SimpleNamespace(returncode=0,
                            stdout=f'-A RWATCH_7030 -m comment --comment "{marker}" -j RETURN\n',
                            stderr="")
                    return SimpleNamespace(returncode=0, stdout="", stderr="")
                worker = engine(runner=runner)
                with self.assertRaisesRegex(RuntimeError, "non-RequestWatch"):
                    worker._cleanup_family("iptables")
                self.assertFalse(any("-F" in command or "-X" in command for command in calls))

    def test_cleanup_accepts_exact_quoted_comment(self):
        calls = []
        def runner(command, **kwargs):
            calls.append(command)
            if "-C" in command:
                return SimpleNamespace(returncode=1, stdout="", stderr="")
            if "-S" in command:
                return SimpleNamespace(returncode=0,
                    stdout='-A RWATCH_7030 -m comment --comment "requestwatch-managed-7030" -j RETURN\n',
                    stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        engine(runner=runner)._cleanup_family("iptables")
        self.assertTrue(any("-F" in command for command in calls))
        self.assertTrue(any("-X" in command for command in calls))


if __name__ == "__main__":
    unittest.main()


def test_shutdown_drains_more_than_a_normal_batch_after_stopping_producer():
    worker = engine(FakeRuntime(intercept=False))
    raw = make_packet(b"last captured bytes")
    events = []
    for _ in range(700):
        worker._observations.put((0, raw, "eth0"))

    class Sniffer:
        running = True

        def stop(self):
            events.append("sniffer stopped")
            self.running = False
            worker._observations.put((0, raw, "eth0"))

    class Thread:
        def join(self, timeout):
            assert not worker._sniffer.running
            events.append("worker joined")
            worker._flush_passive(force=True)
            assert worker._observations.empty()

        def is_alive(self):
            return False

    worker._sniffer, worker._thread = Sniffer(), Thread()
    worker.stop()
    assert events == ["sniffer stopped", "worker joined"]
    assert worker._observations.empty()
    assert len(worker.runtime.records) == 701


def test_normal_passive_flush_keeps_its_verdict_fairness_budget():
    worker = engine(FakeRuntime(intercept=False))
    raw = make_packet()
    for _ in range(700):
        worker._observations.put((0, raw, "eth0"))
    worker._flush_passive()
    assert len(worker.runtime.records) == 512
    assert worker._observations.qsize() == 188
    worker._flush_passive(force=True)
    assert len(worker.runtime.records) == 700


class ReceivedWireFrame:
    sniffed_on = "eth0"

    def __init__(self, raw):
        self.layer = SimpleNamespace(original=raw)

    def getlayer(self, name):
        return self.layer if name == "IP" else None


def test_network_profile_defaults_to_readonly_and_never_installs_nfqueue(tmp_path):
    import time
    from requestwatch.config import Config

    calls = []

    def forbidden(*args, **kwargs):
        calls.append(args)
        raise AssertionError("Read-only capture must not load NFQUEUE or modify iptables")

    class Sniffer:
        def __init__(self, **kwargs):
            self.running = False

        def start(self):
            self.running = True

        def stop(self):
            self.running = False

    config = Config(data_dir=tmp_path, token="readonly-capture-test-token", inspection_profile="network")
    config.prepare()
    assert config.passive_only is True
    runtime = FakeRuntime(intercept=True)  # Even existing enabled packet rules cannot activate queueing.
    worker = NetworkEngine(runtime, config, runner=forbidden, queue_factory=forbidden,
                           sniffer_factory=Sniffer, interface_provider=lambda: ["eth0"], platform_name="linux")
    try:
        worker.start()
        assert worker._rules_need_queue() is False
        worker._enable_queue()
        worker._on_sniff(ReceivedWireFrame(make_packet(b"read-only-full-payload")))
        until = time.monotonic() + 2
        while not runtime.records and time.monotonic() < until:
            time.sleep(0.005)
        assert len(runtime.records) == 1
        record = next(iter(runtime.records.values()))
        assert record["payload_text"] == "read-only-full-payload" and record["state"] == "captured"
        queued = FakePacket(make_packet())
        worker._on_queued(queued)
        assert queued.verdicts == ["accept"] and not queued.retained
        assert len(runtime.records) == 1 and calls == []
        assert worker.status()["capture_mode"] == "passive" and not worker.status()["interception_running"]
    finally:
        worker.stop()
    assert calls == []


def test_passive_callback_keeps_original_bytes_and_worker_batches_without_nfqueue_delay(monkeypatch):
    class BatchedRuntime(FakeRuntime):
        def __init__(self):
            super().__init__(intercept=False)
            self.batches = []

        def ingest_packets(self, records):
            self.batches.append(len(records))
            for record in records:
                self.ingest(record, can_intercept=False)

    runtime = BatchedRuntime()
    worker = engine(runtime)
    worker.config.passive_only = True
    raw = make_packet(b"complete-payload" * 200)
    frame = ReceivedWireFrame(raw)  # Layer has no __bytes__: use received bytes directly.
    for _ in range(700):
        worker._on_sniff(frame)
    assert runtime.records == {} and worker._observations.qsize() == 700

    def no_hash(*args, **kwargs):
        raise AssertionError("Pure passive capture must not compute NFQUEUE fingerprints")

    monkeypatch.setattr("requestwatch.network.hashlib.blake2s", no_hash)
    assert worker._flush_passive() == 512  # Newly captured packets do not wait 120ms.
    assert runtime.batches == [512]
    worker._flush_passive(force=True)
    assert runtime.batches == [512, 188]
    assert len(runtime.records) == 700
    assert all(record["payload_hex"] == parse_packet(raw).payload.hex() for record in runtime.records.values())


def test_observation_overflow_counter_does_not_mean_original_packet_drop():
    import queue

    worker = engine(FakeRuntime(intercept=False))
    worker.config.passive_only = True
    worker._observations = queue.Queue(maxsize=1)
    raw = make_packet(b"wire-copy")
    frame = ReceivedWireFrame(raw)
    worker._on_sniff(frame)
    worker._on_sniff(frame)
    assert frame.layer.original == raw
    status = worker.status()
    assert status["passive_dropped"] == status["observation_dropped"] == 1
    assert status["observation_backlog"] == 1
    assert status["observation_drop_semantics"] == "capture copies not saved; original network packets are unaffected"
    assert not worker._pending and worker._nfqueue is None


def test_failed_batch_retries_individual_records_instead_of_losing_whole_batch():
    class FailingBatch(FakeRuntime):
        def ingest_packets(self, records):
            raise OSError("batch failed before commit")

    runtime = FailingBatch(intercept=False)
    worker = engine(runtime)
    for _ in range(12):
        worker._on_sniff(ReceivedWireFrame(make_packet()))
    worker._flush_passive(force=True)
    assert len(runtime.records) == 12
    assert worker.status()["observation_write_failed"] == 0


def test_large_passive_packets_use_bounded_byte_batches_without_truncation():
    class BatchedRuntime(FakeRuntime):
        def __init__(self):
            super().__init__(intercept=False)
            self.batches = []

        def ingest_packets(self, records):
            self.batches.append((len(records), sum(record["payload_size"] for record in records)))
            for record in records:
                self.ingest(record, can_intercept=False)

    runtime = BatchedRuntime()
    worker = engine(runtime)
    payload = b"x" * 60000 + b"GSO-END"
    raw = make_packet(payload)
    for _ in range(150):
        worker._on_sniff(ReceivedWireFrame(raw))
    worker._flush_passive(force=True)
    assert len(runtime.records) == 150 and len(runtime.batches) >= 3
    assert all(size < 4 * 1024 * 1024 + len(raw) for _, size in runtime.batches)
    assert all(record["payload_size"] == len(payload) and record["payload_text"].endswith("GSO-END") for record in runtime.records.values())
