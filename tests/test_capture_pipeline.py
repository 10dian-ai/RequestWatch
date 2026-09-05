"""Real Scapy serialization through capture, persistence, and TCP reconstruction."""
import hashlib
import json
from types import SimpleNamespace

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from requestwatch.dockerinfo import DockerInventory
from requestwatch.network import NetworkEngine
from requestwatch.runtime import Runtime
from requestwatch.store import Store
from requestwatch.stream_decode import decode_stream_file
from requestwatch.tcp_streams import TCPStreamStore


class QueuedPacket:
    hook = 2
    indev = outdev = physindev = physoutdev = 0

    def __init__(self, raw):
        self.raw, self.accepted = raw, False

    def get_payload(self):
        return self.raw

    def accept(self):
        self.accepted = True


def wire_packet(payload=b"", *, seq=100, flags="PA", reverse=False, identifier=1):
    source, target, sport, dport = "18.180.237.131", "172.19.0.2", 54779, 3000
    if reverse:
        source, target, sport, dport = target, source, dport, sport
    frame = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / IP(src=source, dst=target, id=identifier) / TCP(sport=sport, dport=dport, seq=seq, flags=flags)
    if payload:
        frame = frame / Raw(payload)
    # Capture callbacks receive an already-dissected Scapy frame, not our builder.
    captured = Ether(bytes(frame))
    captured.sniffed_on = "br-container"
    return captured


def test_docker_chunked_sse_survives_real_capture_layers_retention_and_retransmission(tmp_path):
    store = Store(tmp_path / "records.sqlite3", max_records=8)
    streams = TCPStreamStore(tmp_path)
    inventory = DockerInventory()
    inventory._containers = [{"id": "container-1", "name": "event-server",
                              "ips": ["172.19.0.2"], "network_mode": "bridge"}]
    config = SimpleNamespace(capture_enabled=True, interfaces="any", queue_num=7030,
                             protected_ports=(22, 7030, 8080), pending_limit=4)
    runtime = Runtime(store, config, inventory=inventory, streams=streams)
    engine = NetworkEngine(runtime, config)
    observations = 0

    def capture(frame):
        nonlocal observations
        engine._on_sniff(frame)
        if observations % 3 == 0:
            queued = QueuedPacket(bytes(frame.getlayer("IP")))
            engine._on_queued(queued)
            assert queued.accepted
        engine._flush_passive(force=True)
        observations += 1

    try:
        capture(wire_packet(seq=99, flags="S"))
        capture(wire_packet(seq=199, flags="SA", reverse=True))
        request = b"GET /events HTTP/1.1\r\nHost: event-server:3000\r\n\r\n"
        capture(wire_packet(request, seq=100))
        events = []
        for index in range(1200):
            delta = {"reasoning_content": "灰色"} if index == 0 else {"content": f"完整正文第{index}段。\n"}
            event = {"id": "capture-regression", "choices": [{"index": 0, "delta": delta}]}
            events.append(b"data: " + json.dumps(event, ensure_ascii=False).encode() + b"\n\n")
        events.append(b'data: {"choices":[{"index":0,"delta":{"content":"CAPTURE-COMPLETE-TAIL"}}]}\n\n')
        framed = b"".join(f"{len(event):x}\r\n".encode() + event + b"\r\n" for event in events) + b"0\r\n\r\n"
        response = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n" + framed
        assert len(response) > 100_000
        offsets = list(range(0, len(response), 1111))
        # Data arrives out of order; the final export still follows TCP sequence.
        offsets[1], offsets[2] = offsets[2], offsets[1]
        for offset in offsets:
            capture(wire_packet(response[offset:offset+1111], seq=200+offset, reverse=True))
        capture(wire_packet(response[:1111], seq=200, reverse=True, identifier=2))  # retransmission
        capture(wire_packet(seq=100+len(request), flags="FA"))
        capture(wire_packet(seq=200+len(response), flags="FA", reverse=True))

        sessions = streams.list_sessions(container_id="container-1")["items"]
        assert len(sessions) == 1
        session = sessions[0]
        assert session["complete"] and not session["direction_inferred"]
        assert session["client_ip"] == "18.180.237.131"
        assert session["server_ip"] == "172.19.0.2"
        assert session["packet_count"] == observations
        assert streams.body_path(session["id"], "client").read_bytes() == request
        body = streams.body_path(session["id"], "server")
        assert hashlib.sha256(body.read_bytes()).digest() == hashlib.sha256(response).digest()
        assert streams.list_sessions(q="CAPTURE-COMPLETE-TAIL")["total"] == 1
        stats = store.stats()
        assert stats["captured_total"] == observations and stats["retained"] == 8
        assert stats["evicted_total"] == observations-8
        for summary in store.query()["items"]:
            record = store.get(summary["id"])
            assert record["tcp_session_id"] == session["id"]
            assert record["container_id"] == "container-1"
            assert record["payload_size"] == len(bytes.fromhex(record["payload_hex"]))
            assert streams.session_id_for_record(record["id"]) == session["id"]
        output = tmp_path / "readable.txt"
        parsed = decode_stream_file(body, output)
        readable = output.read_text("utf-8")
        assert parsed["recognized"] and parsed["kind"] == "http-sse"
        assert "灰色" in readable and "完整正文第1199段。" in readable and "CAPTURE-COMPLETE-TAIL" in readable
        assert "\ufffd" not in readable
        assert engine.status()["passive_dropped"] == 0
    finally:
        streams.close()
        store.close()


def test_exact_packet_session_lookup_never_guesses_a_reused_tuple(tmp_path):
    from requestwatch.network import packet_record

    streams = TCPStreamStore(tmp_path, max_sessions=2)
    try:
        first = packet_record(bytes(wire_packet(seq=99, flags="S").getlayer("IP")))
        old_id = streams.ingest(first)
        later = packet_record(bytes(wire_packet(seq=999, flags="S").getlayer("IP")))
        new_id = streams.ingest(later)
        assert old_id != new_id
        assert streams.session_id_for_record(first["id"]) == old_id
        assert streams.session_id_for_record(later["id"]) == new_id
        assert streams.session_id_for_record("unknown-record") is None
        assert streams.session_id_for_record(None) is None
        # Once the old session is evicted its observation cannot resolve to the newer tuple.
        newest = packet_record(bytes(wire_packet(seq=9999, flags="S").getlayer("IP")))
        streams.ingest(newest)
        assert streams.get(old_id) is None
        assert streams.session_id_for_record(first["id"]) is None
        assert streams.session_id_for_record(later["id"]) == new_id
    finally:
        streams.close()
