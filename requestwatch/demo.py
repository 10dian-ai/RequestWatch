import base64
import json
import time


CONTAINERS = [
    {"id": "demo-newapi", "name": "new-api-demo", "image": "new-api:demo", "status": "演示容器", "network_mode": "bridge", "ips": ["172.18.0.2"], "ports": [{"private_port": 3000, "public_port": 3000, "ip": "0.0.0.0", "type": "tcp"}]},
    {"id": "demo-api", "name": "orders-api", "image": "orders-api:dev", "status": "演示容器", "network_mode": "bridge", "ips": ["172.18.0.3"]},
    {"id": "demo-worker", "name": "event-worker", "image": "event-worker:dev", "status": "演示容器", "network_mode": "bridge", "ips": ["172.18.0.4"]},
]


def seed(runtime):
    if getattr(runtime.config, "inspection_profile", "network") == "newapi":
        seed_newapi(runtime)
    if runtime.streams and not runtime.streams.list_sessions(limit=1)["total"]:
        seed_tcp(runtime)
    if runtime.store.get("demo-http-0"):
        return
    for i, (method, path, status, body) in enumerate([
        ("GET", "/v1/orders?limit=20", 200, '{"orders": [{"id": "ORD-2048", "status": "已付款"}]}'),
        ("POST", "/v1/events", 202, '{"accepted": true}'),
        ("GET", "/v1/health", 200, '{"status": "ok"}'),
        ("GET", "/v1/inventory", 503, '{"error": "upstream unavailable"}'),
    ]):
        request_body = '{"event": "order.created", "order_id": "ORD-2048"}' if method == "POST" else ""
        runtime.ingest({"id": f"demo-http-{i}", "source": "http", "protocol": "HTTPS", "state": "forwarded",
                        "created_at": time.time() - (4-i)*20, "method": method, "url": "https://api.example.test" + path,
                        "summary": method + " " + path, "status_code": status, "duration_ms": 43 + i*29,
                        "src_ip": "172.18.0.3", "src_port": 42001+i, "dst_ip": "192.0.2.20", "dst_port": 443,
                        "container_id": "demo-api", "container_name": "orders-api", "attribution": "demo",
                        "request_headers": [["Accept", "application/json"], ["Content-Type", "application/json"]],
                        "request_body_text": request_body, "request_body_b64": base64.b64encode(request_body.encode()).decode(),
                        "response_headers": [["Content-Type", "application/json"]], "response_body_text": body,
                        "payload_text": request_body, "demo": True})
    runtime.ingest({"id": "demo-udp-0", "source": "packet", "protocol": "UDP", "state": "captured",
                    "created_at": time.time()-10, "src_ip": "172.18.0.4", "src_port": 39544, "dst_ip": "192.0.2.53", "dst_port": 8125,
                    "summary": "UDP · worker.events:1|c", "container_id": "demo-worker", "container_name": "event-worker",
                    "attribution": "demo", "payload_hex": b"worker.events:1|c".hex(), "payload_text": "worker.events:1|c", "payload_size": 17, "demo": True})


def intercept_example(runtime):
    rules = runtime.rules()
    if not rules:
        return None
    rule = next((r for r in rules if r.get("enabled")), None)
    if not rule:
        return None
    record = {"source": "http", "protocol": "HTTPS", "method": "POST", "url": "https://api.example.test/v1/demo",
              "src_ip": "172.18.0.3", "src_port": 45200, "dst_ip": "192.0.2.20", "dst_port": rule.get("port") or 443,
              "container_id": rule.get("container_id") or "demo-api", "container_name": "演示容器",
              "summary": "POST /v1/demo", "request_headers": [["Content-Type", "text/plain"]],
              "request_body_text": rule.get("keyword") or "demo request", "payload_text": rule.get("keyword") or "demo request", "demo": True}
    if rule.get("host"):
        record["url"] = "https://" + rule["host"].split("/")[0] + "/v1/demo"
        record["dst_ip"] = rule["host"].split("/")[0]
    if rule.get("source") == "packet" or rule.get("protocol") in {"TCP", "UDP"}:
        record.update(source="packet", protocol=rule.get("protocol") if rule.get("protocol") in {"TCP", "UDP"} else "TCP")
        record["payload_hex"] = record["payload_text"].encode().hex()
        record["payload_size"] = len(record["payload_text"].encode())
    elif rule.get("protocol") in {"HTTP", "HTTPS"}:
        record["protocol"] = rule["protocol"]
    return runtime.ingest(record, can_intercept=True)


def apply_demo_edits(record, edits, body_store=None):
    from .replay import request_parts
    result = dict(record)
    if not edits:
        return result
    if record["source"] == "http":
        if body_store:
            record = dict(record)
            record["request_body_b64"] = base64.b64encode(body_store.read_body(record)).decode()
        method, url, headers, body = request_parts(record, edits, body_store)
        for suffix in ("_body_ref", "_text_ref", "_body_complete", "_truncated", "_body_size"):
            result.pop("request" + suffix, None)
        result.update(method=method, url=url, request_headers=headers,
                      request_body_text=body.decode("utf-8", errors="replace"),
                      request_body_b64=base64.b64encode(body).decode(),
                      payload_text=body.decode("utf-8", errors="replace"), summary=f"{method} {url}")
    else:
        payload = bytes.fromhex(edits.get("payload_hex", record.get("payload_hex", "")))
        result.update(payload_hex=payload.hex(), payload_text=payload.decode("utf-8", errors="replace"), payload_size=len(payload))
    return result


def seed_tcp(runtime):
    """Synthetic packets only; never opens a socket or sends traffic."""
    import socket
    import struct
    from .network import _checksum
    client, server = "172.18.0.4", "192.0.2.30"
    request = b"EVENT /jobs\r\nContent-Type: application/json\r\n\r\n" + ('{"event":"跨包完整会话","padding":"' + 'x' * 80000 + '","result":"TCP-DEMO-END"}').encode()
    response = b"OK 200\r\n\r\n" + '服务端完整响应'.encode()
    def add(reverse, seq, flags, payload=b""):
        src, dst = (server, client) if reverse else (client, server)
        sport, dport = (9000, 45000) if reverse else (45000, 9000)
        transport = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 65535, 0, 0) + payload
        pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(transport))
        transport = transport[:16] + struct.pack("!H", _checksum(pseudo + transport)) + transport[18:]
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 0, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
        header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
        runtime.ingest({"source": "packet", "protocol": "TCP", "state": "captured", "demo": True,
                       "src_ip": src, "src_port": sport, "dst_ip": dst, "dst_port": dport,
                       "container_id": "demo-worker", "container_name": "event-worker", "attribution": "demo",
                       "summary": "TCP 演示会话 · " + ("响应" if reverse else "请求"),
                       "raw_b64": base64.b64encode(header + transport).decode(),
                       "payload_text": payload.decode("utf-8", errors="replace"), "payload_hex": payload.hex(), "payload_size": len(payload)})
    add(False, 100, 2)
    add(True, 500, 18)
    for offset in reversed(range(0, len(request), 32000)):
        add(False, 101 + offset, 24, request[offset:offset + 32000])
    add(True, 501, 24, response)
    add(False, 101 + len(request), 17)
    add(True, 501 + len(response), 17)


def seed_newapi(runtime):
    """Explicitly simulated two-leg LLM exchange; never contacts New API."""
    if runtime.store.get("demo-newapi-client"):
        return
    messages = [
        {"role": "system", "content": "用中文回答。保留重要细节，给出可执行的步骤。"},
        {"role": "user", "content": "解释 Docker Compose 中服务名、宿主机映射端口和容器端口的区别。"},
    ]
    response = (
        'data: '+json.dumps({"choices":[{"index":0,"delta":{"reasoning_content":"先区分宿主机和容器的网络空间。","content":"同一 Compose 网络里的服务可以通过服务名互相访问。\n"}}]},ensure_ascii=False)+'\n\n'
        +'data: '+json.dumps({"choices":[{"index":0,"delta":{"content":"宿主机访问映射端口；容器之间使用服务名和容器内部端口。"},"finish_reason":"stop"}]},ensure_ascii=False)+'\n\ndata: [DONE]\n\n'
    )
    for leg in ("client", "upstream"):
        body = {"model": "client-model-alias" if leg == "client" else "provider-model-demo", "messages": messages, "stream": True}
        if leg == "upstream":
            body = {**body, "messages": [{"role":"system","content":"这是渠道附加的系统提示，仅出现在上游请求。"}]+messages}
        raw = json.dumps(body,ensure_ascii=False).encode()
        url = "http://new-api-demo:3000/v1/chat/completions" if leg == "client" else "https://provider.example.test/v1/chat/completions"
        runtime.ingest({"id":"demo-newapi-"+leg,"source":"http","protocol":"HTTP" if leg=="client" else "HTTPS",
                       "capture_leg":leg,"state":"forwarded","created_at":time.time()-(1 if leg=="client" else 0),
                       "method":"POST","url":url,"summary":"POST /v1/chat/completions","status_code":200,
                       "container_id":"demo-newapi","container_name":"new-api-demo","attribution":"demo","demo":True,
                       "request_headers":[["Content-Type","application/json"]],"request_body_b64":base64.b64encode(raw).decode(),
                       "request_body_text":raw.decode(),"response_headers":[["Content-Type","text/event-stream"]],
                       "response_body_b64":base64.b64encode(response.encode()).decode(),"response_body_text":response,
                       "response_sse_utf8":True,"request_body_complete":True,"response_body_complete":True})
