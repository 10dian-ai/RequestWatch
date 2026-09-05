import base64
import time


CONTAINERS = [
    {"id": "demo-api", "name": "orders-api", "image": "orders-api:dev", "status": "演示容器", "network_mode": "bridge", "ips": ["172.18.0.3"]},
    {"id": "demo-worker", "name": "event-worker", "image": "event-worker:dev", "status": "演示容器", "network_mode": "bridge", "ips": ["172.18.0.4"]},
]


def seed(runtime):
    if runtime.store.stats()["total"]:
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


def apply_demo_edits(record, edits):
    from .replay import request_parts
    result = dict(record)
    if not edits:
        return result
    if record["source"] == "http":
        method, url, headers, body = request_parts(record, edits)
        result.update(method=method, url=url, request_headers=headers,
                      request_body_text=body.decode("utf-8", errors="replace"),
                      request_body_b64=base64.b64encode(body).decode(),
                      payload_text=body.decode("utf-8", errors="replace"), summary=f"{method} {url}")
    else:
        payload = bytes.fromhex(edits.get("payload_hex", record.get("payload_hex", "")))
        result.update(payload_hex=payload.hex(), payload_text=payload.decode("utf-8", errors="replace"), payload_size=len(payload))
    return result
