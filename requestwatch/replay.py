from __future__ import annotations

import base64
import re
import socket
import time
from email.message import Message
from urllib.parse import urlsplit

import httpx


MAX_BODY = 1024 * 1024
HOP_HEADERS = {"connection", "proxy-connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade", "proxy-authorization", "proxy-authenticate", "content-length", "host"}


def validate_http_edits(edits: dict) -> dict:
    if not isinstance(edits, dict):
        raise ValueError("HTTP 编辑必须是对象")
    if set(edits) - {"method", "url", "headers", "body_text", "body_b64"}:
        raise ValueError("HTTP 编辑字段无效")
    if "url" in edits:
        value = edits["url"]
        if not isinstance(value, str) or any(ord(c) <= 32 or ord(c) == 127 for c in value):
            raise ValueError("URL 必须是没有空白或控制字符的 HTTP/HTTPS 地址")
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or "#" in value or "\\" in value):
            raise ValueError("URL 必须是 HTTP/HTTPS，且不能包含用户名、密码或片段")
        port = parsed.port
        if port is not None and port < 1:
            raise ValueError("URL 端口必须在 1–65535 范围内")
    if "method" in edits and (not isinstance(edits["method"], str)
                              or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}", edits["method"])):
        raise ValueError("HTTP 方法无效")
    if "body_text" in edits and "body_b64" in edits:
        raise ValueError("正文不能同时使用文本和 Base64")
    if "body_text" in edits and (not isinstance(edits["body_text"], str) or len(edits["body_text"].encode()) > MAX_BODY):
        raise ValueError("编辑正文不能超过 1 MiB")
    if "body_b64" in edits:
        if not isinstance(edits["body_b64"], str):
            raise ValueError("正文 Base64 必须是字符串")
        try:
            body = base64.b64decode(edits["body_b64"], validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("正文 Base64 无效") from exc
        if len(body) > MAX_BODY:
            raise ValueError("编辑正文不能超过 1 MiB")
    if "headers" in edits:
        headers = edits["headers"]
        if not isinstance(headers, list) or len(headers) > 200:
            raise ValueError("请求头必须是名称和值组成的数组，最多 200 项")
        for pair in headers:
            if (not isinstance(pair, (list, tuple)) or len(pair) != 2 or not all(isinstance(x, str) for x in pair)
                    or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", pair[0]) or any(c in pair[1] for c in "\r\n\0")):
                raise ValueError("请求头格式无效")
        if sum(len(k) + len(v) for k, v in headers) > 65536:
            raise ValueError("请求头过长")
    return edits


def request_parts(record: dict, edits: dict):
    validate_http_edits(edits)
    if record.get("request_truncated") and not ({"body_text", "body_b64"} & edits.keys()):
        raise ValueError("请求正文已截断，请补齐完整正文后重发")
    method = edits.get("method", record.get("method", "GET"))
    url = edits.get("url", record.get("url", ""))
    validate_http_edits({"method": method, "url": url})
    headers = edits.get("headers", record.get("request_headers", []))
    validate_http_edits({"headers": headers})
    connection_tokens = {v.strip().lower() for k, value in headers if k.lower() == "connection" for v in value.split(",")}
    headers = [(k, v) for k, v in headers if k.lower() not in HOP_HEADERS | connection_tokens]
    if "body_b64" in edits:
        body = base64.b64decode(edits["body_b64"], validate=True)
    elif "body_text" in edits:
        body = edits["body_text"].encode("utf-8")
        # An explicitly edited text body is no longer the original compressed representation.
        headers = [(k, v) for k, v in headers if k.lower() != "content-encoding"]
        content_type_found = False
        for index, (name, value) in enumerate(headers):
            if name.lower() == "content-type":
                content_type_found = True
                message = Message()
                message["Content-Type"] = value
                message.set_param("charset", "utf-8", header="Content-Type", replace=True)
                headers[index] = (name, message["Content-Type"])
        if not content_type_found:
            headers.append(("Content-Type", "text/plain; charset=utf-8"))
    else:
        if "request_body_b64" in record:
            try:
                body = base64.b64decode(record["request_body_b64"], validate=True)
            except (ValueError, TypeError) as exc:
                raise ValueError("已保存的请求正文 Base64 无效") from exc
        else:
            body = record.get("request_body_text", "").encode("utf-8")
    return method, url, headers, body


def replay_http(record: dict, edits: dict) -> dict:
    method, url, headers, body = request_parts(record, edits)
    parsed = urlsplit(url)
    result = {"source": "http", "protocol": parsed.scheme.upper(), "method": method, "url": url,
              "dst_ip": parsed.hostname, "dst_port": parsed.port or (443 if parsed.scheme == "https" else 80),
              "summary": f"{method} {url}", "state": "replayed", "replay_of": record["id"],
              "attribution": "host-replay", "container_id": "", "container_name": "宿主机重发",
              "request_headers": headers, "request_body_text": body.decode("utf-8", errors="replace"),
              "request_body_b64": base64.b64encode(body).decode(), "payload_text": body.decode("utf-8", errors="replace")}
    started = time.monotonic()
    try:
        with httpx.Client(timeout=20, trust_env=False, follow_redirects=False) as client:
            with client.stream(method, url,
                               headers=[(k.encode("ascii"), v.encode("utf-8")) for k, v in headers],
                               content=body) as response:
                chunks, length = [], 0
                for chunk in response.iter_bytes():
                    chunks.append(chunk[:max(0, MAX_BODY + 1 - length)])
                    length += len(chunk)
                    if length > MAX_BODY:
                        break
                content = b"".join(chunks)[:MAX_BODY]
                result.update(status_code=response.status_code, response_headers=list(response.headers.multi_items()),
                              response_body_text=content.decode("utf-8", errors="replace"), response_body_b64=base64.b64encode(content).decode(),
                              response_truncated=length > MAX_BODY)
    except (httpx.HTTPError, OSError, ValueError) as exc:
        result.update(state="error", error=str(exc))
    result["duration_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


def replay_packet(record: dict, edits: dict) -> dict:
    if not isinstance(edits, dict) or set(edits) - {"payload_hex"}:
        raise ValueError("原始包重发仅支持编辑 payload_hex")
    try:
        payload = bytes.fromhex(edits.get("payload_hex", record.get("payload_hex", "")))
    except (TypeError, ValueError) as exc:
        raise ValueError("请输入有效的十六进制内容") from exc
    if not payload:
        raise ValueError("此包没有应用数据，不能作为新请求重发")
    if len(payload) > 65507:
        raise ValueError("单次发送内容不能超过 65507 字节")
    if record.get("truncated") and "payload_hex" not in edits:
        raise ValueError("包已截断，请提供完整数据后再重发")
    host, port = record.get("dst_ip"), record.get("dst_port")
    if not isinstance(host, str) or not host or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("目标地址或端口无效")
    protocol = record.get("protocol")
    if protocol not in {"TCP", "UDP"}:
        raise ValueError("仅支持 TCP/UDP 数据重发")
    result = {"source": "packet", "protocol": protocol, "dst_ip": host, "dst_port": port,
              "state": "replayed", "summary": f"{protocol} 新连接重发 → {host}:{port}", "replay_of": record["id"],
              "container_id": "", "container_name": "宿主机重发", "attribution": "host-replay",
              "payload_hex": payload.hex(), "payload_text": payload.decode("utf-8", errors="replace"), "payload_size": len(payload),
              "detail": "使用宿主机新连接/数据报发送，不复用原连接或容器身份"}
    started = time.monotonic()
    try:
        if protocol == "TCP":
            connection = socket.create_connection((host, port), timeout=5)
        else:
            family, socktype, proto, _, address = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
            connection = socket.socket(family, socktype, proto)
            connection.settimeout(5)
            connection.connect(address)
        with connection:
            result["src_ip"], result["src_port"] = connection.getsockname()[:2]
            connection.sendall(payload)
            result["sent_bytes"] = len(payload)
            connection.settimeout(2)
            try:
                response = connection.recv(65535)
                result.update(response_body_text=response.decode("utf-8", errors="replace"), response_body_b64=base64.b64encode(response).decode())
            except socket.timeout:
                result["detail"] += "；2 秒内未收到回复，数据已提交发送"
    except OSError as exc:
        result.update(state="error", error=str(exc))
    result["duration_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result
