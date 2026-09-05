"""File-backed HTTP/1 and SSE readability; raw capture remains the source of truth.

Framing follows RFC 9112 section 6/7. SSE dispatch follows the HTML event-stream
algorithm. This module never sends traffic, guesses across sequence gaps, or
claims TLS ciphertext is readable. Limits bound parsing memory, not file output.
"""
from __future__ import annotations

import codecs
import json
import os
from pathlib import Path
import re
import tempfile
import zlib

DECODER_VERSION = 2
BLOCK = 64 * 1024
JSON_BUDGET = 4 * 1024 * 1024
HEADER_BUDGET = 256 * 1024
HTTP_START = re.compile(rb"(?:HTTP/1\.[01] [0-9]{3}(?: [^\r\n]*)?|[!#$%&'*+.^_`|~0-9A-Za-z-]+ [^\r\n ]+ HTTP/1\.[01])\r?\n")
CHUNK_START = re.compile(rb"[0-9a-fA-F]{1,16}(?:;[^\r\n]*)?\r\n")


def _warning(meta, message):
    if message not in meta["warnings"]:
        meta["warnings"].append(message)


def _incomplete(meta, message):
    meta["complete"] = False
    _warning(meta, message)


def _copy(source, target, count=None):
    total = 0
    while count is None or total < count:
        piece = source.read(BLOCK if count is None else min(BLOCK, count-total))
        if not piece:
            break
        target.write(piece)
        total += len(piece)
    return total


def _append_file(source, target):
    with Path(source).open("r", encoding="utf-8", newline="") as stream:
        _copy(stream, target)


def _line(stream):
    line = stream.readline(HEADER_BUDGET+1)
    if len(line) > HEADER_BUDGET:
        raise ValueError("HTTP 头行或分块长度行过长；请查看原始数据")
    return line


def _chunked(source, destination, meta):
    """Consume exactly one body, including trailers; retain observed partial data."""
    trailers = []
    total_trailer = 0
    with destination.open("wb") as output:
        while True:
            line = _line(source)
            if not line:
                _incomplete(meta, "分块传输尚未收到结束块，当前仅解析已捕获内容")
                return trailers, False
            if not CHUNK_START.fullmatch(line):
                _incomplete(meta, "分块长度或边界无效，后续内容保留在原始数据中")
                return trailers, False
            length = int(line.split(b";", 1)[0].strip(), 16)
            if length == 0:
                while True:
                    trailer = _line(source)
                    if trailer == b"\r\n":
                        return trailers, True
                    if not trailer:
                        _incomplete(meta, "分块尾部尚未捕获完整")
                        return trailers, False
                    total_trailer += len(trailer)
                    if total_trailer > HEADER_BUDGET:
                        raise ValueError("HTTP 分块尾部过长；请查看原始数据")
                    trailers.append(trailer.decode("latin-1").rstrip("\r\n"))
            got = _copy(source, output, length)
            if got != length:
                _incomplete(meta, "最后一个分块未捕获完整，当前仅解析已捕获内容")
                return trailers, False
            if source.read(2) != b"\r\n":
                _incomplete(meta, "分块数据后的边界缺失，后续内容保留在原始数据中")
                return trailers, False


def _inflate(source, destination, coding, meta):
    modes = [31] if coding in {"gzip", "x-gzip"} else [15, -15]
    for attempt, mode in enumerate(modes):
        try:
            decoder = zlib.decompressobj(mode)
            member_complete = False
            with source.open("rb") as incoming, destination.open("wb") as output:
                while piece := incoming.read(BLOCK):
                    if member_complete:
                        if coding not in {"gzip", "x-gzip"}:
                            raise zlib.error("extra bytes after compressed body")
                        decoder = zlib.decompressobj(mode)
                        member_complete = False
                    pending = piece
                    while pending:
                        decoded = decoder.decompress(pending, BLOCK)
                        output.write(decoded)
                        pending = decoder.unconsumed_tail
                        if decoder.eof:
                            pending = decoder.unused_data
                            member_complete = True
                            if pending:
                                if coding not in {"gzip", "x-gzip"}:
                                    raise zlib.error("extra bytes after compressed body")
                                decoder = zlib.decompressobj(mode)
                                member_complete = False
                if not decoder.eof:
                    _incomplete(meta, "压缩正文未完整捕获，解压结果可能只有已收到的部分")
            return True
        except zlib.error:
            if attempt+1 < len(modes):
                continue
            _incomplete(meta, "正文解压失败或校验不通过；请查看原始数据")
            return False
    return False


def _to_utf8(source, destination, content_type, meta):
    with source.open("rb") as stream:
        sample = stream.read(BLOCK)
    if sample[:1] in (b"\x14", b"\x15", b"\x16", b"\x17") and sample[1:2] == b"\x03":
        _warning(meta, "这是 TLS 加密数据，无法从原始 TCP 包直接还原明文；请使用已信任 CA 的 HTTPS 代理记录")
        return False
    declared = re.search(r"charset\s*=\s*[\"']?([\w.:-]+)", content_type, re.I)
    encoding = declared.group(1) if declared else "utf-8-sig"
    if "text/event-stream" in content_type.lower():
        encoding = "utf-8-sig"
    try:
        decoder = codecs.getincrementaldecoder(encoding)(errors="strict")
        with source.open("rb") as stream, destination.open("w", encoding="utf-8", newline="") as output:
            while piece := stream.read(BLOCK):
                text = decoder.decode(piece)
                if any(ord(char) < 32 and char not in "\t\r\n\f" for char in text):
                    _warning(meta, "内容包含二进制控制字节，无法自动作为文本解析；请查看原始数据或 HEX")
                    return False
                output.write(text)
            if not meta["complete"] and decoder.getstate()[0]:
                _warning(meta, "末尾字符仍在接收，当前显示已完整解码的文本；未完整字符的原始字节仍保留")
            output.write(decoder.decode(b"", final=meta["complete"]))
        return True
    except (UnicodeError, LookupError):
        _warning(meta, "内容不是有效的声明字符集文本，可能是二进制、加密数据或缺失的字符片段；请查看原始数据或 HEX")
        return False


def _unique_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON keys must retain their original representation")
        result[key] = value
    return result


def _safe_text(text):
    # JSON permits escaped unpaired surrogates. Keep their escapes rather than
    # failing the entire view or writing invalid UTF-8 into the generated file.
    return text.encode("utf-8", "backslashreplace").decode("utf-8")


def _json_dump(value, output):
    for piece in json.JSONEncoder(ensure_ascii=False, indent=2).iterencode(value):
        output.write(_safe_text(piece))


def _content_values(content):
    if isinstance(content, str):
        yield _safe_text(content)
    elif isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                yield _safe_text(item["text"])


def _sse(source, output, work, meta):
    """Buffer at most JSON_BUDGET per event; preserve larger events as full text."""
    detail = work / "sse-details.txt"
    event_path = work / "sse-event.txt"
    channels = {}
    count = 0
    done = False

    def dispatch(event, detail_out, partial=False):
        nonlocal count, done
        count += 1
        detail_out.write(f"\n--- 事件 {count}" + ("（未结束）" if partial else "") + " ---\n")
        size = event.stat().st_size
        if size > JSON_BUDGET:
            _append_file(event, detail_out)
            _warning(meta, "存在超过 4 MiB 的单个事件：已完整保留事件文本，未进行该事件的 JSON 提取")
            return
        lines = event.read_text("utf-8").split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        data = []
        for line in lines:
            field, separator, value = line.partition(":")
            if separator and value.startswith(" "):
                value = value[1:]
            if field == "data":
                data.append(value)
            else:
                detail_out.write(line+"\n")
        if not data:
            return
        payload = "\n".join(data)
        if payload == "[DONE]":
            done = True
            detail_out.write("[DONE]\n")
            return
        try:
            parsed = json.loads(payload, object_pairs_hook=_unique_json_pairs)
        except (ValueError, RecursionError):
            detail_out.write(payload+"\n")
            return
        _json_dump(parsed, detail_out)
        detail_out.write("\n")
        if partial or not isinstance(parsed, dict) or not isinstance(parsed.get("choices"), list):
            return
        for ordinal, choice in enumerate(parsed["choices"]):
            if not isinstance(choice, dict):
                continue
            index = choice.get("index", ordinal)
            if not isinstance(index, int) or index < 0 or index > 127:
                continue
            value = choice.get("delta", choice.get("message", {}))
            if not isinstance(value, dict):
                continue
            for field, label in (("content", "正文"), ("reasoning_content", "思考内容"), ("reasoning", "思考内容")):
                pieces = list(_content_values(value.get(field)))
                if not pieces:
                    continue
                key = (index, label)
                if key not in channels:
                    channels[key] = work / f"sse-choice-{index}-{len(channels)}.txt"
                with channels[key].open("a", encoding="utf-8", newline="") as channel:
                    channel.writelines(pieces)

    with source.open("r", encoding="utf-8", newline=None) as incoming, detail.open("w", encoding="utf-8", newline="") as detail_out:
        event = event_path.open("w", encoding="utf-8", newline="")
        line_start = True
        try:
            while piece := incoming.readline(BLOCK):
                empty_line = line_start and piece == "\n"
                line_start = piece.endswith("\n")
                if empty_line:
                    event.close()
                    if event_path.stat().st_size:
                        dispatch(event_path, detail_out)
                    event = event_path.open("w", encoding="utf-8", newline="")
                else:
                    event.write(piece)
            event.close()
            if event_path.stat().st_size:
                dispatch(event_path, detail_out, partial=True)
                _incomplete(meta, "最后一个 SSE 事件尚未以空行结束，已保留事件明细但未拼入正文")
        finally:
            event.close()
    output.write("SSE 流式事件\n")
    for (index, label), path in channels.items():
        output.write(f"\n{label}（选项 {index}）\n")
        _append_file(path, output)
        output.write("\n")
    if done:
        output.write("\n流结束标记：[DONE]\n")
    output.write("\n事件明细（保留全部字段）\n")
    _append_file(detail, output)
    meta["event_count"] = meta.get("event_count", 0)+count
    return "sse"


def _body(source, output, work, meta, content_type="", content_encoding=""):
    current = source
    codings = [part.strip().lower() for part in content_encoding.split(",") if part.strip()]
    for number, coding in enumerate(reversed(codings)):
        if coding == "identity":
            continue
        if coding not in {"gzip", "x-gzip", "deflate"}:
            _warning(meta, f"暂不支持 Content-Encoding: {coding}；完整数据可在原始视图下载")
            return False, "binary"
        inflated = work / f"inflated-{number}.bin"
        if not _inflate(current, inflated, coding, meta):
            return False, "binary"
        current = inflated
    text_path = work / "utf8.txt"
    if not _to_utf8(current, text_path, content_type, meta):
        return False, "binary"
    with text_path.open("r", encoding="utf-8") as stream:
        sample = stream.read(BLOCK)
    if "text/event-stream" in content_type.lower() or re.match(r"(?:data:|event:|id:|retry:|:)", sample.lstrip("\r\n")):
        with tempfile.TemporaryDirectory(prefix="sse-", dir=work) as folder:
            return True, _sse(text_path, output, Path(folder), meta)
    stripped = sample.lstrip()
    if "json" in content_type.lower() or stripped.startswith(("{", "[")):
        if text_path.stat().st_size <= JSON_BUDGET:
            try:
                value = json.loads(text_path.read_text("utf-8"), object_pairs_hook=_unique_json_pairs)
            except (ValueError, RecursionError):
                _warning(meta, "JSON 尚未完整或格式无效，已保留全部文本")
            else:
                _json_dump(value, output)
                output.write("\n")
                return True, "json"
        else:
            _warning(meta, "JSON 超过 4 MiB：已完整保留文本，跳过整体格式化以限制内存占用")
    _append_file(text_path, output)
    return True, "text"


def _headers(stream):
    first = _line(stream)
    if not HTTP_START.fullmatch(first):
        raise ValueError("后续字节无法识别为 HTTP/1 消息，已保留在原始数据中")
    raw = [first.decode("latin-1").rstrip("\r\n")]
    headers = {}
    size = len(first)
    while True:
        line = _line(stream)
        if line in {b"\r\n", b"\n"}:
            break
        if not line:
            raise ValueError("HTTP 头尚未捕获完整；请查看原始数据")
        size += len(line)
        if size > HEADER_BUDGET:
            raise ValueError("HTTP 头超过解析预算；完整字节保留在原始数据中")
        raw.append(line.decode("latin-1").rstrip("\r\n"))
        name, separator, value = line.partition(b":")
        if not separator or name.strip() != name or not name:
            raise ValueError("HTTP 头字段无效；请查看原始数据")
        key = name.decode("latin-1").lower()
        headers.setdefault(key, []).append(value.decode("latin-1").strip())
    return raw, headers


def _framing(headers, first):
    transfer = ",".join(headers.get("transfer-encoding", [])).lower().strip()
    lengths = [piece.strip() for value in headers.get("content-length", []) for piece in value.split(",")]
    if transfer and lengths:
        raise ValueError("同时出现 Transfer-Encoding 和 Content-Length，边界存在歧义；请查看原始数据")
    if transfer and transfer != "chunked":
        raise ValueError("无法可靠解析此 Transfer-Encoding；请查看原始数据")
    if lengths and (len(set(lengths)) != 1 or not re.fullmatch(r"[0-9]{1,20}", lengths[0])):
        raise ValueError("Content-Length 不合法或冲突；请查看原始数据")
    if first.startswith("HTTP/"):
        status = int(first.split(" ")[1])
        if 100 <= status < 200 or status in {204, 304}:
            return "length", 0
    if transfer:
        return "chunked", None
    if lengths:
        return "length", int(lengths[0])
    return ("close", None) if first.startswith("HTTP/") else ("length", 0)


def decode_stream_file(source, destination, *, content_type="", content_encoding="", transfer_encoding="", has_gaps=False, source_complete=True):
    """Write a complete readable representation atomically, returning small metadata.

    ``complete`` describes both capture/framing, not successful protocol recognition.
    On gaps the output explains why decoding is refused instead of joining them.
    Unrecognized bytes always remain available in the caller's raw download.
    """
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError("解码输出不能覆盖原始数据")
    destination.parent.mkdir(parents=True, exist_ok=True)
    meta = {"recognized": False, "kind": "unknown", "complete": bool(source_complete), "warnings": [], "decoder_version": DECODER_VERSION}
    if not source_complete:
        _warning(meta, "原始捕获未确认完整，解析视图仅包含当前已捕获的数据")
    with tempfile.TemporaryDirectory(prefix=".decode-", dir=destination.parent) as folder:
        work = Path(folder)
        result = work / "readable.txt"
        with result.open("w", encoding="utf-8", newline="") as output:
            if has_gaps:
                _incomplete(meta, "TCP 会话存在缺失、截断、冲突或序列异常，不能跨缺口拼接解析；请查看原始数据及会话完整性信息")
            else:
                try:
                    with source.open("rb") as incoming:
                        sample = incoming.read(BLOCK)
                        incoming.seek(0)
                        if not (content_type or content_encoding or transfer_encoding) and HTTP_START.match(sample):
                            count = 0
                            kinds = set()
                            while incoming.peek(1):
                                raw_headers, headers = _headers(incoming)
                                framing, length = _framing(headers, raw_headers[0])
                                if raw_headers[0].startswith("HTTP/"):
                                    following = incoming.peek(BLOCK)
                                    if framing == "length" and length and following.startswith(b"HTTP/") and HTTP_START.match(following):
                                        raise ValueError("响应正文位置出现另一条 HTTP 响应，可能是 HEAD 响应；缺少配对请求方法，不能可靠判断边界，请查看原始数据")
                                    if framing == "close":
                                        _incomplete(meta, "此响应没有正文长度，且缺少配对请求方法；无法区分关闭定界正文与 CONNECT 隧道，以下仅展示观察到的文本")
                                body = work / "body.bin"
                                trailers = []
                                frame_complete = True
                                if framing == "chunked":
                                    trailers, frame_complete = _chunked(incoming, body, meta)
                                else:
                                    with body.open("wb") as sink:
                                        got = _copy(incoming, sink, length)
                                    if length is not None and got != length:
                                        _incomplete(meta, "HTTP 正文未达到 Content-Length，当前仅解析已捕获内容")
                                count += 1
                                output.write(f"HTTP 消息 {count}\n"+"\n".join(raw_headers)+"\n\n")
                                recognized, kind = _body(body, output, work, meta, ",".join(headers.get("content-type", [])), ",".join(headers.get("content-encoding", [])))
                                if not recognized:
                                    output.write("此消息正文无法自动解析，请查看原始数据。\n")
                                kinds.add(kind)
                                if trailers:
                                    output.write("\n分块尾部字段\n"+"\n".join(trailers)+"\n")
                                output.write("\n\n")
                                meta["recognized"] = True
                                if framing == "close" or not frame_complete:
                                    break
                            meta["message_count"] = count
                            meta["kind"] = "http-sse" if "sse" in kinds else "http"
                        else:
                            framed = source
                            inferred = False
                            if transfer_encoding.strip().lower() == "chunked":
                                framed = work / "body.bin"
                                _chunked(incoming, framed, meta)
                                if incoming.read(1):
                                    _incomplete(meta, "分块正文结束后仍有额外字节，已保留在原始数据中")
                            elif transfer_encoding.strip() and transfer_encoding.strip().lower() != "identity":
                                raise ValueError("不支持此 Transfer-Encoding；请查看原始数据")
                            elif not (content_type or content_encoding) and CHUNK_START.match(sample):
                                candidate = work / "candidate.bin"
                                trial = {"complete": meta["complete"], "warnings": []}
                                _chunked(incoming, candidate, trial)
                                with candidate.open("rb") as decoded:
                                    payload_sample = decoded.read(BLOCK).removeprefix(b"\xef\xbb\xbf").lstrip()
                                if payload_sample.startswith((b"data:", b"event:", b":", b"{", b"[")):
                                    framed = candidate
                                    meta["complete"] = trial["complete"]
                                    for warning in trial["warnings"]:
                                        _warning(meta, warning)
                                    if incoming.read(1):
                                        _incomplete(meta, "分块正文结束后仍有额外字节，已保留在原始数据中")
                                    inferred = True
                                    _incomplete(meta, "未捕获 HTTP 头，分块格式根据内容推断；不能确认原始消息完整")
                            meta["recognized"], meta["kind"] = _body(framed, output, work, meta, content_type, content_encoding)
                            if inferred:
                                meta["inferred"] = True
                except (ValueError, OverflowError) as exc:
                    _incomplete(meta, str(exc))
            if not meta["recognized"]:
                output.write("无法自动解析为可读应用内容。原始字节与 HEX 视图仍完整保留。\n")
            if meta["warnings"]:
                output.write("\n解析说明\n"+"\n".join("- "+warning for warning in meta["warnings"])+"\n")
        try:
            result.chmod(0o600)
        except OSError:
            pass
        os.replace(result, destination)
    meta["size"] = destination.stat().st_size
    return meta
