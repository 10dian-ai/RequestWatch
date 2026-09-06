"""Bounded, file-backed prompt extraction. Original body files are never changed."""
from __future__ import annotations

import codecs
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

from .stream_decode import (BLOCK, JSON_BUDGET, _chunked, _inflate,
                            _safe_text, _to_utf8, _unique_json_pairs)

PROMPT_VERSION = 1
MAX_CHANNELS = 512


class Fallback(ValueError):
    pass


def _dump(value):
    return _safe_text(json.dumps(value, ensure_ascii=False, indent=2))


def _content(value):
    if isinstance(value, str):
        return _safe_text(value)
    # Multimodal images, audio, tool results and unknown content blocks retain
    # their complete fields instead of disappearing behind a text-only filter.
    if value is None:
        return ""
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, dict) and set(item) <= {"type", "text"} and isinstance(item.get("text"), str):
                parts.append(_safe_text(item["text"]))
            else:
                parts.append(_content(item) if isinstance(item, str) else _dump(item))
        return "\n".join(parts)
    return _dump(value)


def _section(output, title, value):
    output.write("\n" + title + "\n" + _content(value) + "\n")


def _messages(output, messages, meta):
    if not isinstance(messages, list):
        raise Fallback("messages/input 的结构无法可靠识别")
    for i, message in enumerate(messages):
        if not isinstance(message, dict):
            _section(output, f"消息 {i + 1}", message)
        else:
            role = message.get("role", message.get("type", "message"))
            _section(output, f"消息 {i + 1} · {role}", message.get("content", message))
            for key in ("name", "tool_call_id", "tool_calls", "function_call", "reasoning_content", "reasoning", "refusal"):
                if key in message:
                    _section(output, key, message[key])
        meta["message_count"] += 1


def _request(value, output, meta):
    if not isinstance(value, dict):
        raise Fallback("不是已支持的模型请求对象")
    if "contents" in value:
        meta["provider"] = "gemini"
        if "systemInstruction" in value:
            _section(output, "systemInstruction", value["systemInstruction"])
        _messages(output, value["contents"], meta)
    elif "input" in value or "instructions" in value:
        meta["provider"] = "responses"
        if "instructions" in value:
            _section(output, "instructions", value["instructions"])
        if isinstance(value.get("input"), list):
            _messages(output, value["input"], meta)
        elif "input" in value:
            _section(output, "input", value["input"])
            meta["message_count"] += 1
    elif "messages" in value:
        messages = value["messages"]
        if not isinstance(messages, list):
            raise Fallback("messages 的结构无法可靠识别")
        anthropic = "system" in value or "anthropic_version" in value or any(
            isinstance(x, dict) and isinstance(x.get("content"), list) and any(
                isinstance(y, dict) and y.get("type") in {"tool_use", "tool_result", "thinking"} for y in x["content"]
            ) for x in messages)
        meta["provider"] = "anthropic" if anthropic else "openai"
        if "system" in value:
            _section(output, "system", value["system"])
        _messages(output, value["messages"], meta)
    elif isinstance(value.get("prompt"), (str, list)):
        meta["provider"] = "openai"
        _section(output, "prompt", value["prompt"])
        meta["message_count"] += 1
    else:
        raise Fallback("未识别为 Chat Completions、Responses、Anthropic 或 Gemini 请求")
    for key in ("tools", "functions", "tool_choice", "function_call"):
        if key in value:
            _section(output, key, value[key])


def _response(value, output, meta):
    if not isinstance(value, dict):
        raise Fallback("不是已支持的模型响应对象")
    if isinstance(value.get("choices"), list):
        meta["provider"] = "openai"
        for i, choice in enumerate(value["choices"]):
            if not isinstance(choice, dict):
                raise Fallback("无法识别 choices 结构")
            message = choice.get("message", choice.get("delta"))
            if isinstance(message, dict):
                _messages(output, [message], meta)
            elif "text" in choice:
                _section(output, f"输出 {choice.get('index', i)}", choice["text"])
                meta["message_count"] += 1
            else:
                _section(output, f"选项 {i}", choice)
    elif isinstance(value.get("output"), list):
        meta["provider"] = "responses"
        _messages(output, value["output"], meta)
    elif isinstance(value.get("candidates"), list):
        meta["provider"] = "gemini"
        for i, candidate in enumerate(value["candidates"]):
            _section(output, f"输出 {i}", candidate.get("content", candidate) if isinstance(candidate, dict) else candidate)
            meta["message_count"] += 1
    elif value.get("type") == "message" and isinstance(value.get("content"), (list, str)):
        meta["provider"] = "anthropic"
        _messages(output, [value], meta)
    else:
        raise Fallback("未识别为模型响应；可能是错误信息或其他接口内容")


class Channels:
    def __init__(self, root):
        self.root = root
        self.paths = {}

    def add(self, key, value, *, final=False):
        if value is None or value == "":
            return
        if key in self.paths and final:
            return
        if key not in self.paths:
            if len(self.paths) >= MAX_CHANNELS:
                raise Fallback("流式输出分支过多，改为完整原文以限制内存")
            self.paths[key] = self.root / (str(len(self.paths)) + ".txt")
        with self.paths[key].open("a", encoding="utf-8", newline="") as sink:
            sink.write(_content(value))

    def write(self, output):
        for key, path in self.paths.items():
            output.write("\n" + " · ".join(map(str, key)) + "\n")
            with path.open("r", encoding="utf-8", newline="") as incoming:
                shutil.copyfileobj(incoming, output, BLOCK)
            output.write("\n")


def _openai_event(value, channels):
    for ordinal, choice in enumerate(value.get("choices", [])):
        if not isinstance(choice, dict):
            raise Fallback("无法识别流式 choices 结构")
        index = choice.get("index", ordinal)
        delta = choice.get("delta", choice.get("message", {}))
        if not isinstance(delta, dict):
            raise Fallback("无法识别流式 delta 结构")
        if "text" in choice:
            channels.add((index, "正文"), choice["text"])
        known = {"role", "content", "reasoning_content", "reasoning", "refusal", "tool_calls", "function_call"}
        for field, label in (("content", "正文"), ("reasoning_content", "思考内容"), ("reasoning", "思考内容"), ("refusal", "拒绝信息")):
            if field in delta:
                channels.add((index, label), delta[field])
        calls = delta.get("tool_calls", [])
        if "function_call" in delta:
            calls = [dict(index=0, function=delta["function_call"])]
        if not isinstance(calls, list):
            raise Fallback("无法识别 tool_calls 结构")
        for order, call in enumerate(calls):
            if not isinstance(call, dict) or not isinstance(call.get("function", {}), dict):
                raise Fallback("无法识别工具参数")
            key = (index, "工具", call.get("index", order))
            for field in ("id", "type"):
                channels.add((*key, field), call.get(field))
            for field, content in call.get("function", {}).items():
                channels.add((*key, field), content)
        extra = {k: v for k, v in delta.items() if k not in known}
        if extra:
            channels.add((index, "其他内容"), _dump(extra) + "\n")


def _responses_event(value, channels):
    kind = value.get("type", "")
    index = value.get("output_index", value.get("item_id", 0))
    content_index = value.get("content_index", value.get("summary_index", 0))
    fields = {"output_text": "正文", "reasoning_text": "思考内容", "reasoning_summary_text": "思考摘要", "refusal": "拒绝信息", "function_call_arguments": "工具参数"}
    for field, label in fields.items():
        if kind == f"response.{field}.delta":
            channels.add((index, content_index, label), value.get("delta", ""))
            return
        if kind == f"response.{field}.done":
            channels.add((index, content_index, label), value.get("text", value.get("arguments", value.get("refusal", ""))), final=True)
            return
    if kind in {"response.output_item.added", "response.output_item.done"}:
        item = value.get("item", {})
        if not isinstance(item, dict):
            raise Fallback("无法识别 Responses 输出项")
        if item.get("type") == "function_call":
            for field in ("name", "call_id"):
                channels.add((index, "工具", field), item.get(field), final=True)
            channels.add((index, 0, "工具参数"), item.get("arguments"), final=True)
        elif kind.endswith(".done") and item.get("type") == "message":
            for ordinal, part in enumerate(item.get("content", [])):
                if isinstance(part, dict) and part.get("type") in {"output_text", "refusal"}:
                    field, label = ("text", "正文") if part["type"] == "output_text" else ("refusal", "拒绝信息")
                    channels.add((index, ordinal, label), part.get(field), final=True)
                    extras = {k: v for k, v in part.items() if k not in {"type", field}}
                    if extras:
                        channels.add((index, ordinal, "附加内容"), extras, final=True)
                else:
                    channels.add((index, ordinal, "内容项"), part, final=True)
        elif kind.endswith(".done") and item.get("type") == "reasoning":
            for ordinal, part in enumerate(item.get("summary", [])):
                if isinstance(part, dict) and part.get("type") == "summary_text":
                    channels.add((index, ordinal, "思考摘要"), part.get("text"), final=True)
                else:
                    channels.add((index, ordinal, "思考内容项"), part, final=True)
        elif kind.endswith(".done"):
            channels.add((index, "输出项"), item)
        return
    if kind in {"response.completed", "response.incomplete"}:
        if not channels.paths:
            raise Fallback("流中仅有完整响应对象，改为完整原文，避免遗漏输出项")
        return
    if kind in {"response.created", "response.in_progress", "response.queued", "response.content_part.added", "response.content_part.done", "response.reasoning_summary_part.added", "response.reasoning_summary_part.done"}:
        return
    raise Fallback("存在尚未支持的 Responses 事件，已保留全部原文")


def _anthropic_event(value, channels):
    kind, index = value.get("type", ""), value.get("index", 0)
    if kind == "content_block_start":
        block = value.get("content_block", {})
        for field, label in (("text", "正文"), ("thinking", "思考内容")):
            channels.add((index, label), block.get(field))
        if block.get("type") == "tool_use":
            for field in ("name", "id"):
                channels.add((index, "工具", field), block.get(field))
            if block.get("input"):
                channels.add((index, "工具参数"), block["input"])
        elif block.get("type") not in {"text", "thinking"}:
            channels.add((index, "内容块"), block)
    elif kind == "content_block_delta":
        delta = value.get("delta", {})
        mapping = {"text_delta": ("text", "正文"), "thinking_delta": ("thinking", "思考内容"), "input_json_delta": ("partial_json", "工具参数"), "signature_delta": ("signature", "思考签名")}
        if delta.get("type") not in mapping:
            raise Fallback("存在尚未支持的 Anthropic 内容增量")
        field, label = mapping[delta["type"]]
        channels.add((index, label), delta.get(field))
    elif kind not in {"message_start", "content_block_stop", "message_delta", "message_stop", "ping"}:
        raise Fallback("存在尚未支持的 Anthropic 事件")


def _gemini_event(value, channels):
    for ordinal, candidate in enumerate(value.get("candidates", [])):
        if not isinstance(candidate, dict) or not isinstance(candidate.get("content", {}), dict):
            raise Fallback("无法识别 Gemini 流式候选内容")
        index = candidate.get("index", ordinal)
        for part in candidate.get("content", {}).get("parts", []):
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                channels.add((index, "思考内容" if part.get("thought") else "正文"), part["text"])
                extra = {k: v for k, v in part.items() if k not in {"text", "thought"}}
                if extra:
                    channels.add((index, "附加内容"), _dump(extra) + "\n")
            else:
                channels.add((index, "工具或多模态内容"), _dump(part) + "\n")


def _sse(source, output, work, meta):
    channels = Channels(work)
    buffer, size, provider = [], 0, "unknown"

    def dispatch():
        nonlocal buffer, size, provider
        lines, buffer, size = "".join(buffer).split("\n"), [], 0
        data = []
        for line in lines:
            name, sep, value = line.partition(":")
            if name == "data":
                data.append(value.removeprefix(" "))
        if not data:
            return
        meta["event_count"] += 1
        payload = "\n".join(data)
        if payload == "[DONE]":
            return
        try:
            value = json.loads(payload, object_pairs_hook=_unique_json_pairs)
        except (ValueError, RecursionError) as exc:
            raise Fallback("存在未完成或非 JSON 的 SSE 数据，已保留全部原文") from exc
        if not isinstance(value, dict):
            raise Fallback("SSE 数据不是已支持的模型事件")
        event_provider = ("openai" if isinstance(value.get("choices"), list) else
                          "gemini" if isinstance(value.get("candidates"), list) else
                          "responses" if str(value.get("type", "")).startswith("response.") else
                          "anthropic" if value.get("type") in {"message_start", "message_delta", "message_stop", "content_block_start", "content_block_delta", "content_block_stop", "ping"} else "unknown")
        if event_provider == "unknown" or (provider != "unknown" and provider != event_provider):
            raise Fallback("SSE 含未知或混合协议事件，已保留全部原文")
        provider = event_provider
        {"openai": _openai_event, "gemini": _gemini_event, "responses": _responses_event, "anthropic": _anthropic_event}[provider](value, channels)

    # A bound applies to each read and accumulated event, including physical
    # lines split across blocks. Only a genuinely empty physical line dispatches.
    with source.open("r", encoding="utf-8", newline=None) as incoming:
        line_start = True
        while piece := incoming.readline(BLOCK):
            empty_line = line_start and piece == "\n"
            line_start = piece.endswith("\n")
            if empty_line:
                dispatch()
            else:
                size += len(piece.encode("utf-8"))
                if size > JSON_BUDGET:
                    raise Fallback("单个 SSE 事件超过 4 MiB，跳过提取并显示完整原文")
                buffer.append(piece)
        if buffer:
            meta["complete"] = False
            raise Fallback("最后一个 SSE 事件尚未以空行结束，已保留完整已捕获原文")
    if provider == "unknown" or not channels.paths:
        raise Fallback("当前没有可提取的模型正文，保留完整事件原文")
    meta["provider"] = provider
    meta["message_count"] = len({key[0] for key in channels.paths})
    channels.write(output)


def _raw_copy(source, output):
    # Preserve all bytes in a textual representation, including malformed UTF-8.
    decoder = codecs.getincrementaldecoder("utf-8")(errors="backslashreplace")
    with source.open("rb") as incoming:
        while piece := incoming.read(BLOCK):
            output.write(decoder.decode(piece))
        output.write(decoder.decode(b"", final=True))


def decode_prompt_file(source, destination, *, side="response", content_type="", content_encoding="", transfer_encoding="", has_gaps=False, source_complete=True):
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError("Prompt 输出不能覆盖原始数据")
    if side not in {"request", "response"}:
        raise ValueError("无效的 Prompt 方向")
    destination.parent.mkdir(parents=True, exist_ok=True)
    meta = {"presentation": "prompt", "kind": "prompt-raw", "provider": "unknown", "recognized": False,
            "complete": bool(source_complete) and not has_gaps, "warnings": [], "message_count": 0,
            "event_count": 0, "fallback": False, "prompt_version": PROMPT_VERSION}
    if not meta["complete"]:
        meta["warnings"].append("捕获尚未确认完整；仅显示当前已捕获内容")
    with tempfile.TemporaryDirectory(prefix=".prompt-", dir=destination.parent) as folder:
        work = Path(folder)
        current = source
        raw_text = source
        result = work / "view.txt"
        with result.open("w", encoding="utf-8", newline="") as output:
            try:
                if has_gaps:
                    raise Fallback("内容存在缺口，不能可靠提取 Prompt，保留原文")
                if transfer_encoding.lower().strip() == "chunked":
                    current = work / "unchunked.bin"
                    with source.open("rb") as incoming:
                        _chunked(incoming, current, meta)
                        if incoming.read(1):
                            raise Fallback("分块后仍有额外字节，保留完整原文")
                elif transfer_encoding.lower().strip() not in {"", "identity"}:
                    raise Fallback("不支持此 Transfer-Encoding，保留完整原文")
                for i, coding in enumerate(reversed([x.strip().lower() for x in content_encoding.split(",") if x.strip()])):
                    if coding == "identity":
                        continue
                    if coding not in {"gzip", "x-gzip", "deflate"}:
                        raise Fallback("此压缩格式未解码，请查看原始正文下载")
                    inflated = work / f"inflate-{i}.bin"
                    if not _inflate(current, inflated, coding, meta):
                        raise Fallback("正文未能完整解压，请查看原始正文下载")
                    current = inflated
                utf8 = work / "utf8.txt"
                if not _to_utf8(current, utf8, content_type, meta):
                    raise Fallback("内容不是有效文本；保留原始字节的文本转义表示，原始下载不变")
                raw_text = utf8
                with utf8.open("r", encoding="utf-8") as incoming:
                    sample = incoming.read(BLOCK)
                if "text/event-stream" in content_type.lower() or re.match(r"(?:data:|event:|id:|retry:|:)", sample.lstrip("\r\n")):
                    _sse(utf8, output, work, meta)
                    meta["kind"] = "prompt-sse"
                else:
                    if utf8.stat().st_size > JSON_BUDGET:
                        raise Fallback("JSON 超过 4 MiB，跳过整体提取并显示完整原文")
                    try:
                        value = json.loads(utf8.read_text("utf-8"), object_pairs_hook=_unique_json_pairs)
                    except (ValueError, RecursionError) as exc:
                        raise Fallback("JSON 未完成或格式未知，已保留完整原文") from exc
                    (_request if side == "request" else _response)(value, output, meta)
                    if not output.tell():
                        raise Fallback("没有可提取的消息正文，保留完整原文")
                    meta["kind"] = "prompt-json"
                meta["recognized"] = True
            except (Fallback, TypeError, AttributeError, RecursionError) as exc:
                meta["fallback"] = True
                meta["kind"] = "prompt-raw"
                meta["warnings"].append(str(exc) if isinstance(exc, Fallback) else "协议结构无法可靠提取，已保留完整原文")
                output.seek(0)
                output.truncate()
                _raw_copy(raw_text, output)
        result.chmod(0o600)
        os.replace(result, destination)
    meta["size"] = destination.stat().st_size
    return meta
