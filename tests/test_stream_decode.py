import gzip
import json
from pathlib import Path
import zlib

import pytest

from requestwatch.stream_decode import DECODER_VERSION, JSON_BUDGET, decode_stream_file


def decode(tmp_path, data, **options):
    source, target = tmp_path / "source.bin", tmp_path / "readable.txt"
    source.write_bytes(data)
    meta = decode_stream_file(source, target, **options)
    return meta, target.read_text("utf-8")


def chunks(data, cuts=(1, 2, 17, 103)):
    encoded = bytearray()
    offset = 0
    for length in (*cuts, len(data)):
        piece = data[offset:offset+length]
        if not piece:
            break
        encoded.extend(f"{len(piece):x};extension=value\r\n".encode()+piece+b"\r\n")
        offset += len(piece)
    encoded.extend(b"0\r\nX-Checksum: preserved\r\n\r\n")
    return bytes(encoded)


def response(body, *, extra=b"", chunked=False):
    framing = b"Transfer-Encoding: chunked\r\n" if chunked else f"Content-Length: {len(body)}\r\n".encode()
    return b"HTTP/1.1 200 OK\r\n"+framing+extra+b"\r\n"+(chunks(body) if chunked else body)


def event(text, *, reasoning=None, extra=None, index=0):
    delta = {"content": text}
    if reasoning is not None:
        delta["reasoning_content"] = reasoning
    value = {"id": "chatcmpl-observed", "choices": [{"index": index, "delta": delta}], "usage": {"tokens": 7}}
    if extra:
        value.update(extra)
    return ("data: "+json.dumps(value, ensure_ascii=False)+"\n\n").encode()


def test_http_chunked_sse_utf8_boundaries_and_every_field(tmp_path):
    body = event("第一行\n", reasoning="独立思考")+event("第二行", extra={"other": "保留字段"})+b"data: [DONE]\n\n"
    meta, text = decode(tmp_path, response(body, extra=b"Content-Type: text/event-stream\r\n", chunked=True))
    assert meta["recognized"] and meta["complete"] and meta["kind"] == "http-sse"
    assert meta["decoder_version"] == DECODER_VERSION and meta["event_count"] == 3
    assert "第一行\n第二行" in text
    assert "思考内容（选项 0）\n独立思考" in text
    assert '"usage"' in text and '"other": "保留字段"' in text
    assert "X-Checksum: preserved" in text
    assert "extension=value" not in text


def test_midstream_chunked_inference_marks_missing_headers(tmp_path):
    meta, text = decode(tmp_path, chunks(event("截图中的正文\n下一行")))
    assert meta["recognized"] and meta["inferred"] and not meta["complete"]
    assert "未捕获 HTTP 头" in " ".join(meta["warnings"])
    assert "截图中的正文\n下一行" in text


def test_missing_chunks_never_join_to_fabricated_text(tmp_path):
    meta, text = decode(tmp_path, event("伪造连接内容"), has_gaps=True)
    assert not meta["recognized"] and not meta["complete"]
    assert "伪造连接内容" not in text and "不能跨缺口" in text


@pytest.mark.parametrize("coding,encoder", [("gzip", gzip.compress), ("deflate", zlib.compress), ("deflate", lambda raw: zlib.compress(raw)[2:-4])])
def test_compressed_sse_full_body(tmp_path, coding, encoder):
    body = event("解压后的中文末尾")
    compressed = encoder(body)
    meta, text = decode(tmp_path, response(compressed, extra=f"Content-Encoding: {coding}\r\nContent-Type: text/event-stream\r\n".encode(), chunked=True))
    assert meta["recognized"] and meta["complete"]
    assert "解压后的中文末尾" in text


def test_concatenated_gzip_members(tmp_path):
    data = gzip.compress(event("第一段"))+gzip.compress(event("第二段"))
    meta, text = decode(tmp_path, data, content_type="text/event-stream", content_encoding="gzip")
    assert meta["complete"] and "第一段第二段" in text


def test_stacked_content_encoding(tmp_path):
    raw = json.dumps({"field": "叠加压缩"}, ensure_ascii=False).encode()
    meta, text = decode(tmp_path, zlib.compress(gzip.compress(raw)), content_type="application/json", content_encoding="gzip, deflate")
    assert meta["complete"] and '"field": "叠加压缩"' in text


def test_gzip_checksum_corruption_and_partial_input(tmp_path):
    compressed = bytearray(gzip.compress(event("被破坏的正文")))
    compressed[-5] ^= 0xff
    meta, text = decode(tmp_path, bytes(compressed), content_encoding="gzip")
    assert not meta["recognized"] and not meta["complete"]
    assert "校验不通过" in text
    meta, text = decode(tmp_path, gzip.compress(event("部分内容"))[:-8], content_encoding="gzip")
    assert not meta["complete"] and "压缩正文未完整" in text


def test_multiple_keepalive_messages_do_not_mix_sse_choices(tmp_path):
    first = response(event("消息一"), extra=b"Content-Type: text/event-stream\r\n")
    second = response(event("消息二"), extra=b"Content-Type: text/event-stream\r\n", chunked=True)
    meta, text = decode(tmp_path, first+second)
    assert meta["message_count"] == 2 and meta["complete"]
    left, right = text.split("HTTP 消息 2")
    assert "消息一" in left and "消息二" not in left
    assert "消息二" in right and "消息一" not in right


def test_requests_without_body_followed_by_json_upload(tmp_path):
    body = '{"message":"完整请求"}'.encode()
    raw = b"GET /one HTTP/1.1\r\nHost: example.test\r\n\r\n"
    raw += b"POST /two HTTP/1.1\r\nContent-Type: application/json\r\n"+f"Content-Length: {len(body)}\r\n\r\n".encode()+body
    meta, text = decode(tmp_path, raw)
    assert meta["message_count"] == 2 and meta["complete"]
    assert '"message": "完整请求"' in text and "GET /one HTTP/1.1" in text


def test_interim_and_no_body_status(tmp_path):
    raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"+response(b"tail")
    meta, text = decode(tmp_path, raw)
    assert meta["message_count"] == 3 and "tail" in text


@pytest.mark.parametrize("data", [b"\x16\x03\x03\x00\x04secret", b"text\x00binary", b"\xff\xfe\xfd"])
def test_binary_is_not_mislabeled_plaintext(tmp_path, data):
    meta, text = decode(tmp_path, data)
    assert not meta["recognized"] and meta["kind"] == "binary"
    assert "HEX" in text


def test_large_body_tail_is_complete_not_preview(tmp_path):
    data = ("前缀" * 400000+"最后的标记TAIL").encode()
    meta, text = decode(tmp_path, response(data, extra=b"Content-Type: text/plain; charset=utf-8\r\n"))
    assert len(data) > 1024*1024
    assert meta["recognized"] and meta["complete"]
    assert "前缀"*400000+"最后的标记TAIL" in text


def test_many_sse_events_over_one_mib_have_full_concatenated_tail(tmp_path):
    raw = b"".join(event("片段"*1500) for _ in range(160))+event("最终标记TAIL")
    assert len(raw) > 1024*1024
    meta, text = decode(tmp_path, response(raw, extra=b"Content-Type: text/event-stream\r\n", chunked=True))
    assert meta["complete"] and meta["event_count"] == 161
    assert "片段"*(1500*160)+"最终标记TAIL" in text


def test_large_single_event_keeps_all_text_with_explicit_parse_limit(tmp_path):
    raw = b"data: {\"value\":\""+b"z"*(JSON_BUDGET+7)+b"TAIL\"}\n\n"
    meta, text = decode(tmp_path, raw, content_type="text/event-stream")
    assert meta["recognized"] and meta["complete"] and "TAIL" in text
    assert text.count("z") == JSON_BUDGET+7
    assert "超过 4 MiB" in " ".join(meta["warnings"])


def test_generic_sse_multiline_data_comments_and_unknown_fields(tmp_path):
    raw = b': keepalive\r\nevent: custom\r\nid: abc\r\nx-custom: retained\r\ndata: {"x":\r\ndata: 1}\r\n\r\ndata: hello\r\ndata: world\r\n\r\n'
    meta, text = decode(tmp_path, raw)
    assert meta["event_count"] == 2 and meta["complete"]
    assert '"x": 1' in text and "hello\nworld" in text
    assert ": keepalive" in text and "x-custom: retained" in text and "id: abc" in text


def test_sse_bom_cr_newlines_unicode_separator_and_incomplete_event(tmp_path):
    raw = b"\xef\xbb\xbf"+event("前\u2028后").replace(b"\n", b"\r")
    meta, text = decode(tmp_path, raw, content_type="text/event-stream")
    assert meta["complete"] and "前\u2028后" in text
    meta, text = decode(tmp_path, event("不可分派")[:-1], content_type="text/event-stream")
    assert not meta["complete"] and "正文（选项" not in text
    assert "不可分派" in text and "未结束" in text


def test_multiple_choices_and_message_shape_are_separate(tmp_path):
    raw = ('data: '+json.dumps({"choices": [{"index": 0, "delta": {"content": "零"}}, {"index": 1, "message": {"content": [{"type": "text", "text": "一"}]}}]}, ensure_ascii=False)+'\n\n').encode()
    meta, text = decode(tmp_path, raw)
    assert meta["complete"] and "正文（选项 0）\n零" in text and "正文（选项 1）\n一" in text


def test_declared_charset_and_json_prettyprint(tmp_path):
    meta, text = decode(tmp_path, '{"word":"中文"}'.encode("gb18030"), content_type="application/json; charset=gb18030")
    assert meta["complete"] and '\n  "word": "中文"\n' in text


def test_content_length_missing_bytes_and_invalid_chunk_boundaries(tmp_path):
    meta, text = decode(tmp_path, b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
    assert meta["recognized"] and not meta["complete"] and "short" in text
    meta, text = decode(tmp_path, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nshortXXtail")
    assert not meta["complete"] and "分块数据后的边界缺失" in text
    meta, text = decode(tmp_path, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n20\r\nshort")
    assert not meta["complete"] and "short" in text


@pytest.mark.parametrize("headers", [b"Content-Length: 1\r\nContent-Length: 2\r\n", b"Content-Length: 1\r\nTransfer-Encoding: chunked\r\n", b"Content-Length: -1\r\n", b"Transfer-Encoding: gzip, chunked\r\n"])
def test_ambiguous_http_framing_is_rejected(tmp_path, headers):
    meta, text = decode(tmp_path, b"HTTP/1.1 200 OK\r\n"+headers+b"\r\nmessage")
    assert not meta["recognized"] and not meta["complete"] and meta["warnings"]


def test_open_source_close_delimited_message_warns(tmp_path):
    meta, text = decode(tmp_path, b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\npartial", source_complete=False)
    assert meta["recognized"] and not meta["complete"] and "partial" in text


def test_raw_hexadecimal_line_alone_is_not_guessed_chunked(tmp_path):
    meta, text = decode(tmp_path, b"170\r\nnormal application text\r\n")
    assert meta["recognized"] and meta["kind"] == "text" and not meta.get("inferred")
    assert "170\nnormal application text" in text


def test_never_overwrites_raw_source(tmp_path):
    path = tmp_path / "source.bin"
    path.write_bytes(b"original")
    with pytest.raises(ValueError):
        decode_stream_file(path, path)
    assert path.read_bytes() == b"original"



def test_json_unpaired_surrogate_preserved_as_escape(tmp_path):
    meta, text = decode(tmp_path, b'{"text":"\\ud800"}', content_type="application/json")
    assert meta["recognized"] and meta["complete"] and "\\ud800" in text
    raw = b'data: {"choices":[{"delta":{"content":"\\ud800"}}]}\n\n'
    meta, text = decode(tmp_path, raw)
    assert meta["complete"] and "正文（选项 0）\n\\ud800" in text


def test_sse_leading_blank_lines_and_bom_in_chunked_payload(tmp_path):
    meta, text = decode(tmp_path, b"\n\n"+event("空行之后"))
    assert meta["kind"] == "sse" and "正文（选项 0）\n空行之后" in text
    meta, text = decode(tmp_path, chunks(b"\xef\xbb\xbf"+event("BOM 之后")))
    assert meta["inferred"] and "BOM 之后" in text


def test_large_plain_json_not_truncated_when_prettyprint_budget_exceeded(tmp_path):
    raw = b'{"large":"'+b"x"*(JSON_BUDGET+32)+b'TAIL"}'
    meta, text = decode(tmp_path, raw, content_type="application/json")
    assert meta["recognized"] and meta["complete"]
    assert text.startswith(raw.decode()) and "TAIL" in text


def test_chunked_body_trailing_bytes_are_reported(tmp_path):
    meta, text = decode(tmp_path, chunks(b"body")+b"NOT LOST SILENTLY", transfer_encoding="chunked")
    assert meta["recognized"] and not meta["complete"]
    assert "额外字节" in text



def test_head_response_with_next_response_does_not_consume_as_body(tmp_path):
    following = response(b"tail")
    for length in (5, len(following)):
        raw = f"HTTP/1.1 200 OK\r\nContent-Length: {length}\r\n\r\n".encode()+following
        meta, text = decode(tmp_path, raw)
        assert not meta["complete"] and "HEAD" in text
        assert "不能可靠判断边界" in text


def test_gzip_expansion_keeps_parser_memory_bounded_and_tail(tmp_path):
    import tracemalloc

    source, target = tmp_path / "source.gz", tmp_path / "decoded.txt"
    with gzip.open(source, "wb") as output:
        for _ in range(160):
            output.write(b"large plaintext chunk "*4096)
        output.write(b"END_OF_COMPLETE_BODY")
    tracemalloc.start()
    try:
        meta = decode_stream_file(source, target, content_type="text/plain", content_encoding="gzip")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert meta["complete"] and target.stat().st_size > 10*1024*1024
    assert peak < 4*1024*1024
    with target.open("rb") as stream:
        stream.seek(-20, 2)
        assert stream.read() == b"END_OF_COMPLETE_BODY"
