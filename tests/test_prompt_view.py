import gzip
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from requestwatch.prompt_view import decode_prompt_file, JSON_BUDGET
from requestwatch.readable_cache import ReadableCache
from requestwatch.store import Store


def decode(tmp_path, value, *, side='response', raw=False, **options):
    source = tmp_path / 'source.bin'
    source.write_bytes(value if raw else json.dumps(value, ensure_ascii=False).encode())
    target = tmp_path / 'prompt.txt'
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    meta = decode_prompt_file(source, target, side=side, **options)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    return meta, target.read_text('utf-8')


def sse(*events):
    return ''.join('data: ' + (json.dumps(event, ensure_ascii=False) if not isinstance(event, str) else event) + '\n\n' for event in events).encode()


@pytest.mark.parametrize('provider,value,expected', [
    ('openai', {'messages': [{'role': 'system', 'content': '系统\n限制'}, {'role': 'user', 'content': [{'type': 'text', 'text': '图片问题'}, {'type': 'image_url', 'image_url': {'url': 'data:full-image-data'}}]}], 'tools': [{'type': 'function', 'function': {'name': '完整工具', 'parameters': {'tail': 'schema-end'}}}]}, ['system', '系统\n限制', 'user', '图片问题', 'data:full-image-data', 'schema-end']),
    ('responses', {'instructions': '完整指令', 'input': [{'role': 'user', 'content': [{'type': 'input_text', 'text': '输入最末尾'}]}, {'type': 'function_call_output', 'call_id': 'call-1', 'output': '工具输出末尾'}]}, ['完整指令', '输入最末尾', '工具输出末尾']),
    ('responses', {'instructions': '首行', 'input': '用户的\n完整输入'}, ['首行', '用户的\n完整输入']),
    ('anthropic', {'system': [{'type': 'text', 'text': '完整系统提示'}], 'messages': [{'role': 'assistant', 'content': [{'type': 'tool_use', 'id': 'id-1', 'name': 'tool-end', 'input': {'needle': 'args-end'}}]}, {'role': 'user', 'content': [{'type': 'tool_result', 'tool_use_id': 'id-1', 'content': '结果结束'}]}]}, ['完整系统提示', 'tool-end', 'args-end', '结果结束']),
    ('gemini', {'systemInstruction': {'parts': [{'text': 'Gemini系统尾部'}]}, 'contents': [{'role': 'user', 'parts': [{'text': '内容尾部'}, {'inlineData': {'mimeType': 'image/png', 'data': 'full-image-tail'}}]}], 'tools': [{'functionDeclarations': [{'name': 'tool-tail'}]}]}, ['Gemini系统尾部', '内容尾部', 'full-image-tail', 'tool-tail']),
])
def test_complete_request_prompt_families(tmp_path, provider, value, expected):
    meta, text = decode(tmp_path, value, side='request')
    assert meta['recognized'] and not meta['fallback'] and meta['complete']
    assert meta['provider'] == provider and meta['kind'] == 'prompt-json'
    assert all(piece in text for piece in expected)


@pytest.mark.parametrize('provider,value,expected', [
    ('openai', {'choices': [{'message': {'role': 'assistant', 'content': '答案\n尾部', 'reasoning_content': '完整思考', 'tool_calls': [{'function': {'name': 'tool', 'arguments': '{"tail":"end"}'}}]}}]}, ['答案\n尾部', '完整思考', 'end']),
    ('responses', {'output': [{'type': 'reasoning', 'summary': [{'type': 'summary_text', 'text': '推理结束'}]}, {'type': 'message', 'role': 'assistant', 'content': [{'type': 'output_text', 'text': '答案尾部'}]}, {'type': 'function_call', 'name': 'tool', 'arguments': '{"tail":"args-end"}'}]}, ['推理结束', '答案尾部', 'args-end']),
    ('anthropic', {'type': 'message', 'role': 'assistant', 'content': [{'type': 'thinking', 'thinking': '思考末尾'}, {'type': 'text', 'text': '答案末尾'}, {'type': 'tool_use', 'input': {'x': '工具末尾'}}]}, ['思考末尾', '答案末尾', '工具末尾']),
    ('gemini', {'candidates': [{'content': {'role': 'model', 'parts': [{'thought': True, 'text': '推理'}, {'text': '答案'}, {'functionCall': {'name': 'tool', 'args': {'q': '参数'}}}]}}]}, ['推理', '答案', '参数']),
])
def test_complete_response_families(tmp_path, provider, value, expected):
    meta, text = decode(tmp_path, value)
    assert meta['recognized'] and meta['provider'] == provider
    assert all(piece in text for piece in expected)


def test_openai_sse_merges_full_text_reasoning_and_function_arguments(tmp_path):
    body = sse({'choices': [{'index': 0, 'delta': {'reasoning_content': '先想', 'tool_calls': [{'index': 0, 'id': 'call-one', 'function': {'name': 'weather', 'arguments': '{"city":'}}]}}]},
               {'choices': [{'index': 0, 'delta': {'reasoning_content': '然后', 'content': '中文', 'tool_calls': [{'index': 0, 'function': {'arguments': '"上海"}'}}]}}]},
               {'choices': [{'index': 0, 'delta': {'content': '响应尾部'}}]}, '[DONE]')
    meta, text = decode(tmp_path, body, raw=True)
    assert meta['recognized'] and meta['event_count'] == 4 and meta['provider'] == 'openai'
    assert '先想然后' in text and '中文响应尾部' in text and '{"city":"上海"}' in text
    assert 'weather' in text and 'call-one' in text


def test_responses_sse_does_not_duplicate_final_text_or_arguments(tmp_path):
    body = sse({'type': 'response.created', 'response': {'id': 'resp-1'}},
               {'type': 'response.output_text.delta', 'output_index': 0, 'content_index': 0, 'delta': '完整'},
               {'type': 'response.output_text.delta', 'output_index': 0, 'content_index': 0, 'delta': '答案'},
               {'type': 'response.output_text.done', 'output_index': 0, 'content_index': 0, 'text': '完整答案'},
               {'type': 'response.reasoning_summary_text.delta', 'output_index': 1, 'summary_index': 0, 'delta': '完整思考'},
               {'type': 'response.output_item.added', 'output_index': 2, 'item': {'type': 'function_call', 'name': 'weather', 'call_id': 'call-one', 'arguments': ''}},
               {'type': 'response.function_call_arguments.delta', 'output_index': 2, 'delta': '{"q":'},
               {'type': 'response.function_call_arguments.delta', 'output_index': 2, 'delta': '"参数"}'},
               {'type': 'response.function_call_arguments.done', 'output_index': 2, 'arguments': '{"q":"参数"}'},
               {'type': 'response.completed', 'response': {'id': 'resp-1'}})
    meta, text = decode(tmp_path, body, raw=True)
    assert meta['recognized'] and meta['provider'] == 'responses'
    assert text.count('完整答案') == 1 and text.count('{"q":"参数"}') == 1
    assert '完整思考' in text and 'weather' in text


def test_anthropic_sse_merges_thinking_text_and_tools(tmp_path):
    body = sse({'type': 'message_start', 'message': {'role': 'assistant'}},
               {'type': 'content_block_start', 'index': 0, 'content_block': {'type': 'thinking', 'thinking': ''}},
               {'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'thinking_delta', 'thinking': '完整思考'}},
               {'type': 'content_block_start', 'index': 1, 'content_block': {'type': 'text', 'text': ''}},
               {'type': 'content_block_delta', 'index': 1, 'delta': {'type': 'text_delta', 'text': '完整答案'}},
               {'type': 'content_block_start', 'index': 2, 'content_block': {'type': 'tool_use', 'id': 'tool-one', 'name': 'tool', 'input': {}}},
               {'type': 'content_block_delta', 'index': 2, 'delta': {'type': 'input_json_delta', 'partial_json': '{"x":'}},
               {'type': 'content_block_delta', 'index': 2, 'delta': {'type': 'input_json_delta', 'partial_json': '"完整参数"}'}},
               {'type': 'message_stop'})
    meta, text = decode(tmp_path, body, raw=True)
    assert meta['recognized'] and meta['provider'] == 'anthropic'
    assert '完整思考' in text and '完整答案' in text and '{"x":"完整参数"}' in text


def test_gemini_sse_merges_text_and_keeps_multimodal_fields(tmp_path):
    body = sse({'candidates': [{'content': {'parts': [{'thought': True, 'text': '想'}, {'text': '答'}]}}]},
               {'candidates': [{'content': {'parts': [{'thought': True, 'text': '完'}, {'text': '完'}, {'functionCall': {'name': 'tool', 'args': {'tail': '参数结束'}}}]}}]})
    meta, text = decode(tmp_path, body, raw=True)
    assert meta['recognized'] and meta['provider'] == 'gemini'
    assert '想完' in text and '答完' in text and '参数结束' in text


def test_large_prompt_and_sse_keep_tail_without_preview_cutoff(tmp_path):
    needle = '整段中文\n' * 110000 + 'END-PROMPT'
    meta, text = decode(tmp_path, {'messages': [{'role': 'user', 'content': needle}]}, side='request')
    assert meta['recognized'] and needle in text
    body = sse(*({'choices': [{'delta': {'content': '测试' * 2000}}]} for _ in range(20)), {'choices': [{'delta': {'content': 'END-RESPONSE'}}]})
    meta, text = decode(tmp_path, body, raw=True)
    assert meta['recognized'] and '测试' * 40000 + 'END-RESPONSE' in text


@pytest.mark.parametrize('sse_body', [False, True])
def test_over_budget_falls_back_to_entire_original_text(tmp_path, monkeypatch, sse_body):
    raw = json.dumps({'messages': [{'role': 'user', 'content': 'x' * (JSON_BUDGET + 200) + 'TAIL-NEVER-DROP'}]}).encode()
    if sse_body:
        raw = b'data: ' + raw + b'\n\n'
    original_read = Path.read_text
    def bounded(path, *args, **kwargs):
        assert path.stat().st_size <= JSON_BUDGET, 'giant JSON must never be read into memory for parsing'
        return original_read(path, *args, **kwargs)
    source, output = tmp_path / 'source', tmp_path / 'result'
    source.write_bytes(raw)
    monkeypatch.setattr(Path, 'read_text', bounded)
    meta = decode_prompt_file(source, output, side='request')
    assert not meta['recognized'] and meta['fallback'] and meta['warnings']
    assert output.read_bytes() == raw


@pytest.mark.parametrize('raw', [b'{"unknown":"all-fields-tail"}', b'{"messages": [{"content": "unfinished', b'{"messages":[],"messages":["duplicate-end"]}', b'data: {"unknown": "event-tail"}\n\n', b'data: {"choices":[{"delta":{"content":"partial-tail"}}]}'])
def test_unknown_invalid_duplicate_or_partial_preserves_exact_text(tmp_path, raw):
    meta, text = decode(tmp_path, raw, raw=True, side='request')
    assert meta['fallback'] and not meta['recognized']
    assert text.encode() == raw
    if raw.startswith(b'data:') and not raw.endswith(b'\n\n'):
        assert not meta['complete']


def test_declared_charset_gzip_and_incomplete_capture(tmp_path):
    raw = json.dumps({'messages': [{'role': 'user', 'content': '中文完整'}]}, ensure_ascii=False).encode('gb18030')
    meta, text = decode(tmp_path, gzip.compress(raw), raw=True, side='request', content_type='application/json; charset=gb18030', content_encoding='gzip', source_complete=False)
    assert meta['recognized'] and not meta['complete'] and '中文完整' in text and meta['warnings']


def test_sse_line_boundary_bom_and_multiline_data(tmp_path):
    # A physical data line of exactly one read block followed by its newline.
    prefix = b'data: {"choices":[{"delta":{"content":"'
    suffix = b'"}}]}'
    raw = prefix + b'x' * (65536 - len(prefix) - len(suffix)) + suffix + b'\n\n'
    meta, text = decode(tmp_path, raw, raw=True)
    assert meta['recognized'] and text.count('x') == 65536 - len(prefix) - len(suffix)
    raw = b'\xef\xbb\xbfdata: {"choices":\rdata: [{"delta":{"content":"multiline-tail"}}]}\r\r'
    meta, text = decode(tmp_path, raw, raw=True)
    assert meta['recognized'] and 'multiline-tail' in text


def test_cache_isolates_prompt_auto_sides_and_immutable_content(tmp_path):
    source = tmp_path / 'body.json'
    source.write_text(json.dumps({'messages': [{'role': 'user', 'content': 'FULL-PROMPT-END'}]}), encoding='utf-8')
    cache = ReadableCache(tmp_path)
    auto = cache.build('owner', source, presentation='auto', side='request')
    prompt = cache.build('owner', source, presentation='prompt', side='request')
    response = cache.build('owner', source, presentation='prompt', side='response')
    assert len({item['revision'] for item in (auto, prompt, response)}) == 3
    assert auto['kind'] == 'json' and prompt['kind'] == 'prompt-json' and response['fallback']
    assert cache.get('owner', auto['revision'])[1].read_text('utf-8').startswith('{')
    assert 'FULL-PROMPT-END' in cache.get('owner', prompt['revision'])[1].read_text('utf-8')
    assert cache.build('owner', source, presentation='prompt', side='request')['revision'] == prompt['revision']
    with pytest.raises(ValueError):
        cache.get('different-owner', prompt['revision'])


def test_capture_leg_filters_only_explicit_http_labels_and_searches_complete_body(tmp_path):
    store = Store(tmp_path / 'db.sqlite3')
    store.save_many([{'id': 'client', 'source': 'http', 'capture_leg': 'client', 'request_body_text': 'x' * 20000 + 'client-only-tail'},
                     {'id': 'upstream', 'source': 'http', 'capture_leg': 'upstream', 'request_body_text': 'x' * 20000 + 'upstream-only-tail'},
                     {'id': 'unmarked', 'source': 'http'}, {'id': 'packet', 'source': 'packet', 'capture_leg': 'client'},
                     {'id': 'invalid', 'source': 'http', 'capture_leg': 'guess'}])
    for leg in ('client', 'upstream'):
        result = store.query(capture_leg=leg)
        assert result['total'] == 1 and result['items'][0]['id'] == leg
        assert result['items'][0]['capture_leg'] == leg and 'request_body_text' not in result['items'][0]
        assert store.query(capture_leg=leg, q=leg + '-only-tail')['total'] == 1
    assert store.query(source='packet', capture_leg='client')['total'] == 0
    assert store.query(capture_leg='guess')['total'] == 0
    assert all('capture_leg' not in item for item in store.query()['items'] if item['id'] in {'packet', 'unmarked', 'invalid'})
    store.close()


def test_capture_leg_migrates_previous_compact_schema_without_guessing(tmp_path):
    path = tmp_path / 'db.sqlite3'
    store = Store(path)
    original = store.save({'id': 'old-leg', 'source': 'http', 'capture_leg': 'upstream', 'response_body_text': 'FULL-TAIL'})
    store.save({'id': 'old-unknown', 'source': 'http'})
    store.close()
    with sqlite3.connect(path) as db:
        db.execute('DROP INDEX summary_leg_time')
        db.execute('ALTER TABLE record_summaries DROP COLUMN capture_leg')
    store = Store(path)
    assert store.get('old-leg') == original
    assert store.query(capture_leg='upstream')['items'][0]['id'] == 'old-leg'
    assert store.query(capture_leg='client')['total'] == 0
    assert store.query()['total'] == 2
    store.close()


def test_responses_done_items_keep_outputs_that_had_no_delta(tmp_path):
    body = sse({'type': 'response.output_text.delta', 'output_index': 0, 'content_index': 0, 'delta': '已有增量'},
               {'type': 'response.output_item.done', 'output_index': 0, 'item': {'type': 'message', 'content': [{'type': 'output_text', 'text': '已有增量'}, {'type': 'output_text', 'text': '仅结束事件中的尾部'}]}},
               {'type': 'response.output_item.done', 'output_index': 1, 'item': {'type': 'reasoning', 'summary': [{'type': 'summary_text', 'text': '仅结束事件中的思考'}]}},
               {'type': 'response.completed', 'response': {}})
    meta, text = decode(tmp_path, body, raw=True)
    assert meta['recognized'] and text.count('已有增量') == 1
    assert '仅结束事件中的尾部' in text and '仅结束事件中的思考' in text


@pytest.mark.parametrize('body', [b'{"choices":[],"usage":{"total_tokens":100}}', sse({'choices': [{'delta': {'role': 'assistant'}}]}), sse({'type': 'message_start', 'message': {'id': 'start-only'}})])
def test_empty_model_output_never_becomes_a_blank_view(tmp_path, body):
    meta, text = decode(tmp_path, body, raw=True)
    assert meta['fallback'] and not meta['recognized'] and text.encode() == body
