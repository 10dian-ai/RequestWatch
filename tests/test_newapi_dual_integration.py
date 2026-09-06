"""Two real proxies around a local test relay; no external New API installation."""
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import httpx
import pytest
import uvicorn
from requestwatch.app import create_app
from requestwatch.config import Config
from test_app_integration import until


def reserve_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


@pytest.mark.skipif(os.getenv('RW_RUN_APP_INTEGRATION') != '1', reason='Opt-in dual mitmdump integration')
def test_two_legs_preserve_separate_complete_prompts(tmp_path):
    executable = os.getenv('RW_MITMDUMP', '')
    assert Path(executable).is_file()
    release, received = threading.Event(), threading.Event()
    observed = {}
    first = ('data: '+json.dumps({'choices':[{'index':0,'delta':{'reasoning_content':'先思考中文','content':'第一段回答\n'}}]},ensure_ascii=False)+'\n\n').encode()
    last = b'data: {"choices":[{"index":0,"delta":{"content":"PROVIDER-REPLY-END"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n'
    forward_port, reverse_port = reserve_port(), reserve_port()

    class Provider(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *args): pass
        def do_POST(self):
            observed['provider_body'] = self.rfile.read(int(self.headers['Content-Length']))
            observed['provider_auth'] = self.headers.get('Authorization')
            self.send_response(200)
            self.send_header('Content-Type','text/event-stream')
            self.send_header('Transfer-Encoding','chunked')
            self.send_header('Connection','close')
            self.end_headers()
            for piece in (first,last):
                self.wfile.write(f'{len(piece):x}\r\n'.encode()+piece+b'\r\n')
                self.wfile.flush()
                if piece is first: release.wait(25)
            self.wfile.write(b'0\r\n\r\n')
            self.wfile.flush()

    provider = ThreadingHTTPServer(('127.0.0.1',0),Provider)

    class Relay(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self,*args): pass
        def do_POST(self):
            original = self.rfile.read(int(self.headers['Content-Length']))
            observed.update(client_body=original,client_auth=self.headers.get('Authorization'),client_host=self.headers.get('Host'))
            value = json.loads(original)
            value['model'] = 'provider-mapped-model'
            value['messages'].insert(0,{'role':'system','content':'ONLY-UPSTREAM-SYSTEM'})
            outgoing = json.dumps(value,ensure_ascii=False).encode()
            with httpx.Client(proxy=f'http://127.0.0.1:{forward_port}',timeout=35,trust_env=False) as sender:
                with sender.stream('POST',f'http://127.0.0.1:{provider.server_port}/v1/chat/completions',content=outgoing,headers={'Content-Type':'application/json','Authorization':'Bearer provider-fixture-token'}) as reply:
                    self.send_response(reply.status_code)
                    self.send_header('Content-Type',reply.headers['content-type'])
                    self.send_header('Transfer-Encoding','chunked')
                    self.send_header('Connection','close')
                    self.end_headers()
                    for piece in reply.iter_raw():
                        self.wfile.write(f'{len(piece):x}\r\n'.encode()+piece+b'\r\n')
                        self.wfile.flush()
                    self.wfile.write(b'0\r\n\r\n')
                    self.wfile.flush()

    relay = ThreadingHTTPServer(('127.0.0.1',0),Relay)
    services = [provider,relay]
    workers = [threading.Thread(target=service.serve_forever,daemon=True) for service in services]
    for worker in workers: worker.start()
    listener = socket.socket()
    listener.bind(('127.0.0.1',0))
    listener.listen(2048)
    admin_port = listener.getsockname()[1]
    token = 'dual-leg-integration-test-token'
    app = create_app(Config(host='127.0.0.1',port=admin_port,data_dir=tmp_path/'app',token=token,inspection_profile='newapi',newapi_upstream=f'http://127.0.0.1:{relay.server_port}',newapi_reverse_port=reverse_port,proxy_host='127.0.0.1',proxy_port=forward_port,capture_enabled=False,proxy_enabled=True,mitmdump=executable))
    server = uvicorn.Server(uvicorn.Config(app,log_level='error',access_log=False))
    server_thread = threading.Thread(target=server.run,kwargs={'sockets':[listener]},daemon=True)
    server_thread.start()
    prompt = '完整中文输入'*100000+'CLIENT-PROMPT-END'
    original = json.dumps({'model':'client-alias','messages':[{'role':'user','content':prompt}],'stream':True},ensure_ascii=False).encode()
    client_data = bytearray()
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    def request():
        with httpx.Client(timeout=35,trust_env=False) as client:
            with client.stream('POST',f'http://127.0.0.1:{reverse_port}/v1/chat/completions',content=original,headers={'Host':'newapi-client.test','Content-Type':'application/json','Authorization':'Bearer client-fixture-token'}) as response:
                assert response.status_code == 200
                for piece in response.iter_raw():
                    client_data.extend(piece)
                    received.set()
    try:
        until(lambda:server.started,'app ready',seconds=25)
        def proxies_ready():
            try:
                for port in (forward_port,reverse_port):
                    with socket.create_connection(('127.0.0.1',port),timeout=.1): pass
                return True
            except OSError: return False
        until(proxies_ready,'both proxy listeners',seconds=25)
        future = pool.submit(request)
        assert received.wait(10), 'first chunk must cross both proxies before EOF'
        assert not future.done()
        with httpx.Client(base_url=f'http://127.0.0.1:{admin_port}',headers={'Authorization':'Bearer '+token},timeout=15,trust_env=False) as admin:
            def first_captures():
                records = admin.get('/api/records',params={'source':'http'}).json()['items']
                result = {record.get('capture_leg'):record for record in records}
                return result if all(result.get(leg,{}).get('response_body_size',0) for leg in ('client','upstream')) else None
            legs = until(first_captures,'both partial captures',seconds=12)
            for leg in ('client','upstream'):
                route = '/api/records/'+legs[leg]['id']
                assert admin.get(route).json()['response_body_complete'] is False
                assert admin.get(route+'/body/response?view=raw').content == first
            release.set()
            future.result(timeout=15)
            assert bytes(client_data) == first+last
            assert observed['client_body'] == original
            assert observed['client_auth'] == 'Bearer client-fixture-token'
            assert observed['client_host'] == 'newapi-client.test'
            assert observed['provider_auth'] == 'Bearer provider-fixture-token'
            assert json.loads(observed['provider_body'])['model'] == 'provider-mapped-model'
            for leg,expected in [('client',original),('upstream',observed['provider_body'])]:
                route = '/api/records/'+legs[leg]['id']
                until(lambda:admin.get(route).json().get('response_body_complete'),leg+' final capture')
                assert admin.get('/api/records',params={'source':'http','capture_leg':leg}).json()['total'] == 1
                raw = admin.get(route+'/body/request?view=raw').content
                assert hashlib.sha256(raw).digest() == hashlib.sha256(expected).digest()
                assert admin.get(route+'/body/response?view=raw').content == first+last
                for side,tail in [('request','CLIENT-PROMPT-END'),('response','PROVIDER-REPLY-END')]:
                    response = admin.get(route+f'/readable/{side}?presentation=prompt')
                    assert response.status_code == 200,response.text
                    meta = response.json()
                    text = admin.get(meta['content_url']).text
                    assert tail in text and meta['complete']
                    if side == 'request': assert ('ONLY-UPSTREAM-SYSTEM' in text) == (leg == 'upstream')
                    else: assert '先思考中文' in text and '第一段回答' in text
                    assert admin.get(meta['download_url']).text == text
                exported = admin.get(route+'/message/request')
                assert exported.status_code == 200 and exported.content.split(b'\r\n\r\n',1)[1] == expected
    finally:
        release.set()
        pool.shutdown(wait=True,cancel_futures=True)
        server.should_exit = True
        server_thread.join(timeout=18)
        if server_thread.is_alive():
            server.force_exit = True
            server_thread.join(timeout=3)
        listener.close()
        for service in services:
            service.shutdown()
            service.server_close()
        for worker in workers: worker.join(timeout=2)
        assert not server_thread.is_alive()
