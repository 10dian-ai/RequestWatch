const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.RW_PLAYWRIGHT_MODULE || 'playwright-core');
(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.RW_BROWSER_PATH ? { executablePath: process.env.RW_BROWSER_PATH } : {}) });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const errors = []; page.on('pageerror', error => errors.push(String(error)));
    await page.addInitScript(() => sessionStorage.setItem('requestwatch-token', 'newapi-ui-test-token'));
    let profile = 'newapi'; let revision = 1; let putBody = null; let pending = [];
    const counts = { puts: 0, applies: 0, bodies: {}, queries: [] };
    const prompt = '[system]\n系统要求 SYSTEM-COMPLETE\n[developer]\n开发要求 DEVELOPER-COMPLETE\n[user]\n' + '用户完整提示词 '.repeat(20000) + 'PROMPT-TAIL-COMPLETE\n[assistant]\n工具调用 TOOL-CALL-COMPLETE\n[tool]\n工具结果 TOOL-RESULT-COMPLETE';
    const reply = () => '[reasoning]\n完整思考 REASONING-COMPLETE\n[tool_calls]\n完整工具参数 TOOL-ARGS-COMPLETE\n[assistant]\n' + '模型完整回复 '.repeat(19000) + `REPLY-TAIL-${revision}`;
    const requestRaw = JSON.stringify({ model: 'test-model', messages: [{ role: 'user', content: prompt }], stream: true, metadata: { opaque: 'RAW-ONLY-FIELD' } });
    const responseRaw = () => `data: ${JSON.stringify({ choices: [{ delta: { reasoning_content: '完整思考', content: reply() } }], opaque: 'EVENT-ONLY-FIELD' })}\n\ndata: [DONE]\n\n`;
    const record = (id, leg) => ({ id, source: 'http', protocol: 'HTTPS', state: 'forwarded', capture_leg: leg, created_at: 1788660000, method: 'POST', url: leg === 'client' ? 'http://127.0.0.1:3000/v1/chat/completions' : 'https://provider.example/v1/chat/completions', container_name: 'new-api', request_headers: [['Content-Type', 'application/json']], request_body_ref: `${id}-request`, request_body_size: Buffer.byteLength(requestRaw), request_body_complete: true, response_headers: [['Content-Type', 'text/event-stream']], response_body_ref: `${id}-response-${revision}`, response_body_size: Buffer.byteLength(responseRaw()), response_body_complete: false, response_streaming: true, status_code: 200 });
    const packet = { id: 'old-packet', source: 'packet', protocol: 'TCP', state: 'captured', created_at: 1788660000, payload_hex: '616263', payload_size: 3, src_ip: '192.0.2.1', src_port: 3000, dst_ip: '192.0.2.2', dst_port: 53000 };
    const records = () => [record('client-call', 'client'), record('upstream-call', 'upstream'), record('legacy-call', undefined), packet];
    const containers = [
      { id: 'ambiguous', name: 'other-services', image: 'services:latest', ips: ['172.19.0.4'], ports: [{ type: 'tcp', private_port: 3000, public_port: 8300, ip: '0.0.0.0' }, { type: 'tcp', private_port: 9000, public_port: 8900, ip: '0.0.0.0' }] },
      { id: 'internal', name: 'private-api', image: 'private:latest', ips: ['172.19.0.5'], ports: [{ type: 'tcp', private_port: 3001 }] },
      { id: 'new-api', name: 'new-api-production', image: 'newapi:latest', ips: ['172.19.0.2'], ports: [{ type: 'tcp', private_port: 3000, public_port: 8300, ip: '0.0.0.0' }, { type: 'tcp', private_port: 3000, public_port: 8300, ip: '::' }] },
      { id: 'bound', name: 'bound-interface', image: 'service:latest', ips: ['172.19.0.7'], ports: [{ type: 'tcp', private_port: 3000, public_port: 8400, ip: '192.0.2.10' }] }
    ];
    let saved = { host: '127.0.0.1', port: 7030, inspection_profile: 'newapi', newapi_upstream: 'http://127.0.0.1:3000', newapi_reverse_port: 8081, passive_only: true, capture_enabled: false, interfaces: 'any', queue_num: 7030, protected_ports: [22], pending_limit: 128, default_timeout_seconds: 30, tcp_idle_timeout: 300, mitmdump: '', max_records: 10000, proxy_enabled: true, proxy_host: '127.0.0.1', proxy_port: 8080, token_configured: true, proxy_auth_configured: false };
    const settings = () => ({ saved, current: saved, pending, demo: true, restart_supported: true, interfaces: ['eth0'], data_dir: '/srv/requestwatch', settings_path: '/srv/requestwatch/settings.json' });
    await page.route('http://requestwatch.test/**', async route => {
      const url = new URL(route.request().url()); const resource = url.pathname;
      const json = value => route.fulfill({ contentType: 'application/json', body: JSON.stringify(value) });
      const text = value => route.fulfill({ contentType: 'text/plain; charset=utf-8', body: value });
      if (!resource.startsWith('/api/')) {
        const file = resource === '/' ? 'index.html' : resource.slice(1);
        if (!['index.html', 'app.js', 'app.css', 'favicon.svg'].includes(file)) return route.fulfill({ status: 404 });
        return route.fulfill({ contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.svg') ? 'image/svg+xml' : 'text/html', body: fs.readFileSync(path.join(__dirname, '..', 'requestwatch', 'static', file)) });
      }
      assert.equal(route.request().headers().authorization, 'Bearer newapi-ui-test-token');
      if (resource === '/api/status') return json({ mode: 'live', inspection_profile: profile, passive_only: true, newapi_upstream: saved.newapi_upstream, newapi_reverse_port: saved.newapi_reverse_port, proxy_port: 8080, capture: { capture_running: false }, stats: { total: 4, http: 3, packets: 1 } });
      if (resource === '/api/containers') return json({ items: containers });
      if (resource === '/api/records') { counts.queries.push(Object.fromEntries(url.searchParams)); const items = records().filter(item => (!url.searchParams.get('source') || item.source === url.searchParams.get('source')) && (!url.searchParams.get('capture_leg') || item.capture_leg === url.searchParams.get('capture_leg')) && (!url.searchParams.get('protocol') || item.protocol === url.searchParams.get('protocol'))); return json({ total: items.length, items }); }
      if (resource === '/api/settings') {
        if (route.request().method() === 'PUT') { counts.puts++; putBody = route.request().postDataJSON(); pending = Object.keys(putBody); saved = { ...saved, ...putBody }; }
        return json(settings());
      }
      if (resource === '/api/settings/apply') { counts.applies++; profile = saved.inspection_profile; pending = []; return json({ demo: true }); }
      if (resource.startsWith('/api/records/')) {
        const id = resource.split('/')[3]; const current = records().find(item => item.id === id);
        if (!current) return route.fulfill({ status: 404 });
        if (resource.split('/').length === 4) return json(current);
        const side = resource.includes('/request') ? 'request' : 'response';
        const presentation = url.searchParams.get('presentation') === 'prompt' ? 'prompt' : 'auto';
        if (resource.includes('/readable/') && !resource.endsWith('/content')) return json({ recognized: true, kind: presentation === 'prompt' ? 'prompt' : 'json', complete: true, content_url: `${resource}/content?presentation=${presentation}&revision=${revision}`, download_url: `${resource}/content?presentation=${presentation}&revision=${revision}&download=true` });
        if (resource.endsWith('/content')) { const key = `${id}:${side}:${presentation}`; counts.bodies[key] = (counts.bodies[key] || 0) + 1; return text(presentation === 'prompt' ? side === 'request' ? prompt : reply() : side === 'request' ? JSON.stringify(JSON.parse(requestRaw), null, 2) : responseRaw()); }
        if (resource.includes('/body/')) return text(side === 'request' ? requestRaw : responseRaw());
        if (resource.includes('/message/')) return text(`HTTP/1.1 ${side === 'request' ? 'POST /v1/chat/completions' : '200 OK'}\r\n\r\n${side === 'request' ? requestRaw : responseRaw()}`);
      }
      return route.fulfill({ status: 404, body: resource });
    });
    await page.goto('http://requestwatch.test'); await page.locator('#records-body tr').first().waitFor(); await page.locator('#poll-button').click();
    assert.equal(await page.locator('#filter-source').inputValue(), 'http'); assert.equal(await page.locator('#records-body tr').count(), 3);
    assert.match(await page.locator('#traffic-title').textContent(), /New API 请求/); assert.equal(await page.locator('#newapi-setup').isVisible(), true); assert.equal(await page.locator('#newapi-setup').getAttribute('open'), null);
    assert.match(await page.locator('#capture-state').textContent(), /不抓全机包/); assert.equal(await page.locator('#capture-dot').getAttribute('class'), 'engine-dot online');
    assert.match(await page.locator('[data-id="client-call"] .event-capture-leg').textContent(), /客户端 → NewAPI/); assert.match(await page.locator('[data-id="upstream-call"] .event-capture-leg').textContent(), /NewAPI → 供应商/); assert.equal(await page.locator('[data-id="legacy-call"] .event-capture-leg').textContent(), '未标记链路');
    await page.locator('[data-id="upstream-call"] .event-detail-button').click();
    await page.waitForFunction(() => document.querySelector('[data-body-side="request"] .body-pane-content pre')?.textContent.includes('TOOL-RESULT-COMPLETE') && document.querySelector('[data-body-side="response"] .body-pane-content pre')?.textContent.includes('REPLY-TAIL-1'));
    assert.equal(await page.locator('#detail-leg').textContent(), 'NewAPI → 供应商', 'selected detail explicitly identifies its captured leg');
    assert.equal(await page.locator('#http-request-format').inputValue(), 'prompt'); assert.equal(await page.locator('#http-response-format').inputValue(), 'prompt');
    assert.equal(await page.locator('[data-body-side="request"] .body-pane-title').textContent(), '发送的 Prompt'); assert.equal(await page.locator('[data-body-side="response"] .body-pane-title').textContent(), '收到的回复');
    assert.equal(await page.locator('[data-body-side="request"] .body-pane-content pre').textContent(), prompt); assert.equal(await page.locator('[data-body-side="response"] .body-pane-content pre').textContent(), reply());
    fs.mkdirSync(path.join(__dirname, '..', 'artifacts'), { recursive: true }); await page.locator('#toast').evaluate(node => { node.hidden = true; });
    await page.screenshot({ path: path.join(__dirname, '..', 'artifacts', 'newapi-prompt-workspace.png'), animations: 'disabled' });
    await page.locator('#http-request-format').selectOption('auto'); await page.waitForFunction(() => document.querySelector('[data-body-side="request"] .body-pane-content pre')?.textContent.includes('RAW-ONLY-FIELD'));
    await page.locator('#http-request-format').selectOption('prompt'); await page.waitForFunction(() => document.querySelector('[data-body-side="request"] .body-pane-content pre')?.textContent.startsWith('[system]'));
    assert.equal(counts.bodies['upstream-call:request:prompt'], 1, 'Prompt cache must survive switching to original JSON and back');
    assert.equal(counts.bodies['upstream-call:request:auto'], 1, 'original JSON has its own cache');
    await page.locator('#http-response-format').selectOption('text'); await page.waitForFunction(() => document.querySelector('[data-body-side="response"] .body-pane-content pre')?.textContent.includes('EVENT-ONLY-FIELD'));
    assert.equal(await page.locator('[data-body-side="response"] .body-pane-content pre').textContent(), responseRaw());
    await page.locator('#http-response-format').selectOption('prompt'); await page.waitForFunction(() => document.querySelector('[data-body-side="response"] .body-pane-content pre')?.textContent.startsWith('[reasoning]'));
    revision++; await page.locator('#detail-refresh').click(); await page.waitForFunction(() => document.querySelector('[data-body-side="response"] .body-pane-content pre')?.textContent.includes('REPLY-TAIL-2'));
    assert.equal(counts.bodies['upstream-call:request:prompt'], 1); assert.equal(counts.bodies['upstream-call:response:prompt'], 2);
    const responsePane = page.locator('[data-body-side="response"]'); await responsePane.locator('.body-download-menu > summary').click();
    const [download] = await Promise.all([page.waitForEvent('download'), responsePane.getByRole('button', { name: '下载原始正文', exact: true }).click()]); assert.equal(fs.readFileSync(await download.path(), 'utf8'), responseRaw());
    await page.locator('#close-detail').click(); await page.locator('#filter-leg').selectOption('client'); await page.waitForFunction(() => document.querySelectorAll('#records-body tr').length === 1);
    assert.equal(await page.locator('#records-body tr').getAttribute('data-id'), 'client-call'); assert.equal(counts.queries.at(-1).capture_leg, 'client');
    await page.locator('#filter-protocol').selectOption('TCP'); await page.waitForFunction(() => document.querySelector('#records-body tr')?.dataset.id === 'old-packet');
    assert.equal(await page.locator('#filter-source').inputValue(), ''); assert.equal(await page.locator('#filter-leg').inputValue(), '', 'TCP selection clears HTTP-only source/leg constraints');
    await page.locator('#filter-leg').selectOption('upstream'); await page.waitForFunction(() => document.querySelector('#records-body tr')?.dataset.id === 'upstream-call');
    assert.equal(await page.locator('#filter-source').inputValue(), 'http'); assert.equal(await page.locator('#filter-protocol').inputValue(), '');
    await page.locator('#reset-filters').click(); await page.waitForFunction(() => document.querySelectorAll('#records-body tr').length === 4); assert.equal(await page.locator('#filter-source').inputValue(), '');
    await page.locator('#refresh-button').click(); await page.waitForFunction(() => !document.querySelector('#refresh-button').disabled); assert.equal(await page.locator('#filter-source').inputValue(), '', 'ordinary refresh respects explicit all-network selection');
    await page.locator('.navigation [data-view="settings"]').click(); await page.locator('#settings-form').waitFor();
    assert.equal(await page.locator('#setting-inspection-profile').inputValue(), 'newapi'); assert.equal(await page.locator('#setting-newapi-reverse-port').inputValue(), '8081');
    assert.equal(await page.locator('#newapi-container-target option').nth(1).getAttribute('value'), 'new-api', 'NewAPI containers sort first');
    await page.locator('#newapi-container-target').selectOption('new-api'); await page.locator('#newapi-use-container').click(); assert.equal(await page.locator('#setting-newapi-upstream').inputValue(), 'http://127.0.0.1:8300'); assert.equal(counts.puts, 0); assert.equal(counts.applies, 0, 'picking a container only changes the draft');
    await page.locator('#newapi-container-target').selectOption('ambiguous'); await page.locator('#newapi-use-container').click(); assert.equal(await page.locator('#setting-newapi-upstream').inputValue(), 'http://127.0.0.1:8300', 'ambiguous ports do not overwrite the draft'); assert.match(await page.locator('#toast').textContent(), /多个端口/);
    await page.locator('#newapi-container-target').selectOption('internal'); await page.locator('#newapi-use-container').click(); assert.equal(await page.locator('#setting-newapi-upstream').inputValue(), 'http://172.19.0.5:3001');
    await page.locator('#newapi-container-target').selectOption('bound'); await page.locator('#newapi-use-container').click(); assert.equal(await page.locator('#setting-newapi-upstream').inputValue(), 'http://192.0.2.10:8400', 'specific host binding is preserved');
    await page.locator('#setting-newapi-upstream').fill('ftp://127.0.0.1:3000'); await page.locator('#settings-save').click(); assert.match(await page.locator('#settings-error').textContent(), /http:\/\/ 或 https:\/\//); assert.equal(counts.puts, 0);
    await page.locator('#setting-newapi-upstream').fill('http://127.0.0.1:9300'); await page.locator('#setting-newapi-reverse-port').fill('9081'); await page.locator('#setting-inspection-profile').selectOption('network'); await page.locator('#settings-save').click();
    await page.waitForFunction(() => document.querySelector('#settings-save-state')?.textContent.includes('等待应用'));
    assert.deepEqual(putBody, { inspection_profile: 'network', newapi_upstream: 'http://127.0.0.1:9300', newapi_reverse_port: 9081 });
    await page.locator('#settings-apply').click(); await page.waitForFunction(() => document.querySelector('#settings-save-state')?.textContent === '设置已应用');
    await page.locator('.navigation [data-view="traffic"]').click(); await page.waitForFunction(() => document.querySelector('#traffic-title')?.textContent.includes('网络流量')); assert.equal(await page.locator('#newapi-setup').isVisible(), false); assert.equal(await page.locator('#filter-source').inputValue(), '');
    profile = 'newapi'; await page.locator('#refresh-button').click(); await page.waitForFunction(() => document.querySelector('#traffic-title')?.textContent.includes('New API 请求')); assert.equal(await page.locator('#filter-source').inputValue(), 'http');
    await page.setViewportSize({ width: 390, height: 844 }); assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1), false, 'NewAPI filters retain mobile layout');
    assert.deepEqual(errors, []);
    console.log('NewAPI UI passed: HTTP default, both capture legs and unknown history, full Prompt/reasoning/tool/reply views, isolated original-format caches, one-side stream refresh, exact raw download, TCP/all-record fallback, Web settings apply, Docker draft selection and ambiguity checks, mobile layout.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exit(1); });
