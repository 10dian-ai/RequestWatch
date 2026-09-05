const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.RW_PLAYWRIGHT_MODULE || 'playwright-core');
(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.RW_BROWSER_PATH ? { executablePath: process.env.RW_BROWSER_PATH } : {}) });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1050 } });
    const errors = []; page.on('pageerror', error => errors.push(String(error)));
    await page.addInitScript(() => sessionStorage.setItem('requestwatch-token', 'body-test-token'));
    const now = Date.now() / 1000;
    const requestText = JSON.stringify({ prompt: '请求体\n' + '完整请求内容 '.repeat(8000) + 'REQUEST-END-VISIBLE' });
    const responseText = '响应正文\n' + '全部响应内容 '.repeat(9000) + 'RESPONSE-END-VISIBLE';
    const http = { id: 'http-body', source: 'http', protocol: 'HTTP', state: 'forwarded', created_at: now, method: 'POST', url: 'http://example.test/chat', request_body_ref: 'req-body', request_body_size: Buffer.byteLength(requestText), request_body_complete: true, request_headers: [['Content-Type', 'application/json']], response_body_ref: 'res-body', response_body_size: Buffer.byteLength(responseText), response_body_complete: true, response_headers: [['Content-Type', 'text/plain']], status_code: 200 };
    const get = { ...http, id: 'http-get', method: 'GET', request_body_ref: 'empty', request_body_size: 0 };
    const packet = { id: 'packet-body', source: 'packet', protocol: 'TCP', state: 'captured', created_at: now, src_ip: '172.19.0.2', src_port: 3000, dst_ip: '192.0.2.4', dst_port: 54000, payload_hex: Buffer.from('data: 一个片段').toString('hex'), payload_size: 23, payload_text: 'data: 一个片段', tcp_session_id: 'body-session', tcp_session_available: true, tcp_session_direction: 'server' };
    let readOnly = true; let revision = 1; let inferred = false; let sessionCalls = 0; const bodyCalls = [];
    const direction = () => ({ byte_count: 8000 + revision, segment_count: revision, gap_count: 0, missing_bytes: 0 });
    const session = () => ({ id: 'body-session', state: 'open', created_at: now, updated_at: now + revision, midstream: inferred, direction_inferred: inferred, client_ip: packet.dst_ip, client_port: packet.dst_port, server_ip: packet.src_ip, server_port: packet.src_port, directions: { client: direction(), server: direction() } });
    const tcpText = side => `${side === 'client' ? 'POST /chat HTTP/1.1\n请求正文' : 'HTTP/1.1 200 OK\n思考内容\n第一行\n响应正文'}\n${'完整连接内容 '.repeat(1000)}\n${side === 'client' ? 'REQ' : 'RES'}-END-VISIBLE-${revision}`;
    await page.route('http://requestwatch.test/**', async route => {
      const url = new URL(route.request().url()); const resource = url.pathname;
      const json = value => route.fulfill({ contentType: 'application/json', body: JSON.stringify(value) });
      const text = value => route.fulfill({ contentType: 'text/plain; charset=utf-8', body: value });
      if (!resource.startsWith('/api/')) {
        const file = resource === '/' ? 'index.html' : resource.slice(1);
        if (!['index.html', 'app.js', 'app.css', 'favicon.svg'].includes(file)) return route.fulfill({ status: 404 });
        return route.fulfill({ contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.svg') ? 'image/svg+xml' : 'text/html', body: fs.readFileSync(path.join(__dirname, '..', 'requestwatch', 'static', file)) });
      }
      assert.equal(route.request().headers().authorization, 'Bearer body-test-token');
      if (resource === '/api/status') return json({ mode: 'live', passive_only: readOnly, stats: { total: 3, pending: 0, http: 2, packets: 1 } });
      if (resource === '/api/containers') return json({ items: [] });
      if (resource === '/api/records') return json({ total: 3, items: [http, packet, get] });
      if (resource === '/api/records/http-body') return json(http);
      if (resource === '/api/records/http-get') return json(get);
      if (resource === '/api/records/packet-body') return json(packet);
      if (resource === '/api/sessions') return json({ total: 1, items: [session()] });
      if (resource === '/api/sessions/body-session') { sessionCalls++; return json(session()); }
      if (resource.includes('/readable/') && !resource.endsWith('/content')) {
        bodyCalls.push(resource);
        return json({ recognized: true, kind: resource.startsWith('/api/sessions/') ? 'http' : resource.endsWith('/request') ? 'json' : 'text', complete: true, warnings: [], content_url: `${resource}/content?revision=${revision}`, download_url: `${resource}/content?revision=${revision}&download=true` });
      }
      if (resource.endsWith('/content')) {
        if (resource.startsWith('/api/sessions/')) return text(tcpText(resource.includes('/client/') ? 'client' : 'server'));
        return text(resource.includes('/request/') ? resource.includes('/http-get/') ? '' : JSON.stringify(JSON.parse(requestText), null, 2) : responseText);
      }
      if (resource.includes('/body/')) {
        if (resource.startsWith('/api/sessions/')) return text(tcpText(resource.endsWith('/client') ? 'client' : 'server'));
        return text(resource.endsWith('/request') ? resource.includes('/http-get/') ? '' : requestText : responseText);
      }
      return route.fulfill({ status: 404, body: resource });
    });
    await page.goto('http://requestwatch.test'); await page.locator('#records-body tr').first().waitFor(); await page.locator('#poll-button').click();
    fs.mkdirSync(path.join(__dirname, '..', 'artifacts'), { recursive: true });
    await page.locator('#toast').evaluate(node => { node.hidden = true; });
    await page.screenshot({ path: path.join(__dirname, '..', 'artifacts', 'webui-event-list-desktop.png'), fullPage: true, animations: 'disabled' });
    await page.locator('#records-body tr[data-id="http-body"] .event-detail-button').click();
    await page.waitForFunction(() => document.querySelector('[data-body-side="request"] .readable-body')?.textContent.includes('REQUEST-END-VISIBLE') && document.querySelector('[data-body-side="response"] .readable-body')?.textContent.includes('RESPONSE-END-VISIBLE'));
    assert.equal(await page.locator('[data-tab="content"]').getAttribute('aria-selected'), 'true');
    assert.equal(await page.locator('.body-workspace > .body-pane').count(), 2);
    assert.equal(await page.locator('[data-body-side="request"] .body-pane-title').textContent(), '请求体');
    assert.equal(await page.locator('[data-body-side="response"] .body-pane-title').textContent(), '响应体');
    assert.match(await page.locator('[data-body-side="request"] .body-pane-subtitle').textContent(), /POST.*example.test/);
    assert.match(await page.locator('[data-body-side="response"] .body-pane-subtitle').textContent(), /HTTP 200/);
    assert.equal(await page.locator('.body-pane-headers[open]').count(), 0);
    assert.equal(await page.locator('.navigation [data-view="rules"]').isVisible(), false);
    assert.equal(await page.locator('.navigation [data-view="pending"]').isVisible(), false);
    assert.equal(await page.locator('#stat-pending').isVisible(), false);
    assert.equal(await page.locator('#edit-button').isVisible(), false); assert.equal(await page.locator('#replay-button').isVisible(), false);
    const duplicateIds = await page.evaluate(() => { const ids = [...document.querySelectorAll('[id]')].map(el => el.id); return ids.filter((id, n) => ids.indexOf(id) !== n); }); assert.deepEqual(duplicateIds, []);
    await page.locator('#http-request-format').selectOption('text');
    await page.waitForFunction(raw => document.querySelector('[data-body-side="request"] .full-body')?.textContent === raw, requestText);
    assert.equal(await page.locator('#http-response-format').inputValue(), 'auto');
    const pane = page.locator('[data-body-side="response"]');
    await pane.getByRole('searchbox', { name: '搜索此处全文' }).fill('RESPONSE-END-VISIBLE'); await pane.getByRole('button', { name: '查找', exact: true }).click();
    assert.equal(await page.evaluate(() => window.getSelection().toString()), 'RESPONSE-END-VISIBLE');
    const [responseDownload] = await Promise.all([page.waitForEvent('download'), pane.getByRole('button', { name: '下载原始正文', exact: true }).click()]);
    assert.equal(fs.readFileSync(await responseDownload.path(), 'utf8'), responseText);
    await page.locator('#toast').evaluate(node => { node.hidden = true; });
    fs.mkdirSync(path.join(__dirname, '..', 'artifacts'), { recursive: true });
    await page.locator('#record-detail-drawer').evaluate(node => { node.scrollTop = 0; });
    await page.screenshot({ path: path.join(__dirname, '..', 'artifacts', 'webui-body-http-desktop.png'), fullPage: false, animations: 'disabled' });
    await page.locator('#close-detail').click();
    await page.locator('#records-body tr[data-id="packet-body"] .event-detail-button').click();
    await page.waitForFunction(() => document.querySelector('[data-body-side="client"] .inline-tcp-body')?.textContent.includes('REQ-END-VISIBLE-1') && document.querySelector('[data-body-side="server"] .inline-tcp-body')?.textContent.includes('RES-END-VISIBLE-1'));
    assert.equal(await page.locator('[data-tab="content"]').getAttribute('aria-selected'), 'true');
    assert.equal(await page.locator('#packet-context').isVisible(), false);
    assert.equal(await page.locator('[data-body-side="client"] .body-pane-title').textContent(), '客户端 → 服务端');
    const countBefore = bodyCalls.length; await page.waitForTimeout(350); assert.equal(bodyCalls.length, countBefore, 'render callbacks must not trigger a fetch loop');
    revision++;
    await page.locator('#detail-refresh').click();
    await page.waitForFunction(() => document.querySelector('[data-body-side="client"] .inline-tcp-body')?.textContent.includes('REQ-END-VISIBLE-2') && document.querySelector('[data-body-side="server"] .inline-tcp-body')?.textContent.includes('RES-END-VISIBLE-2'));
    await page.locator('#inline-tcp-client-format').selectOption('text');
    await page.waitForFunction(text => document.querySelector('[data-body-side="client"] .inline-tcp-body')?.textContent === text, tcpText('client'));
    assert.equal(await page.locator('#inline-tcp-server-format').inputValue(), 'auto');
    const [tcpDownload] = await Promise.all([page.waitForEvent('download'), page.locator('[data-body-side="server"]').getByRole('button', { name: '下载全部原始字节', exact: true }).click()]);
    assert.equal(fs.readFileSync(await tcpDownload.path(), 'utf8'), tcpText('server'));
    inferred = true; revision++;
    await page.locator('#detail-refresh').click();
    await page.waitForFunction(() => document.querySelector('[data-body-side="client"] .body-pane-title')?.textContent.includes('端点 A → B'));
    assert.match(await page.locator('[data-body-side="server"] .body-pane-title').textContent(), /端点 B → A/);
    assert.equal(await page.locator('.body-workspace .body-pane-title').filter({ hasText: '请求体' }).count(), 0);
    await page.locator('#toast').evaluate(node => { node.hidden = true; });
    await page.locator('#record-detail-drawer').evaluate(node => { node.scrollTop = 0; });
    await page.screenshot({ path: path.join(__dirname, '..', 'artifacts', 'webui-body-tcp-desktop.png'), fullPage: false, animations: 'disabled' });
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1), false, 'mobile horizontal overflow');
    await page.screenshot({ path: path.join(__dirname, '..', 'artifacts', 'webui-body-tcp-mobile.png'), fullPage: false, animations: 'disabled' });
    await page.locator('#close-detail').click();
    await page.locator('#records-body tr[data-id="http-get"] .event-detail-button').click();
    await page.waitForFunction(() => document.querySelector('[data-body-side="request"]')?.textContent.includes('无请求正文'));
    readOnly = false;
    await page.locator('#detail-refresh').click();
    await page.waitForFunction(() => !document.querySelector('#edit-button').hidden);
    assert.equal(await page.locator('.navigation [data-view="rules"]').isVisible(), true);
    assert.equal(await page.locator('#stat-pending').isVisible(), true);
    readOnly = true;
    await page.locator('#detail-refresh').click();
    await page.waitForFunction(() => document.querySelector('#edit-button').hidden);
    await page.keyboard.press('Escape');
    assert.equal(await page.locator('#record-detail-drawer').isVisible(), false, 'Escape closes the drawer');
    assert.equal(await page.locator('#records-body tr[data-id="http-get"] .event-detail-button').evaluate(node => document.activeElement === node), true, 'closing restores row button focus');
    assert(sessionCalls < 10, 'session metadata is fetched on selection/refresh only');
    assert.deepEqual(errors, []);
    console.log('Body workspace passed: default paired HTTP request/response bodies with full tails, independent formats, safe unique IDs, full-text find/download, direct bidirectional TCP content and live updates, inferred endpoints, GET empty body, readonly controls, desktop/mobile.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exit(1); });
