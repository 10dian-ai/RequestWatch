const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.RW_PLAYWRIGHT_MODULE || 'playwright-core');
(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.RW_BROWSER_PATH ? { executablePath: process.env.RW_BROWSER_PATH } : {}) });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const errors = []; page.on('pageerror', error => errors.push(String(error)));
    await page.addInitScript(() => sessionStorage.setItem('requestwatch-token', 'performance-test-token'));
    const originalRequestText = JSON.stringify({ model: 'newapi-test', messages: [{ role: 'user', content: '完整提示词 '.repeat(130000) + 'REQUEST-TAIL-COMPLETE' }] });
    const requestText = originalRequestText.slice(0, 8190) + 'CROSS-BLOCK-边界' + originalRequestText.slice(8190);
    const responseText = revision => JSON.stringify({ choices: [{ message: { role: 'assistant', content: '完整返回内容 '.repeat(125000) + `RESPONSE-TAIL-${revision}` } }] });
    let revision = 1; let acknowledgements = 1; let growTcp = false; let addRecord = false;
    const counts = { status: 0, lists: 0, details: 0, rawBodies: 0, readableMeta: 0, readableBodies: 0, tcpMeta: 0, tcpBodies: 0 };
    const http = () => ({ id: 'large-newapi', source: 'http', protocol: 'HTTPS', state: 'forwarded', created_at: 1788575000, method: 'POST', url: 'https://provider.example/v1/chat/completions', request_body_ref: 'request-sha', request_body_size: Buffer.byteLength(requestText), request_body_complete: true, request_headers: [['Content-Type', 'application/json']], response_body_ref: `response-sha-${revision}`, response_body_size: Buffer.byteLength(responseText(revision)), response_body_complete: false, response_streaming: true, response_headers: [['Content-Type', 'application/json']], status_code: 200, container_name: 'new-api' });
    const packet = { id: 'packet', source: 'packet', protocol: 'TCP', state: 'captured', src_ip: '172.19.0.2', src_port: 3000, dst_ip: '192.0.2.2', dst_port: 53240, created_at: 1788575000, payload_hex: '616263', payload_size: 3, tcp_session_id: 'connection', tcp_session_available: true, tcp_session_direction: 'server' };
    const direction = side => ({ byte_count: 2000000 + (growTcp && side === 'server' ? 4 : 0), segment_count: 12, gap_count: 0, missing_bytes: 0, overlap_conflicts: 0 });
    const session = () => ({ id: 'connection', state: 'open', complete: false, created_at: 1788575000, updated_at: 1788575000 + acknowledgements, packet_count: acknowledgements, client_ip: packet.dst_ip, client_port: packet.dst_port, server_ip: packet.src_ip, server_port: packet.src_port, directions: { client: direction('client'), server: direction('server') } });
    const tcpText = side => side === 'client' ? requestText : responseText(growTcp ? 2 : 1);
    await page.route('http://requestwatch.test/**', async route => {
      const url = new URL(route.request().url()); const resource = url.pathname;
      const json = value => route.fulfill({ contentType: 'application/json', body: JSON.stringify(value) });
      const text = value => route.fulfill({ contentType: 'text/plain; charset=utf-8', body: value });
      if (!resource.startsWith('/api/')) {
        const file = resource === '/' ? 'index.html' : resource.slice(1);
        if (!['index.html', 'app.js', 'app.css', 'favicon.svg'].includes(file)) return route.fulfill({ status: 404 });
        return route.fulfill({ contentType: file.endsWith('.js') ? 'text/javascript' : file.endsWith('.css') ? 'text/css' : file.endsWith('.svg') ? 'image/svg+xml' : 'text/html', body: fs.readFileSync(path.join(__dirname, '..', 'requestwatch', 'static', file)) });
      }
      assert.equal(route.request().headers().authorization, 'Bearer performance-test-token');
      if (resource === '/api/status') { counts.status++; return json({ mode: 'live', passive_only: true, stats: { total: addRecord ? 3 : 2, pending: 0, http: 1, packets: 1 } }); }
      if (resource === '/api/containers') return json({ items: [] });
      if (resource === '/api/records') { counts.lists++; return json({ total: addRecord ? 3 : 2, items: [...(addRecord ? [{ ...packet, id: 'new-record' }] : []), http(), packet] }); }
      if (resource === '/api/records/large-newapi') { counts.details++; return json(http()); }
      if (resource === '/api/records/packet') { counts.details++; return json(packet); }
      if (resource === '/api/sessions/connection') { counts.tcpMeta++; return json(session()); }
      if (resource.includes('/readable/') && !resource.endsWith('/content')) { counts.readableMeta++; return json({ recognized: true, kind: 'json', complete: true, warnings: [], content_url: `${resource}/content`, download_url: `${resource}/content?download=true` }); }
      if (resource.endsWith('/content')) {
        if (resource.startsWith('/api/sessions/')) { counts.tcpBodies++; return text(tcpText(resource.includes('/client/') ? 'client' : 'server')); }
        counts.readableBodies++; return text(resource.includes('/request/') ? requestText : responseText(revision));
      }
      if (resource.includes('/body/')) { counts.rawBodies++; return text(resource.endsWith('/request') ? requestText : responseText(revision)); }
      return route.fulfill({ status: 404, body: resource });
    });
    const waitBodies = suffix => page.waitForFunction(suffix => document.querySelector('[data-body-side="request"] .body-pane-content pre')?.textContent.endsWith('REQUEST-TAIL-COMPLETE"}]}') && document.querySelector('[data-body-side="response"] .body-pane-content pre')?.textContent.includes(suffix), suffix);
    const startTime = Date.now();
    await page.goto('http://requestwatch.test'); await page.locator('#records-body tr[data-id="large-newapi"]').waitFor();
    await page.locator('#records-body tr[data-id="large-newapi"] .event-detail-button').click();
    await waitBodies('RESPONSE-TAIL-1'); console.log(`Large bodies loaded in ${Date.now() - startTime}ms.`);
    assert(Buffer.byteLength(requestText) > 2000000);
    assert(Buffer.byteLength(responseText(1)) > 2000000);
    assert.equal(counts.rawBodies, 0, 'readonly parsed view must not fetch duplicate full original bodies');
    assert.equal(counts.readableBodies, 2, 'one full parsed body per direction');
    await page.evaluate(() => {
      window.baseline = { row: document.querySelector('#records-body tr[data-id="large-newapi"]'), request: document.querySelector('[data-body-side="request"] .body-pane-content pre'), response: document.querySelector('[data-body-side="response"] .body-pane-content pre'), mutations: 0 };
      baseline.request.scrollTop = baseline.request.scrollHeight;
      baseline.readingOffset = baseline.request.scrollTop;
      window.observer = new MutationObserver(changes => { window.baseline.mutations += changes.filter(change => change.type === 'childList').length; });
      window.observer.observe(document.querySelector('#detail-body'), { childList: true, subtree: true });
    });
    const initial = { ...counts }; const until = Date.now() + 12000;
    while (counts.lists < initial.lists + 3 && Date.now() < until) await page.waitForTimeout(200);
    assert(counts.lists >= initial.lists + 3, 'real automatic polls occurred');
    assert.equal(counts.details, initial.details, 'unchanged list metadata does not refetch complete record details');
    assert.equal(counts.readableBodies, initial.readableBodies);
    assert.equal(await page.evaluate(() => baseline.request.scrollTop), await page.evaluate(() => baseline.readingOffset), 'automatic polling and completed chunk layout preserve the exact reading offset');
    assert.deepEqual(await page.evaluate(() => ({ row: baseline.row === document.querySelector('#records-body tr[data-id="large-newapi"]'), request: baseline.request === document.querySelector('[data-body-side="request"] .body-pane-content pre'), response: baseline.response === document.querySelector('[data-body-side="response"] .body-pane-content pre'), mutations: baseline.mutations })), { row: true, request: true, response: true, mutations: 0 });
    console.log('Unchanged HTTP polls verified.');
    const requestPane = page.locator('[data-body-side="request"]');
    for (const needle of ['CROSS-BLOCK-边界', 'REQUEST-TAIL-COMPLETE']) {
      await requestPane.getByRole('searchbox', { name: '搜索此处全文' }).fill(needle);
      await requestPane.getByRole('button', { name: '查找', exact: true }).click();
      assert.equal(await page.evaluate(() => window.getSelection().toString()), needle, 'full-text search crosses chunk boundaries and reaches the tail');
      await page.waitForFunction(() => { const selection = window.getSelection(); if (!selection.rangeCount) return false; const range = selection.getRangeAt(0).getBoundingClientRect(); const block = document.querySelector('[data-body-side="request"] .body-pane-content pre').getBoundingClientRect(); return range.bottom >= block.top && range.top < block.bottom; });
    }
    revision = 2; addRecord = true;
    await page.locator('#detail-refresh').click(); await waitBodies('RESPONSE-TAIL-2');
    assert.equal(counts.readableBodies, initial.readableBodies + 1, 'only changed response body is downloaded');
    assert.equal(await page.evaluate(() => baseline.request === document.querySelector('[data-body-side="request"] .body-pane-content pre')), true, 'large request text node survives response streaming update');
    assert.equal(await page.locator('[data-body-side="request"] .body-pane-content pre').textContent(), requestText);
    assert.equal(await page.locator('[data-body-side="response"] .body-pane-content pre').textContent(), responseText(2));
    await page.locator('#close-detail').click(); await page.locator('#records-body tr[data-id="packet"] .event-detail-button').click();
    await page.waitForFunction(() => document.querySelector('[data-body-side="client"] .body-pane-content pre')?.textContent.includes('REQUEST-TAIL-COMPLETE') && document.querySelector('[data-body-side="server"] .body-pane-content pre')?.textContent.includes('RESPONSE-TAIL-1'));
    await page.evaluate(() => { window.tcpBaseline = { client: document.querySelector('[data-body-side="client"] .body-pane-content pre'), server: document.querySelector('[data-body-side="server"] .body-pane-content pre') }; });
    console.log('Large TCP bodies loaded.');
    const beforeTcp = counts.tcpBodies; acknowledgements += 8000;
    await page.locator('#detail-refresh').click();
    await page.waitForFunction(() => !document.querySelector('#refresh-button').disabled); await page.waitForTimeout(100);
    assert.equal(counts.tcpBodies, beforeTcp, 'ACK-only metadata does not refetch TCP bodies');
    assert.equal(await page.evaluate(() => tcpBaseline.client === document.querySelector('[data-body-side="client"] .body-pane-content pre') && tcpBaseline.server === document.querySelector('[data-body-side="server"] .body-pane-content pre')), true, 'ACK-only metadata does not rebuild either full body');
    growTcp = true; await page.locator('#detail-refresh').click();
    await page.waitForFunction(() => document.querySelector('[data-body-side="server"] .body-pane-content pre')?.textContent.includes('RESPONSE-TAIL-2'));
    assert.equal(counts.tcpBodies, beforeTcp + 1, 'only changed TCP direction refetches');
    assert.equal(await page.evaluate(() => tcpBaseline.client === document.querySelector('[data-body-side="client"] .body-pane-content pre')), true, 'unchanged TCP direction keeps its text DOM during opposite-direction growth');
    assert.equal(await page.locator('[data-body-side="client"] .body-pane-content pre').textContent(), requestText);
    assert.equal(await page.locator('[data-body-side="server"] .body-pane-content pre').textContent(), responseText(2));
    assert.deepEqual(errors, []);
    console.log(`Performance regression passed: ${Buffer.byteLength(requestText)}B request / ${Buffer.byteLength(responseText(2))}B response, 3 automatic polls preserve rows and body DOM with zero body downloads or child mutations, single-side stream update, TCP ACK-only stable bodies. ${JSON.stringify(counts)}`);
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exit(1); });
