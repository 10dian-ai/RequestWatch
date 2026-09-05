const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.RW_PLAYWRIGHT_MODULE || 'playwright-core');

// Browser contract regression: retained records stop at 10,000 while the lifetime
// counter advances; the parser's complete text and raw bytes remain separate.
(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.RW_BROWSER_PATH ? { executablePath: process.env.RW_BROWSER_PATH } : {}) });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1050 } });
    const errors = []; const readableRequests = [];
    page.on('pageerror', error => errors.push(String(error)));
    await page.addInitScript(() => sessionStorage.setItem('requestwatch-token', 'test-readable-token'));
    const now = Date.now() / 1000;
    let captured = 10000; let revision = 1; let inferred = true; let recognized = true;
    const requestRaw = '{"prompt":"你好\\n下一行","messages":[{"role":"user","content":"<img src=x onerror=alert(1)>"}]}';
    const requestReadable = JSON.stringify(JSON.parse(requestRaw), null, 2);
    const rawStream = '170\r\ndata: {"choices":[{"index":0,"delta":{"role":"assistant","content":"你好\\n下一行"}}]}\r\n\r\n0\r\n\r\n';
    const readableStream = '[assistant · choice 0]\n你好\n下一行\n' + Array.from({ length: 800 }, (_, index) => `完整正文第 ${index} 行`).join('\n') + '\n全文末尾标记';
    const direction = () => ({ byte_count: Buffer.byteLength(rawStream) + revision, segment_count: revision, gap_count: 0, missing_bytes: 0 });
    const session = () => ({ id: 'tcp-readable', state: 'open', created_at: now, updated_at: now + revision, packet_count: revision, midstream: true, direction_inferred: inferred, complete: false, client_ip: '10.1.0.2', client_port: 50000, server_ip: '10.1.0.1', server_port: 80, directions: { client: direction(), server: direction() } });
    const record = { id: 'http-readable', source: 'http', protocol: 'HTTP', state: 'forwarded', method: 'POST', url: 'http://example.test/chat', created_at: now, request_body_ref: 'r1', response_body_ref: 's1', request_body_size: Buffer.byteLength(requestRaw), response_body_size: Buffer.byteLength(rawStream), request_headers: [['Content-Type', 'application/json']], response_headers: [['Content-Type', 'text/event-stream']], status_code: 200, request_body_complete: true, response_body_complete: true };
    await page.route('http://requestwatch.test/**', async route => {
      const url = new URL(route.request().url()); const resource = url.pathname;
      const json = value => route.fulfill({ contentType: 'application/json', body: JSON.stringify(value) });
      const text = value => route.fulfill({ contentType: 'text/plain; charset=utf-8', body: value });
      if (!resource.startsWith('/api/')) {
        const filename = resource === '/' ? 'index.html' : resource.slice(1);
        if (!['index.html', 'app.js', 'app.css', 'favicon.svg'].includes(filename)) return route.fulfill({ status: 404 });
        return route.fulfill({ contentType: filename.endsWith('.js') ? 'text/javascript' : filename.endsWith('.css') ? 'text/css' : filename.endsWith('.svg') ? 'image/svg+xml' : 'text/html', body: fs.readFileSync(path.join(__dirname, '..', 'requestwatch', 'static', filename)) });
      }
      assert.equal(route.request().headers().authorization, 'Bearer test-readable-token');
      if (resource === '/api/status') return json({ mode: 'live', port: 7030, max_records: 10000, stats: { total: 10000, retained: 10000, captured_total: captured, evicted_total: captured - 10000, counter_started_at: now, counter_baseline: 10000, last_capture_at: now + captured - 10000, history_before_counter_unknown: true, pending: 0, http: 3000, packets: 7000 } });
      if (resource === '/api/containers') return json({ items: [] });
      if (resource === '/api/records') return json({ total: 1, items: [record] });
      if (resource === '/api/records/http-readable') return json(record);
      if (resource === '/api/sessions') return json({ total: 1, items: [session()] });
      if (resource === '/api/sessions/tcp-readable') return json(session());
      if (resource.includes('/readable/') && !resource.endsWith('/content')) {
        readableRequests.push(resource);
        if (revision > 1) await new Promise(resolve => setTimeout(resolve, 120));
        const isRequest = resource.endsWith('/request');
        const contentUrl = `${resource}/content?revision=${revision}`;
        return json({ recognized: isRequest || recognized, kind: isRequest ? 'json' : 'openai', complete: isRequest, warnings: isRequest ? [] : ['连接仍在采集，内容可能继续增长。'], content_url: contentUrl, download_url: `${contentUrl}&download=true`, revision: String(revision), content_size: Buffer.byteLength(isRequest ? requestReadable : readableStream) });
      }
      if (resource.endsWith('/content')) {
        assert(url.searchParams.get('revision'));
        return text(resource.includes('/request/') ? requestReadable : recognized ? readableStream : rawStream);
      }
      if (resource.includes('/body/')) {
        const raw = resource.endsWith('/request') ? requestRaw : rawStream;
        if (url.searchParams.get('view') === 'raw') {
          const value = Buffer.from(raw); const range = route.request().headers().range;
          if (range) { const [, start, end] = range.match(/bytes=(\d+)-(\d+)/); return route.fulfill({ status: 206, contentType: 'application/octet-stream', headers: { 'Content-Range': `bytes ${start}-${Math.min(Number(end), value.length - 1)}/${value.length}` }, body: value.subarray(Number(start), Number(end) + 1) }); }
          return route.fulfill({ contentType: 'application/octet-stream', body: value });
        }
        return text(raw);
      }
      return route.fulfill({ status: 404, body: resource });
    });
    await page.goto('http://requestwatch.test');
    await page.waitForFunction(() => document.querySelector('#stat-total').textContent === '10,000');
    assert.match(await page.locator('#capture-retention').textContent(), /当前保留 10,000 条 \/ 上限 10,000 条/);
    assert.match(await page.locator('#capture-counter-note').textContent(), /升级前已淘汰/);
    captured = 10042;
    await page.waitForFunction(() => document.querySelector('#stat-total').textContent === '10,042');
    assert.equal(await page.locator('#nav-total').textContent(), '10,000');
    assert.match(await page.locator('#capture-last').textContent(), /最近捕获/);
    await page.locator('#poll-button').click();
    assert.match(await page.locator('#capture-poll-state').textContent(), /刷新已暂停/);
    await page.locator('#records-body tr').first().click();
    await page.locator('[data-tab="request"]').click();
    await page.locator('#detail-body .readable-body').waitFor();
    assert.equal(await page.locator('#http-body-format').inputValue(), 'auto');
    assert.equal(await page.locator('#detail-body .readable-body').textContent(), requestReadable);
    assert.equal(await page.locator('#detail-body img').count(), 0, 'captured markup must be rendered as text');
    await page.locator('#http-body-format').selectOption('text');
    await page.waitForFunction(raw => document.querySelector('#detail-body .full-body')?.textContent === raw, requestRaw);
    await page.locator('#edit-button').click();
    assert.equal(await page.locator('#edit-body').inputValue(), requestRaw, 'editor must use original request, never parsed text');
    await page.locator('#edit-button').click();
    await page.locator('#close-detail').click();
    await page.locator('.navigation [data-view="sessions"]').click();
    await page.locator('#sessions-body tr').first().click();
    await page.locator('#session-content .readable-body').waitFor();
    assert.equal(await page.locator('#session-format').inputValue(), 'auto');
    assert.equal(await page.locator('#session-content .readable-body').textContent(), readableStream);
    assert.match(await page.locator('[data-session-side="client"]').textContent(), /端点 A → B（方向推测）/);
    assert.match(await page.locator('#session-content').textContent(), /连接仍在采集/);
    await page.locator('#session-content .readable-body').evaluate(node => { node.scrollTop = 1000; node.dataset.identityCheck = 'keep'; });
    const contentCalls = readableRequests.length;
    await page.locator('#refresh-sessions').click();
    await page.waitForTimeout(250);
    assert.equal(readableRequests.length, contentCalls, 'unchanged snapshot must not refetch parsed content');
    assert.equal(await page.locator('#session-content .readable-body').getAttribute('data-identity-check'), 'keep', 'unchanged polling must preserve DOM and reading position');
    revision++;
    await page.locator('#refresh-sessions').click();
    await page.waitForTimeout(600);
    assert.equal(await page.locator('#session-content .readable-body').evaluate(node => node.scrollTop), 1000, 'new snapshot must preserve nested text scroll');
    fs.mkdirSync(path.join(__dirname, '..', 'artifacts'), { recursive: true });
    await page.screenshot({ path: path.join(__dirname, '..', 'artifacts', 'webui-readable-desktop.png'), fullPage: true });
    const [parsedDownload] = await Promise.all([page.waitForEvent('download'), page.locator('#session-download-readable').click()]);
    assert.equal(fs.readFileSync(await parsedDownload.path(), 'utf8'), readableStream);
    await page.locator('#session-format').selectOption('text');
    await page.waitForFunction(raw => document.querySelector('#session-content .session-full-body')?.textContent === raw, rawStream);
    const [rawDownload] = await Promise.all([page.waitForEvent('download'), page.locator('#session-download-raw').click()]);
    assert(fs.readFileSync(await rawDownload.path()).equals(Buffer.from(rawStream)));
    await page.locator('#session-format').selectOption('hex');
    await page.locator('#session-content pre.hex').waitFor();
    assert.match(await page.locator('#session-content pre.hex').textContent(), /31 37 30 0d 0a/);
    inferred = false; revision++;
    await page.locator('#refresh-sessions').click();
    await page.waitForFunction(() => document.querySelector('[data-session-side="client"]').textContent === '客户端 → 服务端');
    recognized = false; revision++;
    await page.locator('#session-format').selectOption('auto');
    await page.locator('#refresh-sessions').click();
    await page.waitForFunction(() => document.querySelector('#session-content .readable-status')?.textContent.includes('未识别'));
    assert.equal(await page.locator('#session-content .readable-body').textContent(), rawStream);
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1), false, 'mobile overflow');
    fs.mkdirSync(path.join(__dirname, '..', 'artifacts'), { recursive: true });
    await page.screenshot({ path: path.join(__dirname, '..', 'artifacts', 'webui-readable-mobile.png'), fullPage: true });
    assert.deepEqual(errors, []);
    console.log('Readable UI passed: cumulative/retained statistics, live increment above retention cap, pause status, complete parsed HTTP/TCP, safe text rendering, original editing/downloads, HEX, inferred direction, unsupported fallback, preserved reading position and mobile layout.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exit(1); });
