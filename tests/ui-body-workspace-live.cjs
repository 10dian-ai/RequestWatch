const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.RW_PLAYWRIGHT_MODULE || 'playwright-core');
// Read-only end-to-end check against existing, isolated demo captures. No data
// injection, editing, replay, rule writes, settings writes, or external traffic.
(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.RW_BROWSER_PATH ? { executablePath: process.env.RW_BROWSER_PATH } : {}) });
  try {
    const base = process.env.RW_UI_URL || 'http://127.0.0.1:7030';
    const token = process.env.RW_UI_TOKEN || 'requestwatch-local-demo-7030';
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    const errors = []; page.on('pageerror', error => errors.push(String(error)));
    const reportLayout = async label => {
      const layout = await page.evaluate(() => ({ viewport: [innerWidth, innerHeight], overflow: document.documentElement.scrollWidth > innerWidth + 1, panes: [...document.querySelectorAll('.body-pane')].map(pane => {
        const pre = pane.querySelector('.body-pane-content pre'); const toolbar = pane.querySelector('.body-pane-toolbar');
        return { side: pane.dataset.bodySide, bodyTop: pre ? Math.round(pre.getBoundingClientRect().top) : null, firstLineY: pre ? Math.round(pre.getBoundingClientRect().top + parseFloat(getComputedStyle(pre).paddingTop)) : null, toolbarHeight: toolbar ? Math.round(toolbar.getBoundingClientRect().height) : 0 };
      }) }));
      console.log(`${label}: ${JSON.stringify(layout)}`);
      fs.writeFileSync(path.join(__dirname, '..', 'artifacts', `layout-${label}.json`), JSON.stringify(layout, null, 2));
    };
    const get = async endpoint => { const response = await page.request.get(`${base}${endpoint}`, { headers: { Authorization: `Bearer ${token}` } }); assert(response.ok(), `${endpoint}: ${response.status()} ${await response.text()}`); return response; };
    const status = await (await get('/api/status')).json(); assert.equal(status.mode, 'demo'); assert.equal(status.passive_only, true);
    const packets = (await (await get('/api/records?protocol=TCP&limit=200')).json()).items;
    const packet = packets.find(item => item.tcp_session_id && item.payload_size > 0); assert(packet, 'existing TCP demo fixture required');
    const detail = await (await get(`/api/records/${packet.id}`)).json(); assert.equal(detail.tcp_session_available, true);
    const sessionId = detail.tcp_session_id;
    const expected = {};
    for (const side of ['client', 'server']) {
      const meta = await (await get(`/api/sessions/${sessionId}/readable/${side}`)).json();
      expected[side] = { parsed: await (await get(meta.content_url)).text(), text: await (await get(`/api/sessions/${sessionId}/body/${side}?view=text`)).text(), raw: await (await get(`/api/sessions/${sessionId}/body/${side}?view=raw`)).body() };
    }
    await page.addInitScript(value => sessionStorage.setItem('requestwatch-token', value), token);
    await page.goto(base); await page.locator('#records-body tr').first().waitFor(); await page.locator('#poll-button').click();
    await page.locator('#filter-protocol').selectOption('TCP'); await page.locator(`#records-body tr[data-id="${packet.id}"] .event-detail-button`).click();
    await page.waitForFunction(() => document.querySelectorAll('.body-workspace .inline-tcp-body').length === 2);
    for (const side of ['client', 'server']) assert.equal(await page.locator(`[data-body-side="${side}"] .inline-tcp-body`).textContent(), expected[side].parsed, `${side} parsed content must match the complete real API snapshot`);
    assert(expected.client.text.length > packet.payload_size, 'opened packet must show other packets in the same connection');
    assert(expected.client.text.includes('TCP-DEMO-END'), 'large client fixture tail');
    assert.equal(await page.locator('#edit-button').isVisible(), false); assert.equal(await page.locator('#replay-button').isVisible(), false);
    for (const side of ['client', 'server']) {
      await page.locator(`#inline-tcp-${side}-format`).selectOption('text');
      await page.waitForFunction(({ side, text }) => document.querySelector(`[data-body-side="${side}"] .inline-tcp-body`)?.textContent === text, { side, text: expected[side].text });
    }
    await page.locator('[data-body-side="server"] .body-download-menu > summary').click();
    const [download] = await Promise.all([page.waitForEvent('download'), page.locator('[data-body-side="server"]').getByRole('button', { name: '下载全部原始字节', exact: true }).click()]);
    assert(fs.readFileSync(await download.path()).equals(expected.server.raw), 'real TCP raw download must be byte-exact');
    fs.mkdirSync(path.join(__dirname, '..', 'artifacts'), { recursive: true });
    await page.locator('#toast').evaluate(node => { node.hidden = true; }); await page.locator('#record-detail-drawer').evaluate(node => { node.scrollTop = 0; });
    await reportLayout('live-tcp-desktop');
    await page.screenshot({ path: path.join(__dirname, '..', 'artifacts', 'webui-body-live-tcp.png'), animations: 'disabled' });
    await page.locator('#close-detail').click();
    const httpItems = (await (await get('/api/records?source=http&state=forwarded&limit=200')).json()).items;
    const http = httpItems.find(item => item.request_body_size > 0 && item.response_body_size > 0); assert(http, 'existing HTTP demo fixture required');
    await page.locator('#filter-protocol').selectOption(''); await page.locator('#filter-query').fill(http.url);
    await page.locator(`#records-body tr[data-id="${http.id}"] .event-detail-button`).click();
    await page.waitForFunction(() => document.querySelectorAll('.body-workspace .readable-body').length === 2);
    for (const side of ['request', 'response']) {
      const meta = await (await get(`/api/records/${http.id}/readable/${side}`)).json(); const text = await (await get(meta.content_url)).text();
      assert.equal(await page.locator(`[data-body-side="${side}"] .readable-body`).textContent(), text, `${side} full body from real API`);
    }
    assert.equal(await page.locator('[data-tab="content"]').getAttribute('aria-selected'), 'true');
    assert.equal(await page.locator('#edit-button').isVisible(), false);
    const cdp = await page.context().newCDPSession(page);
    await cdp.send('DOM.enable'); await cdp.send('CSS.enable');
    const document = await cdp.send('DOM.getDocument');
    const node = await cdp.send('DOM.querySelector', { nodeId: document.root.nodeId, selector: '[data-body-side="request"] .readable-body' });
    const fonts = await cdp.send('CSS.getPlatformFontsForNode', { nodeId: node.nodeId });
    console.log('Actual body platform fonts: ' + JSON.stringify(fonts.fonts));
    if (process.platform === 'win32') assert(!fonts.fonts.some(font => /simsun|simsong|times new roman/i.test(font.familyName)), 'Chinese body text must use a readable sans-serif fallback');
    fs.writeFileSync(path.join(__dirname, '..', 'artifacts', 'webui-body-fonts.json'), JSON.stringify(fonts.fonts, null, 2));
    await reportLayout('live-http-desktop');
    await page.screenshot({ path: path.join(__dirname, '..', 'artifacts', 'webui-body-live-http.png'), animations: 'disabled' });
    assert.deepEqual(errors, []);
    console.log(`Read-only live body workspace passed: real HTTP request/response and TCP client ${expected.client.raw.length} / server ${expected.server.raw.length} bytes; both directions match complete API, large tail visible, raw download exact, editing/replay hidden. No server data changed.`);
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exit(1); });
