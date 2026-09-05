const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require(process.env.RW_PLAYWRIGHT_MODULE || 'playwright-core');
(async () => {
  const browser = await chromium.launch({headless: true, ...(process.env.RW_BROWSER_PATH ? {executablePath: process.env.RW_BROWSER_PATH} : {})});
  const page = await browser.newPage({viewport: {width: 1440, height: 1050}, deviceScaleFactor: 1});
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  const base = process.env.RW_UI_URL || 'http://127.0.0.1:7030';
  const adminToken = process.env.RW_UI_TOKEN || 'requestwatch-local-demo-7030';
  const authHeaders = {Authorization: `Bearer ${adminToken}`};
  await page.goto(base);
  await page.locator('#auth-dialog[open]').waitFor();
  await page.locator('#auth-token').fill('wrong-token');
  await page.locator('#login-button').click();
  await page.locator('#auth-error:not([hidden])').waitFor();
  await page.locator('#auth-token').fill(adminToken);
  await page.locator('#login-button').click();
  await page.locator('#auth-dialog[open]').waitFor({state: 'hidden'});
  await page.locator('#records-body tr').first().waitFor();
  assert(await page.locator('#demo-badge').isVisible());
  await page.locator('#filter-query').fill('ORD-2048');
  await page.waitForFunction(() => !document.querySelector('#record-count').textContent.includes('加载') && document.querySelectorAll('#records-body tr').length === 2);
  await page.locator('#records-body tr').filter({hasText: 'POST'}).first().click();
  await page.locator('#edit-button').click();
  await page.locator('#edit-body').fill('界面草稿保留验证');
  await page.waitForTimeout(2300);
  assert.equal(await page.locator('#edit-body').inputValue(), '界面草稿保留验证');
  await page.locator('#replay-button').click();
  await page.locator('#confirm-ok').click();
  await page.waitForFunction(() => document.querySelector('#detail-state').textContent.includes('已重发'));
  await page.locator('[data-tab="request"]').click();
  await page.waitForFunction(() => document.querySelector('#detail-body .full-body')?.textContent.includes('界面草稿保留验证'));
  await page.locator('.navigation [data-view="rules"]').click();
  await page.locator('#new-rule').click();
  await page.locator('#rule-name').fill('UI 验证 · 待审请求');
  await page.locator('#rule-source').selectOption('http');
  await page.locator('#rule-protocol').selectOption('HTTPS');
  await page.locator('#rule-keyword').fill('ui-probe');
  await page.locator('#rule-timeout').fill('120');
  await page.locator('#save-rule').click();
  await page.locator('#rule-dialog[open]').waitFor({state: 'hidden'});
  await page.locator('#generate-demo-request').click();
  await page.locator('#pending-actions:not([hidden])').waitFor();
  await page.locator('#edit-button').click();
  await page.locator('#edit-body').fill('UI 已批准');
  await page.locator('#accept-button').click();
  await page.waitForFunction(() => document.querySelector('#detail-state').textContent.includes('已放行'));
  await page.locator('[data-tab="request"]').click();
  await page.waitForFunction(() => document.querySelector('#detail-body .full-body')?.textContent.includes('UI 已批准'));
  await page.locator('.navigation [data-view="rules"]').click();
  await page.locator('#generate-demo-request').click();
  await page.locator('#pending-actions:not([hidden])').waitFor();
  await page.locator('#drop-button').click();
  if (await page.locator('#confirm-dialog').isVisible()) await page.locator('#confirm-ok').click();
  await page.waitForFunction(() => document.querySelector('#detail-state').textContent.includes('已丢弃'));

  // Bodies larger than the former 1 MiB cap must be searchable, fully visible,
  // editable without truncation, and downloaded with every byte intact.
  const unique = `ui-complete-${Date.now()}`;
  const requestTail = `\n${unique}-request-tail`;
  const responseTail = `\n${unique}-response-tail`;
  const fullRequest = 'x'.repeat(2 * 1024 * 1024) + requestTail;
  const fullResponse = 'y'.repeat(3 * 1024 * 1024) + responseTail;
  const inserted = await page.request.post(`${base}/api/internal/ingest`, {headers: authHeaders, data: {
    source: 'http', protocol: 'HTTP', method: 'POST', url: 'http://fixture.invalid/complete-content', state: 'captured',
    request_headers: [['Content-Type', 'text/plain; charset=utf-8'], ['X-Complete-Header', unique]],
    request_body_text: fullRequest, request_body_size: Buffer.byteLength(fullRequest), request_body_binary: false,
    src_ip: '127.0.0.1', src_port: 45678, dst_ip: '127.0.0.1', dst_port: 80
  }});
  assert(inserted.ok(), await inserted.text());
  const recordId = (await inserted.json()).id;
  const responseSaved = await page.request.put(`${base}/api/internal/records/${recordId}`, {headers: authHeaders, data: {
    state: 'forwarded', status_code: 200, response_headers: [['Content-Type', 'text/plain; charset=utf-8']],
    response_body_text: fullResponse, response_body_size: Buffer.byteLength(fullResponse), response_body_binary: false
  }});
  assert(responseSaved.ok(), await responseSaved.text());
  await page.locator('.navigation [data-view="traffic"]').click();
  await page.locator('#reset-filters').click();
  await page.locator('#filter-query').fill(`${unique}-request-tail`);
  await page.waitForFunction(id => document.querySelectorAll('#records-body tr').length === 1 && document.querySelector('#records-body tr').dataset.id === id, recordId);
  const unavailableBody = url => url.pathname === `/api/records/${recordId}/body/request` && url.searchParams.get('view') === 'text';
  await page.route(unavailableBody, route => route.fulfill({status: 503, contentType: 'application/json', body: JSON.stringify({detail: 'UI fixture: temporary body read failure'})}));
  await page.locator(`#records-body tr[data-id="${recordId}"]`).click();
  await page.locator('[data-tab="request"]').click();
  await page.locator('#http-body-format').selectOption('text');
  await page.waitForFunction(() => document.querySelector('#detail-body').textContent.includes('完整正文加载失败'));
  assert(await page.locator('#edit-button').isDisabled(), 'Failed complete-body load must not allow preview-only editing');
  await page.unroute(unavailableBody);
  await page.locator('#detail-body').getByRole('button', {name: '重新读取'}).click();
  await page.waitForFunction(tail => document.querySelector('#detail-body .full-body')?.textContent.endsWith(tail), requestTail);
  assert.equal(await page.locator('#detail-body .full-body').textContent(), fullRequest);
  assert((await page.locator('#detail-body').textContent()).includes('原始正文完整保存'));
  const fullBodyNode = await page.locator('#detail-body .full-body').elementHandle();
  const readingOffset = await fullBodyNode.evaluate(node => { node.scrollTop = node.scrollHeight; return node.scrollTop; });
  await page.waitForTimeout(2300);
  assert(await fullBodyNode.evaluate(node => node.isConnected), 'Polling must preserve the full-body DOM and selection');
  assert.equal(await fullBodyNode.evaluate(node => node.scrollTop), readingOffset, 'Polling must preserve the full-body reading position');
  const [httpFile] = await Promise.all([page.waitForEvent('download'), page.locator('#message-download').click()]);
  const httpBytes = fs.readFileSync(await httpFile.path());
  assert(httpBytes.toString().includes(`X-Complete-Header: ${unique}`));
  assert(httpBytes.subarray(-Buffer.byteLength(fullRequest)).equals(Buffer.from(fullRequest)));
  const [rawFile] = await Promise.all([page.waitForEvent('download'), page.locator('#body-download').click()]);
  assert(fs.readFileSync(await rawFile.path()).equals(Buffer.from(fullRequest)));
  await page.locator('[data-tab="hex"]').click();
  const lastPage = Math.ceil(Buffer.byteLength(fullRequest) / 4096);
  await page.locator('#hex-page').fill(String(lastPage)); await page.locator('#hex-page').press('Tab');
  await page.waitForFunction(() => Boolean(document.querySelector('#detail-body pre.hex')));
  assert((await page.locator('#detail-body pre.hex').textContent()).startsWith(((lastPage - 1) * 4096).toString(16).padStart(8, '0')));
  assert(await page.locator('#hex-next').isDisabled());
  await page.locator('[data-tab="response"]').click();
  await page.waitForFunction(tail => document.querySelector('#detail-body .full-body')?.textContent.endsWith(tail), responseTail);
  assert.equal(await page.locator('#detail-body .full-body').textContent(), fullResponse);
  const [responseFile] = await Promise.all([page.waitForEvent('download'), page.locator('#message-download').click()]);
  assert(fs.readFileSync(await responseFile.path()).subarray(-Buffer.byteLength(fullResponse)).equals(Buffer.from(fullResponse)));
  await page.locator('[data-tab="request"]').click();
  await page.locator('#edit-button').click();
  assert.equal(await page.locator('#edit-body').inputValue(), fullRequest);
  const fullEdited = `${fullRequest}\nlarge-edited-tail`;
  await page.locator('#edit-body').fill(fullEdited);
  await page.waitForTimeout(2300);
  assert.equal(await page.locator('#edit-body').inputValue(), fullEdited);
  await page.locator('#replay-button').click(); await page.locator('#confirm-ok').click();
  await page.waitForFunction(() => document.querySelector('#detail-state').textContent.includes('已重发'));
  const replayId = await page.locator('#detail-id').getAttribute('title');
  const replayBody = await page.request.get(`${base}/api/records/${replayId}/body/request?view=raw`, {headers: authHeaders});
  assert(replayBody.ok()); assert((await replayBody.body()).equals(Buffer.from(fullEdited)));
  await page.locator('#filter-query').fill(`${unique}-response-tail`);
  await page.waitForFunction(id => Array.from(document.querySelectorAll('#records-body tr')).some(row => row.dataset.id === id), recordId);

  // The optional fixture is generated by the packet parser/reassembler, so this
  // exercises real session endpoints rather than mocked browser responses.
  if (process.env.RW_UI_SESSION_ID) {
    const sessionId = process.env.RW_UI_SESSION_ID;
    const sessionResponse = await page.request.get(`${base}/api/sessions/${sessionId}`, {headers: authHeaders});
    assert(sessionResponse.ok());
    const session = await sessionResponse.json();
    const clientBody = await page.request.get(`${base}/api/sessions/${sessionId}/body/client?view=text`, {headers: authHeaders});
    const serverBody = await page.request.get(`${base}/api/sessions/${sessionId}/body/server?view=text`, {headers: authHeaders});
    const clientText = await clientBody.text(); const serverText = await serverBody.text();
    assert(clientText.length > 65536, 'TCP fixture must span many packets and HEX pages');
    await page.locator('.navigation [data-view="sessions"]').click();
    await page.locator('#session-query').fill(process.env.RW_UI_SESSION_MARKER || clientText.slice(-24));
    await page.locator(`#sessions-body tr[data-id="${sessionId}"]`).waitFor();
    await page.locator(`#sessions-body tr[data-id="${sessionId}"]`).click();
    await page.locator('#session-format').selectOption('text');
    await page.waitForFunction(tail => document.querySelector('#session-content .session-full-body')?.textContent.endsWith(tail), clientText.slice(-24));
    assert.equal(await page.locator('#session-content .session-full-body').textContent(), clientText);
    await page.locator('[data-session-side="server"]').click();
    await page.waitForFunction(tail => document.querySelector('#session-content .session-full-body')?.textContent.endsWith(tail), serverText.slice(-24));
    assert.equal(await page.locator('#session-content .session-full-body').textContent(), serverText);
    await page.locator('[data-session-side="client"]').click();
    const [tcpFile] = await Promise.all([page.waitForEvent('download'), page.locator('#session-download-raw').click()]);
    const rawClient = await page.request.get(`${base}/api/sessions/${sessionId}/body/client?view=raw`, {headers: authHeaders});
    assert(fs.readFileSync(await tcpFile.path()).equals(await rawClient.body()));
    await page.locator('#session-format').selectOption('hex');
    const lastTcpPage = Math.ceil(session.directions.client.byte_count / 4096);
    await page.locator('#session-hex-page').fill(String(lastTcpPage)); await page.locator('#session-hex-page').press('Tab');
    await page.waitForFunction(() => Boolean(document.querySelector('#session-content pre.hex')));
    assert((await page.locator('#session-content pre.hex').textContent()).startsWith(((lastTcpPage - 1) * 4096).toString(16).padStart(8, '0')));
    assert(await page.locator('#session-hex-next').isDisabled());
    await page.locator('#session-container').selectOption(session.container_id || '');
    await page.locator(`#sessions-body tr[data-id="${sessionId}"]`).waitFor();
    const warnings = await page.locator('#session-alert').textContent();
    if (session.midstream) assert(warnings.includes('中途'));
    if (session.directions.client.gap_count || session.directions.server.gap_count) assert(warnings.includes('缺口已省略'));
    await page.locator('[data-session-side="server"]').click();
    await page.locator('#session-format').selectOption('text');
    await page.waitForFunction(tail => document.querySelector('#session-content .session-full-body')?.textContent.endsWith(tail), serverText.slice(-24));
    fs.mkdirSync('artifacts', {recursive: true});
    await page.screenshot({path: 'artifacts/webui-tcp-desktop.png', fullPage: true});
    await page.setViewportSize({width: 390, height: 844});
    await page.screenshot({path: 'artifacts/webui-tcp-mobile.png', fullPage: true});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1), false, 'TCP mobile document overflow');
    await page.setViewportSize({width: 1440, height: 1050});
  }


  await require('./ui-settings.cjs').runSettingsChecks(page, base, adminToken);

  await page.locator('.navigation [data-view="containers"]').click();
  await page.locator('.container-card').first().waitFor();
  assert.equal(await page.locator('.container-card').count(), 2);
  await page.locator('.navigation [data-view="traffic"]').click();
  await page.locator('#reset-filters').click();
  await page.locator('#records-body tr').first().waitFor();
  await page.locator('#records-body tr').filter({hasText: '/v1/orders'}).first().click();
  await page.locator('[data-tab="response"]').click();
  fs.mkdirSync('artifacts', {recursive: true});
  await page.waitForTimeout(5200);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({path: 'artifacts/webui-desktop.png', fullPage: true});
  await page.setViewportSize({width: 390, height: 844});
  await page.screenshot({path: 'artifacts/webui-mobile.png', fullPage: true});
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
  assert.equal(overflow, false, 'Mobile document overflow');
  const guide = page.locator('.mobile-guide-link');
  if (await guide.count()) { await guide.click(); await page.locator('#view-guide:not([hidden])').waitFor(); }
  assert.deepEqual(errors, [], 'Unexpected browser errors');
  console.log('WebUI passed: authentication, full 2 MiB request / 3 MiB response, tail search, complete downloads, HEX pagination, full-body editing/replay, preserved drafts, rules, accept/drop, all Web settings, secret retention/clear, demo apply, containers, responsive layout' + (process.env.RW_UI_SESSION_ID ? ', TCP bidirectional full stream / download / HEX.' : '. TCP fixture not configured.'));
  await browser.close();
})().catch(error => { console.error(error); process.exit(1); });
