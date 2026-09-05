/* Focused browser regression: failed restart restores authentication and UI state.
 * All APIs are mocked; no running RequestWatch instance or real restart is used.
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const {chromium} = require(process.env.RW_PLAYWRIGHT_MODULE || 'playwright-core');
(async () => {
  const files = {'/': ['index.html', 'text/html'], '/app.js': ['app.js', 'text/javascript'], '/app.css': ['app.css', 'text/css']};
  const server = http.createServer((request, response) => {
    const file = files[new URL(request.url, 'http://localhost').pathname];
    if (!file) { response.writeHead(404); response.end(); return; }
    response.writeHead(200, {'Content-Type': file[1]}); response.end(fs.readFileSync(path.join(__dirname, '..', 'requestwatch', 'static', file[0])));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port; const base = `http://127.0.0.1:${port}`;
  const oldToken = 'ui-recovery-original-token'; const newToken = 'ui-recovery-replacement-token';
  const browser = await chromium.launch({headless: true, ...(process.env.RW_BROWSER_PATH ? {executablePath: process.env.RW_BROWSER_PATH} : {})});
  try {
    for (const scenario of ['existing-rollback', 'rollback', 'success', 'new-origin']) {
      const page = await browser.newPage();
      const errors = []; page.on('pageerror', error => errors.push(String(error)));
      await page.addInitScript(value => sessionStorage.setItem('requestwatch-token', value), oldToken);
      let applied = false; let saved = false; let authenticatedSettingsReads = 0;
      const current = {host: '127.0.0.1', port, token_configured: true, capture_enabled: false, interfaces: 'any', queue_num: 7030, protected_ports: [22], pending_limit: 128, default_timeout_seconds: 30, proxy_enabled: false, proxy_host: '127.0.0.1', proxy_port: port === 8080 ? 8081 : 8080, proxy_auth_configured: false, mitmdump: '', max_records: 10000, tcp_idle_timeout: 300};
      const targetPort = scenario === 'new-origin' ? (port < 65535 ? port + 1 : port - 1) : port;
      const payload = () => ({current, saved: {...current, port: saved ? targetPort : port}, pending: saved && !applied ? (targetPort === port ? ['token'] : ['token', 'port']) : [], restart_supported: true, instance_id: applied ? 'after-restart' : 'before-restart', restart_rollback: scenario === 'existing-rollback' || (applied && scenario === 'rollback'), demo: false, settings_path: '/tmp/test/settings.json', data_dir: '/tmp/test', interfaces: ['lo']});
      await page.route('**/api/**', async route => {
        const request = route.request(); const url = new URL(request.url());
        const send = value => route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(value)});
        if (url.pathname === '/api/status') return send({mode: 'live', port, proxy_port: current.proxy_port, stats: {}, capture: {}, proxy: {}, docker: {}, protected_ports: [22, port]});
        if (url.pathname === '/api/containers') return send({items: [], status: {state: 'available'}});
        if (url.pathname === '/api/settings' && request.method() === 'GET') {
          const expectedToken = applied && scenario === 'success' ? newToken : oldToken;
          assert.equal(request.headers().authorization, `Bearer ${expectedToken}`, `${scenario}: settings must use the token of the running configuration`);
          if (applied) authenticatedSettingsReads++;
          return send(payload());
        }
        if (url.pathname === '/api/settings' && request.method() === 'PUT') {
          assert.equal(request.postDataJSON().token, newToken); saved = true; return send(payload());
        }
        if (url.pathname === '/api/settings/apply') {
          assert.equal(request.headers().authorization, `Bearer ${oldToken}`);
          applied = true; return send({ok: true, restarting: true, demo: false, next: {host: '127.0.0.1', port: targetPort, token_changed: true}, instance_id: 'before-restart'});
        }
        return send({items: [], total: 0});
      });
      await page.route('**/healthz', route => route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify({status: 'ok', instance_id: applied ? 'after-restart' : 'before-restart', restart_rollback: scenario === 'rollback'})}));
      await page.goto(`${base}/#settings`); await page.locator('#settings-form:not([hidden])').waitFor();
      assert((await page.locator('.settings-actions').textContent()).includes('重启服务会短暂断开当前流量'));
      if (scenario === 'existing-rollback') {
        assert(await page.locator('#settings-rollback').isVisible());
        assert((await page.locator('#settings-save-state').textContent()).includes('已回退配置'));
      } else {
        await page.locator('#setting-token').fill(newToken);
        if (scenario === 'new-origin') await page.locator('#setting-port').fill(String(targetPort));
        await page.locator('#settings-save').click();
        await page.waitForFunction(() => document.querySelector('#settings-save-state').textContent.includes('等待应用'));
        await page.locator('#settings-apply').click();
        if (scenario === 'new-origin') {
          await page.locator('#settings-recovery-help:not([hidden])').waitFor();
          assert((await page.locator('#settings-recovery-help').textContent()).includes('恢复原地址和原令牌'));
          assert.equal(await page.locator('#settings-original-link').getAttribute('href'), `${base}/#settings`);
          assert.equal(new URL(await page.locator('#settings-next-link').getAttribute('href')).port, String(targetPort));
          assert(!(await page.locator('#settings-apply-result').textContent()).includes(newToken));
          assert.equal(await page.evaluate(() => sessionStorage.getItem('requestwatch-token')), oldToken);
        } else {
          const expected = scenario === 'rollback' ? '自动回退到上次可用配置' : '新设置已生效';
          await page.waitForFunction(text => document.querySelector('#settings-apply-message').textContent.includes(text), expected);
          assert(authenticatedSettingsReads > 0);
          assert.equal(await page.evaluate(() => sessionStorage.getItem('requestwatch-token')), scenario === 'rollback' ? oldToken : newToken);
          assert.equal(await page.locator('#settings-rollback').isVisible(), scenario === 'rollback');
          if (scenario === 'rollback') assert(!(await page.locator('#settings-apply-message').textContent()).includes('新设置已生效'));
        }
      }
      assert.deepEqual(errors, []); await page.close();
    }
    console.log('Restart UI recovery passed: persisted rollback notice, same-origin token restore, successful token rotation, cross-origin original-address recovery link.');
  } finally { await browser.close(); await new Promise(resolve => server.close(resolve)); }
})().catch(error => { console.error(error); process.exit(1); });
