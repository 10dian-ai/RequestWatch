const assert = require('node:assert/strict');
const fs = require('node:fs');
async function runSettingsChecks(page, base, adminToken) {
  const authHeaders = {Authorization: `Bearer ${adminToken}`};
  const unique = `ui-settings-${Date.now()}`;
  fs.mkdirSync('artifacts', {recursive: true});
  // Every runtime setting is editable from the authenticated Web UI. Demo
  // application must never change the live listener or rotate its real token.
  await page.locator('.navigation [data-view="settings"]').click();
  await page.locator('#settings-form:not([hidden])').waitFor();
  assert(await page.locator('#settings-demo').isVisible());
  const initialSettingsResponse = await page.request.get(`${base}/api/settings`, {headers: authHeaders});
  assert(initialSettingsResponse.ok()); const initialSettings = await initialSettingsResponse.json();
  const maxRecords = Number(initialSettings.saved.max_records) + 100;
  await page.locator('#setting-max-records').fill(String(maxRecords));
  await page.locator('#setting-pending-limit').fill('129');
  await page.locator('#setting-host').fill('0.0.0.0');
  await page.locator('#setting-port').fill('17030');
  await page.locator('#setting-capture-enabled').uncheck();
  await page.locator('#setting-interfaces').fill('any');
  await page.locator('#setting-queue-num').fill('7031');
  await page.locator('#setting-protected-ports').fill('22,3306');
  await page.locator('#setting-default-timeout').fill('45');
  await page.locator('#setting-proxy-enabled').uncheck();
  await page.locator('#setting-proxy-host').fill('0.0.0.0');
  await page.locator('#setting-proxy-port').fill('18080');
  await page.locator('#setting-proxy-auth').fill(`ui-user:${unique}`);
  await page.locator('#setting-token').fill(`ui-management-${unique}`);
  await page.locator('#setting-mitmdump').fill('');
  await page.locator('#setting-tcp-idle-timeout').fill('360');
  await page.waitForTimeout(2300);
  assert.equal(await page.locator('#setting-max-records').inputValue(), String(maxRecords));
  await page.locator('#settings-save').click();
  await page.waitForFunction(() => document.querySelector('#settings-save-state').textContent.includes('等待应用'));
  assert.equal(await page.locator('#setting-token').inputValue(), '', 'Saved secrets must be cleared from inputs');
  assert.equal(await page.locator('#setting-proxy-auth').inputValue(), '');
  let settings = await (await page.request.get(`${base}/api/settings`, {headers: authHeaders})).json();
  assert.equal(settings.saved.max_records, maxRecords); assert.equal(settings.saved.port, 17030); assert.equal(settings.saved.proxy_port, 18080);
  assert.equal(settings.saved.token, undefined); assert.equal(settings.saved.proxy_auth, undefined);
  assert.equal(settings.saved.token_configured, true); assert.equal(settings.saved.proxy_auth_configured, true);
  assert(settings.pending.length > 0); assert(settings.current.port !== settings.saved.port || initialSettings.current.port === 17030);
  await page.locator('#settings-apply').click();
  await page.waitForFunction(() => document.querySelector('#settings-apply-message').textContent.includes('演示设置已模拟应用'));
  assert.equal(new URL(page.url()).port, new URL(base).port);
  assert.equal(await page.evaluate(() => sessionStorage.getItem('requestwatch-token')), adminToken, 'Demo apply must not replace the real token');
  settings = await (await page.request.get(`${base}/api/settings`, {headers: authHeaders})).json();
  assert.deepEqual(settings.pending, []); assert.equal(settings.current.max_records, maxRecords); assert.equal(settings.current.default_timeout_seconds, 45);
  // Blank secret inputs retain configured credentials on subsequent saves.
  await page.locator('#setting-max-records').fill(String(maxRecords + 100));
  await page.locator('#settings-save').click();
  await page.waitForFunction(() => document.querySelector('#settings-save-state').textContent.includes('等待应用'));
  settings = await (await page.request.get(`${base}/api/settings`, {headers: authHeaders})).json();
  assert.equal(settings.saved.proxy_auth_configured, true); assert(!settings.pending.includes('token'));
  // Clearing proxy authentication is an explicit, separately checked action.
  await page.locator('#setting-clear-proxy-auth').check();
  assert(await page.locator('#setting-proxy-auth').isDisabled());
  await page.locator('#settings-save').click();
  await page.waitForFunction(() => document.querySelector('#setting-proxy-auth-state').textContent.includes('未启用认证'));
  settings = await (await page.request.get(`${base}/api/settings`, {headers: authHeaders})).json();
  assert.equal(settings.saved.proxy_auth_configured, false);
  await page.locator('#settings-apply').click();
  await page.waitForFunction(() => document.querySelector('#settings-save-state').textContent === '设置已应用');
  await page.locator('.navigation [data-view="rules"]').click();
  await page.locator('#new-rule').click();
  assert.equal(await page.locator('#rule-timeout').inputValue(), '45', 'New rules use the Web-configured default timeout');
  await page.locator('#cancel-rule').click();
  await page.locator('.navigation [data-view="settings"]').click();
  await page.screenshot({path: 'artifacts/webui-settings-desktop.png', fullPage: true, animations: 'disabled'});
  await page.setViewportSize({width: 390, height: 844});
  await page.screenshot({path: 'artifacts/webui-settings-mobile.png', fullPage: true, animations: 'disabled'});
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1), false, 'Settings mobile document overflow');
  await page.setViewportSize({width: 1440, height: 1050});

}
module.exports = {runSettingsChecks};
if (require.main === module) {
  (async () => {
    const {chromium} = require(process.env.RW_PLAYWRIGHT_MODULE || 'playwright-core');
    const browser = await chromium.launch({headless: true, ...(process.env.RW_BROWSER_PATH ? {executablePath: process.env.RW_BROWSER_PATH} : {})});
    try {
      const page = await browser.newPage({viewport: {width: 1440, height: 1050}, deviceScaleFactor: 1});
      const errors = []; page.on('pageerror', error => errors.push(String(error)));
      const base = process.env.RW_UI_URL || 'http://127.0.0.1:7030';
      const token = process.env.RW_UI_TOKEN || 'requestwatch-local-demo-7030';
      await page.goto(base);
      await page.locator('#auth-dialog[open]').waitFor();
      await page.locator('#auth-token').fill(token); await page.locator('#login-button').click();
      await page.locator('#auth-dialog[open]').waitFor({state: 'hidden'});
      await runSettingsChecks(page, base, token);
      assert.deepEqual(errors, []);
      console.log('Web settings passed: all fields, drafts, save/apply, secret redaction/retention, explicit auth clear, demo isolation, configured rule defaults, desktop/mobile layout.');
    } finally { await browser.close(); }
  })().catch(error => { console.error(error); process.exit(1); });
}
