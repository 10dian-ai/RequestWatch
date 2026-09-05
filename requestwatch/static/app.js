/* RequestWatch console. Captured network content is rendered only as text. */
'use strict';

(() => {
  const $ = (id) => document.getElementById(id);
  const stateNames = { captured: '已捕获', pending: '等待处理', resolving: '处理中', forwarded: '已放行', dropped: '已丢弃', error: '错误', replayed: '已重发' };
  const titles = { traffic: '网络流量', pending: '拦截队列', rules: '拦截规则', containers: 'Docker 容器', sessions: 'TCP 会话', settings: '项目设置', guide: '接入指南' };
  const s = { view: 'traffic', status: null, records: [], containers: [], rules: [], selected: null, selectedId: null, tab: 'content', polling: true, authenticated: true, refreshing: false, refreshAgain: false, offset: 0, limit: 50, total: 0, requestVersion: 0, detailVersion: 0, detailLoaded: false, detailLoading: false, detailError: '', editing: false, draftOriginal: null, actionBusy: false, lastInventory: 0 };
  let token = '';
  try { token = sessionStorage.getItem('requestwatch-token') || ''; } catch (_) { /* Session storage can be unavailable in hardened browsers. */ }
  let searchTimer;
  let toastTimer;
  let confirmResolve;
  const bodyCache = new Map();
  const hexCache = new Map();
  const readableCache = new Map();
  const readingPositions = new Map();
  s.bodyFormat = { request: 'auto', response: 'auto' };
  const HEX_PAGE_BYTES = 4096;
  s.hexSide = 'request'; s.hexPage = 0;
  Object.assign(s, { sessions: [], sessionTotal: 0, sessionOffset: 0, sessionSelected: null, sessionId: null, sessionSide: 'client', sessionFormat: 'auto', sessionHexPage: 0, sessionVersion: 0 });
  const sessionBodyCache = new Map();
  let recordSession = null;
  const recordSessionBodies = new Map();
  const recordSessionFormats = { client: 'auto', server: 'auto' };
  const paneSearchValues = new Map();
  let sessionSearchTimer;
  const settingsState = { data: null, dirty: false, saving: false, applying: false, pendingToken: '', restartDone: false };
  const settingNames = { host: 'Web 监听地址', port: '工作台端口', token: '管理令牌', passive_only: '只读观察', capture_enabled: '抓包开关', interfaces: '网卡', queue_num: 'NFQUEUE 队列', protected_ports: '保护端口', pending_limit: '暂停容量', default_timeout_seconds: '规则默认等待', proxy_enabled: '代理开关', proxy_host: '代理地址', proxy_port: '代理端口', proxy_auth: '代理认证', mitmdump: 'mitmdump 路径', max_records: '保留记录数', tcp_idle_timeout: 'TCP 空闲超时' };

  function element(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }
  function message(id, text, variant) {
    const target = $(id);
    target.textContent = text || '';
    target.hidden = !text;
    if (variant) target.className = `notice ${variant}`;
  }
  function toast(text, error = false) {
    clearTimeout(toastTimer);
    $('toast').textContent = text;
    $('toast').className = `toast${error ? ' error' : ''}`;
    $('toast').hidden = false;
    toastTimer = setTimeout(() => { $('toast').hidden = true; }, 5000);
  }
  function storeToken(value) {
    token = value;
    try { if (value) sessionStorage.setItem('requestwatch-token', value); else sessionStorage.removeItem('requestwatch-token'); } catch (_) { /* Keep in memory for this page if unavailable. */ }
  }
  function connection(kind, text) {
    const node = $('connection');
    node.className = `connection ${kind}`;
    node.replaceChildren(element('i'), document.createTextNode(text));
  }
  function openAuth(error = '') {
    message('auth-error', error);
    $('auth-token').value = token;
    if (!$('auth-dialog').open) $('auth-dialog').showModal();
  }
  async function api(path, options = {}) {
    const controller = new AbortController();
    const isReplay = options.method === 'POST' && /^\/api\/records\/[^/]+\/replay$/.test(path);
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs || (isReplay ? 60000 : 15000));
    const headers = { ...options.headers };
    if (token) headers.Authorization = `Bearer ${token}`;
    if (options.body !== undefined) headers['Content-Type'] = 'application/json';
    try {
      const response = await fetch(path, { ...options, headers, signal: controller.signal, cache: 'no-store' });
      if (!response.ok) {
        let detail = `${response.status} ${response.statusText}`;
        try {
          const payload = await response.json();
          const data = payload.detail || payload.error || payload.message;
          detail = typeof data === 'string' ? data : JSON.stringify(data || payload);
        } catch (_) { /* Preserve HTTP status for non-JSON responses. */ }
        const error = new Error(detail);
        error.status = response.status;
        if (response.status === 401 || response.status === 403) {
          s.authenticated = false;
          connection('offline', '需要授权');
          openAuth(response.status === 403 ? '当前令牌没有访问权限，请检查服务端令牌配置。' : '访问令牌无效或未设置，请重新连接。');
        }
        throw error;
      }
      if (response.status === 204) return null;
      if (options.responseType === 'text') return await response.text();
      if (options.responseType === 'bytes') return { data: new Uint8Array(await response.arrayBuffer()), status: response.status, range: response.headers.get('Content-Range') };
      return options.download ? response : await response.json();
    } catch (error) {
      if (error.name === 'AbortError' || error instanceof TypeError) {
        const message = isReplay
          ? '重发结果尚未确认。请求可能已发送且仍在处理，请先查看网络流量中的重发记录，避免重复发送。'
          : error.name === 'AbortError' ? '服务器响应超时，请检查连接后重试。' : '无法连接服务器，请检查 RequestWatch 服务是否在运行。';
        const connectionError = new Error(message);
        connectionError.outcomeUnknown = isReplay;
        throw connectionError;
      }
      throw error;
    } finally { clearTimeout(timeout); }
  }
  function bytes(value) {
    const n = Number(value) || 0;
    return n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`;
  }
  function time(value, full = false) {
    if (!value) return '—';
    const date = typeof value === 'number' ? new Date(value * 1000) : new Date(value);
    if (Number.isNaN(date.getTime())) return '—';
    return full ? date.toLocaleString('zh-CN', { hour12: false }) : date.toLocaleTimeString('zh-CN', { hour12: false });
  }
  function endpoint(ip, port) { return `${ip || '未知'}${port !== undefined && port !== null ? `:${port}` : ''}`; }
  function recordTitle(record) {
    if (record.source === 'http') {
      let path = record.url || record.summary || 'HTTP 请求';
      try { const url = new URL(record.url); path = url.pathname + url.search; } catch (_) { /* Relative or unusual URLs remain visible. */ }
      return `${record.method || 'HTTP'} ${path}`;
    }
    return record.summary || `${record.protocol || '网络包'} → ${endpoint(record.dst_ip, record.dst_port)}`;
  }
  function targetAddress(record) {
    if (record.url) { try { return new URL(record.url).host; } catch (_) { return record.url; } }
    return `${endpoint(record.src_ip, record.src_port)} → ${endpoint(record.dst_ip, record.dst_port)}`;
  }
  function badge(text, type) { return element('span', text, `badge ${type || ''}`); }
  function protocolBadge(record) { return badge(record.protocol || record.source || '—', `protocol-${String(record.protocol).toLowerCase()}`); }
  function recordStateBadge(record) { return badge(stateNames[record.state] || record.state || '未知', `state-${record.state}`); }
  function engineInfo(value) {
    if (!value) return { good: false, label: '未启用' };
    if (typeof value === 'string') return { good: ['running', 'connected', 'ready', 'active', 'available'].includes(value), label: value };
    const raw = value.state || value.status;
    if ('capture_running' in value) return { good: value.capture_running || value.interception_running, label: value.capture_running ? (value.interception_running ? '抓包 + 拦截' : '仅抓包') : value.interception_running ? '拦截运行中' : '未启动', detail: [value.capture_error, value.interception_error].filter(Boolean).join('；') };
    const good = value.running === true || value.connected === true || value.available === true || ['running', 'connected', 'ready', 'active', 'available'].includes(raw);
    const names = { running: '运行中', connected: '已连接', ready: '就绪', active: '运行中', available: '可用', disabled: '未启用', stopped: '未启动', unavailable: '不可用', error: '异常', demo: '演示数据', starting: '启动中' };
    return { good: Boolean(good && !value.error), label: value.error ? '异常' : names[raw] || (good ? '运行中' : value.enabled === false ? '未启用' : '未连接'), detail: value.error || value.message || value.reason || value.detail || '' };
  }
  function renderStatus(status) {
    s.status = status;
    syncReadOnlyActions();
    const stats = status.stats || {};
    ['pending', 'http', 'packets'].forEach((key) => { $(`stat-${key}`).textContent = Number(stats[key] || 0).toLocaleString('zh-CN'); });
    $('stat-total').textContent = Number(stats.captured_total ?? stats.total ?? 0).toLocaleString('zh-CN');
    renderCaptureSummary();
    $('nav-total').textContent = Number(stats.retained ?? stats.total ?? 0).toLocaleString('zh-CN');
    $('nav-pending').textContent = stats.pending || 0;
    $('demo-badge').hidden = status.mode !== 'demo';
    $('demo-rule-tools').hidden = status.mode !== 'demo' || status.passive_only === true;
    $('demo-notice').hidden = status.mode !== 'demo';
    $('server-port').textContent = `:${status.port || 7030}`;
    ['capture', 'proxy', 'docker'].forEach((key) => {
      const info = engineInfo(status[key]);
      $(`${key}-state`).textContent = info.label;
      $(`${key}-state`).title = info.detail || info.label;
      $(`${key}-dot`).className = `engine-dot ${info.good ? 'online' : 'offline'}`;
    });
    const droppedPackets = Number(status.capture?.passive_dropped || 0);
    message('capture-loss-alert', droppedPackets > 0 ? `采集程序曾落后，${droppedPackets.toLocaleString('zh-CN')} 个抓包副本未保存，查看内容可能有缺口；原连接没有因此丢包。` : '', 'warning');
    $('guide-proxy-env').textContent = `HTTP_PROXY=http://<服务器IP>:${status.proxy_port || 8080}\nHTTPS_PROXY=http://<服务器IP>:${status.proxy_port || 8080}`;
    $('protected-ports').textContent = (status.protected_ports || [22, 7030, 8080]).join('、');
    $('runtime-summary').textContent = `工作台 :${status.port || 7030} · HTTP 代理 :${status.proxy_port || 8080} · ${status.mode === 'demo' ? '演示模式' : '实时模式'}。抓包：${engineInfo(status.capture).detail || engineInfo(status.capture).label}；代理：${engineInfo(status.proxy).detail || engineInfo(status.proxy).label}。`;
    connection('online', '服务已连接');
  }
  function isReadOnly() { return s.status?.passive_only === true; }
  function syncReadOnlyActions() {
    const readonly = isReadOnly();
    document.querySelectorAll('.navigation [data-view="pending"], .navigation [data-view="rules"]').forEach(node => { node.hidden = readonly; });
    $('stat-pending').closest('.stat').hidden = readonly;
    const footnote = document.querySelector('#view-traffic .workspace-footnote > span:first-child');
    if (footnote) footnote.textContent = readonly ? '只读观察 · 不暂停、不修改、不重发网络流量' : '按规则拦截 · 超时策略由服务端控制';
    $('edit-button').hidden = readonly;
    $('pending-actions').parentElement.hidden = readonly;
    $('action-help').hidden = readonly;
    if (s.view === 'traffic') $('traffic-subtitle').textContent = readonly ? '只读查看网络请求、响应正文和 TCP 双向通信。' : '查看每一次连接，按规则暂停，在放行前检查与修改。';
    message('rules-readonly-note', readonly ? '当前为只读观察模式。已保存的规则不会暂停流量，也不会修改、丢弃或重发内容。' : '');
    if (readonly) { $('edit-form').hidden = true; s.editing = false; s.draftOriginal = null; }
  }
  function renderCaptureSummary() {
    const status = s.status || {}; const stats = status.stats || {};
    const retained = Number(stats.retained ?? stats.total ?? 0).toLocaleString('zh-CN');
    const limit = stats.max_records ?? status.max_records ?? settingsState.data?.current?.max_records;
    $('capture-retention').textContent = `当前保留 ${retained} 条${limit ? ` / 上限 ${Number(limit).toLocaleString('zh-CN')} 条` : ''} · 旧记录自动轮替`;
    $('capture-last').textContent = `最近捕获：${time(stats.last_capture_at, true)}`;
    $('capture-poll-state').textContent = s.polling ? '每 2 秒自动刷新' : '页面刷新已暂停 · 服务端仍在采集';
    $('capture-poll-state').classList.toggle('paused', !s.polling);
    const note = $('capture-counter-note');
    note.hidden = !stats.history_before_counter_unknown;
    note.textContent = stats.history_before_counter_unknown ? `累计从 ${time(stats.counter_started_at, true)} 启用计数，包含当时保留的 ${Number(stats.counter_baseline || 0).toLocaleString('zh-CN')} 条记录。升级前已淘汰的记录无法追溯。` : '';
  }
  function rememberReading(target) {
    const key = target.dataset.readingKey;
    if (!key || target.dataset.readingReady === 'false') return;
    readingPositions.set(key, { top: target.scrollTop, blocks: [...target.querySelectorAll('pre')].map((node) => [node.scrollTop, node.scrollLeft]) });
    if (readingPositions.size > 40) readingPositions.delete(readingPositions.keys().next().value);
  }
  function restoreReading(target, key) {
    target.dataset.readingKey = key;
    const position = readingPositions.get(key);
    target.scrollTop = position?.top || 0;
    [...target.querySelectorAll('pre')].forEach((node, index) => { node.scrollTop = position?.blocks[index]?.[0] || 0; node.scrollLeft = position?.blocks[index]?.[1] || 0; });
  }
  const readableNames = { openai: '聊天增量合并', sse: 'SSE 事件正文', json: 'JSON 格式化', http: 'HTTP 消息', 'http-sse': 'HTTP / SSE 正文', text: '文本', chunked: 'HTTP 分块正文', binary: '二进制内容', unknown: '原始内容' };
  function readableLabel(meta) { return meta.label || readableNames[meta.kind] || meta.kind || '应用正文'; }
  function appendReadable(target, entry, heading, className = '') {
    const meta = entry.meta || {};
    const note = meta.recognized ? `自动解析 · ${readableLabel(meta)} · ${meta.complete === false ? '当前已捕获部分，完整性受限' : '已载入全部解析内容'}` : '未识别可解析的应用协议，显示 UTF-8 原文；二进制或密文请切换 HEX。';
    target.append(element('p', note, 'detail-note readable-status'));
    if (meta.warnings?.length) target.append(element('p', meta.warnings.join(' '), 'detail-note readable-warning'));
    addCode(target, heading, entry.content, `full-body readable-body ${className}`);
  }
  function updateContainerSelect(id, emptyLabel) {
    const node = $(id);
    const selected = node.value;
    const options = [new Option(emptyLabel, '')];
    s.containers.forEach((container) => options.push(new Option(container.name || container.id.slice(0, 12), container.id)));
    if (selected && !options.some((option) => option.value === selected)) options.push(new Option(`${selected.slice(0, 12)} · 已离线`, selected));
    node.replaceChildren(...options);
    node.value = selected;
  }
  async function loadContainers() {
    const data = await api('/api/containers');
    s.containers = data.items || [];
    s.lastInventory = Date.now();
    updateContainerSelect('filter-container', '全部容器 / 本机');
    updateContainerSelect('rule-container', '全部容器 / 本机');
    updateContainerSelect('session-container', '全部容器 / 本机');
    const info = engineInfo(data.status || s.status?.docker);
    $('container-status').textContent = `${info.detail || info.label} · 发现 ${s.containers.length} 个容器。来源按网络地址关联，无法确定归属时将显示本机 / 未识别。`;
    if (s.view === 'containers') renderContainers();
  }
  function filters() {
    return new URLSearchParams({ q: $('filter-query').value.trim(), protocol: $('filter-protocol').value, container_id: $('filter-container').value, state: s.view === 'pending' ? 'pending' : $('filter-state').value, limit: String(s.limit), offset: String(s.offset) });
  }
  function hasFilters() { return $('filter-query').value.trim() || $('filter-protocol').value || $('filter-container').value || $('filter-state').value && s.view !== 'pending'; }
  function emptyState(target, title, description, action) {
    target.replaceChildren(element('div', '≋', 'empty-glyph'), element('h3', title), element('p', description));
    if (action) { const button = element('button', action.text, 'button secondary compact'); button.addEventListener('click', action.run); target.append(button); }
    target.hidden = false;
  }
  function renderRecords() {
    const focusedId = $('records-body').contains(document.activeElement) ? document.activeElement.closest('tr')?.dataset.id : null;
    const focusedDetailButton = document.activeElement?.classList.contains('event-detail-button');
    const fragment = document.createDocumentFragment();
    s.records.forEach((record) => {
      const row = element('tr'); row.dataset.id = record.id; row.tabIndex = 0;
      row.classList.toggle('selected', record.id === s.selectedId);
      row.setAttribute('aria-selected', String(record.id === s.selectedId));
      row.setAttribute('aria-label', `${recordTitle(record)}，${stateNames[record.state] || record.state}`);
      row.classList.add('event-row');
      const failed = Boolean(record.error || record.state === 'error' || record.state === 'dropped' || Number(record.status_code) >= 400);
      const pending = record.state === 'pending' || record.state === 'resolving';
      const iconCell = element('td', null, 'event-icon-cell');
      const icon = element('span', failed ? '!' : pending ? 'Ⅱ' : '✓', `event-status-icon ${failed ? 'error' : pending ? 'pending' : 'success'}`); icon.setAttribute('aria-hidden', 'true'); iconCell.append(icon);
      const main = element('td', null, 'event-main');
      const titleLine = element('div', null, 'event-title-line');
      const titleText = record.source === 'http' && record.url ? `${record.method || 'GET'} ${record.url}` : record.summary || `${endpoint(record.src_ip, record.src_port)} → ${endpoint(record.dst_ip, record.dst_port)}`;
      const title = element('div', titleText, 'event-title cell-title'); title.title = titleText; titleLine.append(title);
      if (record.source === 'http' && record.status_code) titleLine.append(element('span', `HTTP ${record.status_code}`, `event-http-status ${Number(record.status_code) >= 400 ? 'error' : 'success'}`));
      else titleLine.append(protocolBadge(record));
      const descriptions = [stateNames[record.state] || record.state || '已捕获'];
      if (record.source === 'http') { if (record.request_body_size !== undefined) descriptions.push(`请求体 ${bytes(record.request_body_size)}`); if (record.response_body_size !== undefined) descriptions.push(`响应体 ${bytes(record.response_body_size)}`); }
      else descriptions.push(`本包 ${bytes(record.payload_size || 0)}`, record.protocol === 'TCP' ? '点击查看双向完整通信' : 'UDP 数据报');
      const description = element('div', descriptions.join(' · '), 'event-description');
      const metadata = element('div', null, 'event-metadata');
      metadata.append(element('span', time(record.created_at, true), 'cell-time'), element('span', record.container_name || '本机 / 未识别', 'cell-container'));
      if (record.response_streaming) metadata.append(element('span', '流式接收中', 'event-streaming'));
      if (record.duration_ms !== undefined && record.duration_ms !== null) metadata.append(element('span', `${Number(record.duration_ms).toFixed(0)} ms`));
      if (record.container_id) metadata.append(element('span', String(record.container_id).slice(0, 12), 'event-container-id'));
      main.append(titleLine, description, metadata);
      const actionCell = element('td', null, 'event-action-cell');
      const button = element('button', '查看详情 ›', 'event-detail-button'); button.setAttribute('aria-label', `查看详情：${titleText}`);
      button.addEventListener('click', event => { event.stopPropagation(); selectRecord(record.id); }); actionCell.append(button);
      row.append(iconCell, main, actionCell);
      row.addEventListener('click', () => selectRecord(record.id));
      row.addEventListener('keydown', event => { if (event.target === row && (event.key === 'Enter' || event.key === ' ')) { event.preventDefault(); selectRecord(record.id); } });
      fragment.append(row);
    });
    $('records-body').replaceChildren(fragment);
    if (focusedId) { const row = [...$('records-body').children].find(row => row.dataset.id === focusedId); (focusedDetailButton ? row?.querySelector('.event-detail-button') : row)?.focus({ preventScroll: true }); }
    $('records-empty').hidden = Boolean(s.records.length);
    if (!s.records.length) {
      if (hasFilters()) emptyState($('records-empty'), '没有匹配的流量', '尝试缩短搜索词或减少筛选条件。正文、URL、请求头与网络地址都可以搜索。', { text: '清除筛选', run: resetFilters });
      else if (s.view === 'pending') emptyState($('records-empty'), '当前没有待处理的请求', '命中启用规则的请求会暂停在这里。超时、已放行或已丢弃的记录可在网络流量中查看。', { text: '查看拦截规则', run: () => setView('rules') });
      else emptyState($('records-empty'), '等待第一条网络请求', '为程序配置 HTTP 代理，或在 Ubuntu 上启动抓包引擎。接入后的真实流量会显示在这里。', { text: '查看接入指南 ↗', run: () => setView('guide') });
    }
    $('record-count').textContent = `${s.total.toLocaleString('zh-CN')} 条记录`;
    $('page-info').textContent = s.total ? `${s.offset + 1}–${Math.min(s.offset + s.records.length, s.total)} / ${s.total.toLocaleString('zh-CN')} 条` : '每页 50 条';
    $('previous-page').disabled = s.offset === 0;
    $('next-page').disabled = s.offset + s.limit >= s.total;
    $('last-updated').textContent = time(Date.now() / 1000);
  }
  async function refresh(force = false) {
    if (settingsState.applying || settingsState.restartDone) return;
    if (!s.authenticated && !force) return;
    if (s.refreshing) { if (force) s.refreshAgain = true; return; }
    s.refreshing = true;
    $('refresh-button').disabled = true;
    const version = s.requestVersion;
    try {
      const status = await api('/api/status');
      s.authenticated = true;
      renderStatus(status);
      if (Date.now() - s.lastInventory > 15000 || force) {
        try { await loadContainers(); } catch (error) { if (error.status === 401 || error.status === 403) throw error; $('container-status').textContent = `容器列表加载失败：${error.message}`; }
      }
      if (s.view === 'traffic' || s.view === 'pending') {
        const data = await api(`/api/records?${filters()}`);
        if (version === s.requestVersion) {
          s.records = data.items || []; s.total = Number(data.total || 0);
          if (s.offset >= s.total && s.offset > 0) { s.offset = Math.max(0, Math.floor((s.total - 1) / s.limit) * s.limit); s.refreshAgain = true; }
          else renderRecords();
        }
        if (s.selectedId) {
          const selectedId = s.selectedId; const detailVersion = s.detailVersion;
          try {
            const record = await api(`/api/records/${encodeURIComponent(selectedId)}`);
            if (s.selectedId === selectedId && s.detailVersion === detailVersion) { s.selected = record; s.detailLoaded = true; s.detailLoading = false; s.detailError = ''; renderDetail(false); if (s.tab === 'content') loadRecordSession(record, true); }
          } catch (error) {
            if (error.status === 401 || error.status === 403) throw error;
            if (s.selectedId === selectedId && s.detailVersion === detailVersion) { s.detailLoading = false; s.detailError = error.message; renderDetail(false); }
          }
        }
      }
      if (s.view === 'rules') await loadRules();
      if (s.view === 'sessions') await refreshSessions();
      if (s.view === 'settings' && !settingsState.data) await loadSettings();
      message('global-error', '');
    } catch (error) {
      if (error.status !== 401 && error.status !== 403) connection('offline', '连接异常');
      message('global-error', `连接未完成：${error.message}。可点击「刷新」重试。`, 'danger');
      if (!s.records.length && (s.view === 'traffic' || s.view === 'pending')) emptyState($('records-empty'), '暂时无法加载流量', '请检查服务器状态与访问令牌，恢复连接后重试。', { text: '重新连接', run: () => refresh(true) });
    } finally {
      s.refreshing = false; $('refresh-button').disabled = false;
      if (s.refreshAgain) { s.refreshAgain = false; if (s.authenticated) queueMicrotask(() => refresh(true)); }
    }
  }
  function filterChanged() { s.offset = 0; s.requestVersion++; refresh(true); }
  function resetFilters() { ['filter-query', 'filter-protocol', 'filter-container', 'filter-state'].forEach((id) => { $(id).value = ''; }); filterChanged(); }
  function setView(view) {
    if (!titles[view]) return;
    s.view = view; s.offset = 0; s.requestVersion++;
    document.querySelectorAll('.view').forEach((node) => { node.hidden = node.id !== `view-${view === 'pending' ? 'traffic' : view}`; });
    document.querySelectorAll('.nav-item').forEach((node) => { node.classList.toggle('active', node.dataset.view === view); });
    $('breadcrumb-title').textContent = titles[view];
    if (view === 'traffic' || view === 'pending') {
      $('traffic-title').replaceChildren(document.createTextNode(titles[view]), element('span', '.', 'heading-dot'));
      $('traffic-subtitle').textContent = view === 'pending' ? '匹配规则的请求已暂停。检查内容，编辑后放行，或直接丢弃。' : '查看每一次连接，按规则暂停，在放行前检查与修改。';
      $('list-heading').textContent = view === 'pending' ? '等待处理' : '所有流量';
      $('filter-state').disabled = view === 'pending';
    }
    syncRecordDrawer();
    if (location.hash !== `#${view}`) history.replaceState(null, '', `#${view}`);
    refresh(true);
  }
  async function selectRecord(id) {
    if (s.selectedId === id && (s.detailLoading || (s.detailLoaded && !s.detailError))) return;
    if (s.actionBusy) { toast('当前操作正在提交，请稍候。'); return; }
    if (s.editing && draftDirty() && !await confirmAction('切换请求？', '当前草稿尚未提交，切换后将丢弃此草稿。', '切换请求')) return;
    if (s.selectedId !== id) { s.tab = 'content'; recordSession = null; recordSessionBodies.clear(); }
    const previousRecord = s.selectedId === id ? s.selected : null;
    const previousLoaded = Boolean(previousRecord && s.detailLoaded);
    s.selectedId = id; s.detailLoaded = previousLoaded; s.detailLoading = true; s.detailError = ''; s.editing = false; s.draftOriginal = null;
    s.hexPage = 0; s.hexSide = 'request'; bodyCache.clear(); hexCache.clear(); readableCache.clear();
    $('edit-form').hidden = true; $('edit-button').textContent = '编辑内容';
    s.selected = previousLoaded ? previousRecord : s.records.find((record) => record.id === id) || previousRecord;
    const version = ++s.detailVersion;
    renderRecords();
    if (s.selected) renderDetail(true);
    try {
      const record = await api(`/api/records/${encodeURIComponent(id)}`);
      if (version !== s.detailVersion || id !== s.selectedId) return;
      s.selected = record; s.detailLoaded = true; s.detailLoading = false; s.detailError = ''; renderDetail(true);
    } catch (error) {
      if (version !== s.detailVersion || id !== s.selectedId) return;
      s.detailLoading = false; s.detailError = error.message; renderDetail(true);
    }
  }
  function addMetadata(list, label, value, code = false) { list.append(element('dt', label), element('dd', value === undefined || value === null || value === '' ? '—' : value, code ? 'mono' : '')); }
  function addCode(target, heading, content, className = '') {
    target.append(element('h3', heading, 'detail-section-label'));
    if (content !== null && content !== undefined && content !== '') target.append(element('pre', content, `code-block ${className}`));
    else target.append(element('p', '无内容', 'detail-note'));
  }
  function headerText(headers) {
    if (Array.isArray(headers)) return headers.map((pair) => Array.isArray(pair) ? `${pair[0]}: ${pair[1]}` : JSON.stringify(pair)).join('\n');
    if (headers && typeof headers === 'object') return Object.entries(headers).map(([key, value]) => `${key}: ${value}`).join('\n');
    return headers || '';
  }

  function bodyPresent(record, side) {
    return side === 'request' || Boolean(record.status_code || record.response_headers?.length || record.response_body_ref || record.response_text_ref || record.response_body_text || record.response_body_b64 || record.response_body_size);
  }
  function bodyKey(record, side) {
    return `${record.id}:${side}:${record[`${side}_text_ref`] || record[`${side}_body_ref`] || record[`${side}_body_text`] || ''}:${record[`${side}_body_size`] || 0}:${record[`${side}_truncated`] || false}`;
  }
  function bodyEntry(record, side) {
    const entry = bodyCache.get(side);
    return entry?.key === bodyKey(record, side) ? entry : null;
  }
  function loadBody(record, side, retry = false) {
    if (record.source !== 'http' || !s.detailLoaded || !bodyPresent(record, side)) return null;
    const current = bodyEntry(record, side);
    if (current && !retry) return current;
    const entry = { key: bodyKey(record, side), state: 'loading', text: '', error: '' };
    bodyCache.set(side, entry);
    entry.promise = api(`/api/records/${encodeURIComponent(record.id)}/body/${side}?view=text`, { responseType: 'text', timeoutMs: 120000 })
      .then((text) => { entry.text = text; entry.state = 'ready'; })
      .catch((error) => { entry.error = error.message; entry.state = 'error'; })
      .finally(() => { if (s.selectedId === record.id && bodyEntry(s.selected, side) === entry) renderDetail(false); });
    return entry;
  }
  function bodyStreaming(record, side) { return side === 'response' && record.response_streaming === true; }
  function bodyComplete(record, side) {
    return !bodyStreaming(record, side) && !record[`${side}_truncated`] && record[`${side}_body_complete`] !== false;
  }
  function bodyStatusText(record, side) {
    if (bodyStreaming(record, side)) return '流式响应进行中，显示截至当前已保存的内容';
    return bodyComplete(record, side) ? '完整保存' : '内容不完整，仅显示已保存字节';
  }
  function readableBodyKey(record, side) {
    return `${bodyKey(record, side)}:${JSON.stringify(record[`${side}_headers`] || [])}:${record[`${side}_body_complete`]}`;
  }
  function readableBodyEntry(record, side) {
    const entry = readableCache.get(side);
    return entry?.key === readableBodyKey(record, side) ? entry : null;
  }
  function loadReadableBody(record, side, retry = false) {
    const current = readableBodyEntry(record, side);
    if (current && !retry) return current;
    const entry = { key: readableBodyKey(record, side), state: 'loading' };
    readableCache.set(side, entry);
    api(`/api/records/${encodeURIComponent(record.id)}/readable/${side}`, { timeoutMs: 120000 })
      .then(async (meta) => { entry.meta = meta; entry.content = await api(meta.content_url, { responseType: 'text', timeoutMs: 120000 }); entry.state = 'ready'; })
      .catch((error) => { entry.error = error.message; entry.state = 'error'; })
      .finally(() => { if (s.selectedId === record.id && readableBodyEntry(s.selected, side) === entry) renderDetailBody(); });
    return entry;
  }
  function renderHttpBody(target, record, side, paired = false) {
    const format = s.bodyFormat[side];
    const entry = format === 'auto' ? loadReadableBody(record, side) : loadBody(record, side);
    const caption = side === 'request' ? '请求正文' : '响应正文';
    const controls = element('div', null, 'body-format-toolbar');
    const label = element('label', '内容格式 '); const select = element('select'); select.id = paired ? `http-${side}-format` : 'http-body-format'; select.setAttribute('aria-label', `${caption}内容格式`);
    select.append(new Option('自动解析', 'auto'), new Option('UTF-8 原文', 'text')); select.value = format;
    select.addEventListener('change', () => { s.bodyFormat[side] = select.value; renderDetailBody(); }); label.append(select); controls.append(label);
    if (format === 'auto' && entry?.state === 'ready' && entry.meta?.download_url) { const button = element('button', '下载解析全文 ↗', 'text-button'); button.id = paired ? `http-${side}-download-readable` : 'http-download-readable'; button.addEventListener('click', () => download(entry.meta.download_url, `requestwatch-${record.id}-${side}-readable.txt`)); controls.append(button); }
    target.append(controls);
    const status = element('div', null, 'body-status');
    if (!entry || entry.state === 'loading') {
      status.append(element('span', `正在读取${format === 'auto' ? '并解析' : ''}完整${caption}…`, 'detail-note')); target.append(status); return;
    }
    if (entry.state === 'error') {
      status.append(element('span', `完整正文加载失败：${entry.error}`, 'detail-note body-error'));
      const retry = element('button', '重新读取', 'button secondary compact');
      retry.addEventListener('click', () => { if (format === 'auto') loadReadableBody(record, side, true); else loadBody(record, side, true); renderDetailBody(); });
      status.append(retry); target.append(status); return;
    }
    const complete = bodyComplete(record, side);
    status.append(element('span', `${complete ? '原始正文完整保存' : bodyStatusText(record, side)} · ${bytes(record[`${side}_body_size`] ?? new TextEncoder().encode(entry.text || entry.content || '').length)}`, `detail-note${complete || bodyStreaming(record, side) ? '' : ' body-error'}`)); target.append(status);
    if (bodyStreaming(record, side) && !record[`${side}_body_size`]) target.append(element('p', '已收到响应头，正在等待第一段响应正文。', 'detail-note'));
    if (format === 'auto') appendReadable(target, entry, caption);
    else addCode(target, caption, entry.text, 'full-body');
    if (record[`${side}_body_binary`] || (side === 'request' && record.body_binary)) target.append(element('p', '二进制正文的文本视图可能包含替代字符。HEX 和「下载原始正文」保留全部原始字节；未编辑正文时也保持原始字节。', 'detail-note'));
  }
  function hexForBytes(data) { return Array.from(data, (byte) => byte.toString(16).padStart(2, '0')).join(''); }
  function renderHex(target, record) {
    const side = s.hexSide;
    const isHttp = record.source === 'http';
    const packetHex = isHttp ? '' : requestBytes(record);
    const totalBytes = isHttp ? Number(record[`${side}_body_size`] ?? (side === 'request' ? requestBytes(record).length / 2 : 0)) : packetHex.length / 2;
    const pages = Math.max(1, Math.ceil(totalBytes / HEX_PAGE_BYTES));
    s.hexPage = Math.min(s.hexPage, pages - 1);
    const start = s.hexPage * HEX_PAGE_BYTES;
    const controls = element('div', null, 'hex-controls');
    if (isHttp) {
      const select = element('select'); select.setAttribute('aria-label', 'HEX 查看方向'); select.id = 'hex-side';
      select.append(new Option('请求正文', 'request'), new Option('响应正文', 'response')); select.value = side;
      select.addEventListener('change', () => { s.hexSide = select.value; s.hexPage = 0; renderDetail(); }); controls.append(select);
    }
    const previous = element('button', '上一页', 'button secondary compact'); previous.id = 'hex-previous'; previous.disabled = s.hexPage === 0;
    previous.addEventListener('click', () => { s.hexPage--; renderDetailBody(); });
    const input = element('input'); input.id = 'hex-page'; input.type = 'number'; input.min = '1'; input.max = String(pages); input.value = String(s.hexPage + 1); input.setAttribute('aria-label', 'HEX 页码');
    input.addEventListener('change', () => { s.hexPage = Math.min(pages - 1, Math.max(0, (Number.parseInt(input.value, 10) || 1) - 1)); renderDetailBody(); });
    const next = element('button', '下一页', 'button secondary compact'); next.id = 'hex-next'; next.disabled = s.hexPage + 1 >= pages;
    next.addEventListener('click', () => { s.hexPage++; renderDetailBody(); });
    controls.append(previous, input, element('span', `/ ${pages} 页`, 'detail-note'), next); target.append(controls);
    target.append(element('p', `全部 ${totalBytes.toLocaleString('zh-CN')} 字节 · 当前 ${totalBytes ? start + 1 : 0}–${Math.min(start + HEX_PAGE_BYTES, totalBytes)} · 每页 4 KiB，可跳转任意页`, 'detail-note'));
    if (!isHttp) { addCode(target, 'PAYLOAD · HEX / ASCII', formatHex(packetHex.slice(start * 2, (start + HEX_PAGE_BYTES) * 2), start), 'hex'); return; }
    if (!totalBytes) { addCode(target, 'BODY · HEX / ASCII', ''); return; }
    const key = `${bodyKey(record, side)}:${s.hexPage}`;
    let entry = hexCache.get(key);
    if (!entry) {
      entry = { state: 'loading' }; hexCache.set(key, entry);
      if (hexCache.size > 8) hexCache.delete(hexCache.keys().next().value);
      api(`/api/records/${encodeURIComponent(record.id)}/body/${side}?view=raw`, { responseType: 'bytes', headers: { Range: `bytes=${start}-${Math.min(start + HEX_PAGE_BYTES, totalBytes) - 1}` }, timeoutMs: 120000 })
        .then((result) => { entry.hex = hexForBytes(result.status === 206 ? result.data : result.data.subarray(start, start + HEX_PAGE_BYTES)); entry.state = 'ready'; })
        .catch((error) => { entry.error = error.message; entry.state = 'error'; })
        .finally(() => { if (s.selectedId === record.id && s.tab === 'hex') renderDetailBody(); });
    }
    if (entry.state === 'ready') addCode(target, 'BODY · HEX / ASCII', formatHex(entry.hex, start), 'hex');
    else if (entry.state === 'error') {
      target.append(element('p', `原始字节加载失败：${entry.error}`, 'detail-note body-error'));
      const retry = element('button', '重新读取', 'button secondary compact'); retry.addEventListener('click', () => { hexCache.delete(key); renderDetailBody(); }); target.append(retry);
    } else target.append(element('p', '正在读取此页原始字节…', 'detail-note'));
  }

  function requestBytes(record) {
    if (record.payload_hex) return String(record.payload_hex).replace(/\s/g, '');
    if (record.source !== 'http') return '';
    if (record.request_body_b64) {
      try { return Array.from(atob(record.request_body_b64), (char) => char.charCodeAt(0).toString(16).padStart(2, '0')).join(''); }
      catch (_) { return ''; }
    }
    return Array.from(new TextEncoder().encode(record.request_body_text || ''), (byte) => byte.toString(16).padStart(2, '0')).join('');
  }
  function formatHex(value, baseOffset = 0) {
    const clean = String(value || '').replace(/\s/g, '');
    if (!clean) return '';
    const lines = [];
    for (let offset = 0; offset < clean.length; offset += 32) {
      const chunk = clean.slice(offset, offset + 32).match(/.{1,2}/g) || [];
      const ascii = chunk.map((byte) => { const n = parseInt(byte, 16); return n >= 32 && n <= 126 ? String.fromCharCode(n) : '.'; }).join('');
      lines.push(`${(baseOffset + offset / 2).toString(16).padStart(8, '0')}  ${chunk.join(' ').padEnd(47)}  ${ascii}`);
    }
    return lines.join('\n');
  }
  function syncRecordDrawer() {
    const drawer = $('record-detail-drawer');
    const visible = Boolean(s.selected) && ['traffic', 'pending'].includes(s.view);
    const wasHidden = drawer.hidden;
    drawer.hidden = !visible; $('detail-backdrop').hidden = !visible;
    $('traffic-workbench').classList.toggle('detail-open', visible);
    document.body.classList.toggle('record-drawer-open', visible);
    if (visible && wasHidden) $('close-detail').focus({ preventScroll: true });
  }
  async function closeRecordDetail() {
    if (s.actionBusy) { toast('当前操作正在提交，请稍候。'); return; }
    if (s.editing && draftDirty() && !await confirmAction('关闭详情？', '当前草稿尚未提交，关闭后将丢弃此草稿。', '关闭详情')) return;
    const previousId = s.selectedId;
    s.selected = null; s.selectedId = null; s.editing = false; s.draftOriginal = null; s.detailVersion++;
    renderDetail(); renderRecords();
    const row = [...$('records-body').children].find(row => row.dataset.id === previousId);
    (row?.querySelector('.event-detail-button') || $('filter-query')).focus({ preventScroll: true });
  }
  function renderDetail(reset = false) {
    const record = s.selected;
    document.querySelector('.traffic-workbench')?.classList.toggle('body-workspace-wide', Boolean(record) && s.tab === 'content');
    $('detail-body').classList.toggle('primary-body-view', s.tab === 'content');
    $('detail-empty').hidden = Boolean(record);
    $('detail-content').hidden = !record;
    syncRecordDrawer();
    if (!record) return;
    if (record.source === 'http' && s.detailLoaded) { loadBody(record, 'request'); loadBody(record, 'response'); }
    $('detail-inspector-label').textContent = record.source === 'http' ? 'HTTP INSPECTOR' : 'PACKET INSPECTOR';
    document.querySelector('[data-tab="request"]').textContent = record.source === 'http' ? '请求' : '单包载荷';
    document.querySelector('[data-tab="response"]').textContent = record.source === 'http' ? '响应' : record.response_body_text ? '重发返回' : '返回方向';
    $('detail-title').textContent = recordTitle(record);
    $('detail-title').title = recordTitle(record);
    $('detail-protocol').replaceWith(Object.assign(protocolBadge(record), { id: 'detail-protocol' }));
    $('detail-state').replaceWith(Object.assign(recordStateBadge(record), { id: 'detail-state' }));
    $('detail-id').textContent = `#${String(record.id).slice(0, 8)}`;
    $('detail-id').title = record.id;
    $('detail-url').textContent = record.url || `${endpoint(record.src_ip, record.src_port)} → ${endpoint(record.dst_ip, record.dst_port)}`;
    const alerts = [];
    if (record.error) alerts.push(record.error);
    if (s.uncertainReplayId === record.id) alerts.push('重发结果尚未确认：请求可能已经发送。请先检查网络流量中的重发记录，避免重复发送。');
    if (record.detail) alerts.push(record.detail);
    if (record.response_streaming) alerts.push('流式响应仍在接收，正文会随采集继续更新。');
    if (record.request_truncated || record.response_truncated || record.truncated || record.request_body_complete === false || (record.response_body_complete === false && !record.response_streaming)) alerts.push('此记录未确认完整，下面只显示已保存内容；未捕获的字节无法补回。');
    if (s.detailLoading) alerts.push('正在读取此条记录的详情…');
    if (s.detailError) alerts.push(`详情${s.detailLoaded ? '更新' : '加载'}失败：${s.detailError}。${s.detailLoaded ? '下方保留上次成功读取的内容。' : '列表仅提供摘要，完整内容尚未加载。'}`);
    if (record.state === 'pending') alerts.push(record.deadline ? `请求已暂停，剩余约 ${Math.max(0, Math.ceil(record.deadline - Date.now() / 1000))} 秒；超时后由服务端按配置处理。` : '请求已暂停，等待处理；超时后由服务端按配置处理。');
    message('detail-alert', alerts.join(' '), `compact ${record.error || s.detailError ? 'danger' : record.state === 'pending' ? 'warning' : ''}`);
    $('detail-retry').hidden = !s.detailError; $('detail-retry').disabled = s.detailLoading;
    renderPacketContext(record);
    syncReadOnlyActions();
    $('pending-actions').hidden = record.state !== 'pending';
    $('accept-button').disabled = s.actionBusy || !s.detailLoaded || record.state !== 'pending';
    $('drop-button').disabled = s.actionBusy || !s.detailLoaded || record.state !== 'pending';
    $('replay-button').disabled = s.actionBusy || !s.detailLoaded || record.state === 'pending' || record.state === 'resolving';
    $('edit-button').disabled = s.actionBusy || !s.detailLoaded || record.state === 'resolving' || (record.source === 'http' && bodyEntry(record, 'request')?.state !== 'ready');
    const exportSide = s.tab === 'response' ? 'response' : s.tab === 'hex' ? s.hexSide : 'request';
    $('message-download').hidden = record.source !== 'http'; $('body-download').hidden = record.source !== 'http';
    $('message-download').textContent = `${bodyComplete(record, exportSide) ? '下载完整' : '下载已存'}${exportSide === 'response' ? '响应' : '请求'} ↗`;
    $('message-download').disabled = !s.detailLoaded || !bodyPresent(record, exportSide); $('body-download').disabled = $('message-download').disabled;
    $('replay-button').textContent = record.source === 'http' ? '重发请求 ↗' : '重发载荷 ↗';
    $('action-help').textContent = record.state === 'pending' ? '先处理当前拦截，再重发。编辑草稿会随放行提交；丢弃不会发送草稿。' : record.source === 'http' ? '重发将发送一条新的 HTTP 请求，可能再次执行服务端操作。' : record.protocol === 'UDP' ? '重发会向目标发送一个新的 UDP 数据报。' : '重发会建立新 TCP 连接并发送载荷，不保留原会话与协议握手。';
    if (reset || !s.editing) renderDetailBody();
  }
  function renderDetailBody() {
    const record = s.selected;
    if (!record) return;
    document.querySelectorAll('[data-tab]').forEach((node) => { const selected = node.dataset.tab === s.tab; node.classList.toggle('active', selected); node.setAttribute('aria-selected', String(selected)); });
    const target = $('detail-body');
    const loadState = (s.tab === 'content' ? ['request', 'response'] : ['request', 'response'].includes(s.tab) ? [s.tab] : []).map(side => [bodyEntry(record, side)?.state, bodyEntry(record, side)?.error, readableBodyEntry(record, side)?.state, readableBodyEntry(record, side)?.error, s.bodyFormat[side]]);
    const inlineState = s.tab === 'content' && record.source !== 'http' ? [recordSession?.id, recordSession?.state, recordSession?.error, recordSession?.session, [...recordSessionBodies].map(([key, entry]) => [key, entry.key, entry.state, entry.error]), recordSessionFormats] : null;
    const renderKey = JSON.stringify([s.tab, record, s.detailLoaded, s.detailLoading, s.detailError, loadState, inlineState, s.hexSide, s.hexPage, s.tab === 'hex' ? [...hexCache].map(([key, value]) => [key, value.state, value.error]) : null]);
    if (target.dataset.renderKey === renderKey) return;
    target.dataset.renderKey = renderKey;
    rememberReading(target);
    target.replaceChildren();
    if (!s.detailLoaded && s.tab !== 'overview') {
      target.append(element('p', s.detailLoading ? '正在读取完整记录。读取完成后显示全部已保存的内容。' : '完整记录尚未加载，请点击上方“重新读取详情”。', 'detail-note'));
      return;
    }
    if (s.tab === 'content') {
      renderPrimaryBodies(target, record);
    } else if (s.tab === 'overview') {
      const list = element('dl', null, 'metadata');
      addMetadata(list, '捕获时间', time(record.created_at, true));
      addMetadata(list, '接入类型', record.source === 'http' ? 'HTTP 代理' : '网络包 / NFQUEUE');
      addMetadata(list, '来源地址', endpoint(record.src_ip, record.src_port), true);
      addMetadata(list, '目标地址', endpoint(record.dst_ip, record.dst_port), true);
      addMetadata(list, 'Docker 容器', record.container_name || '本机 / 未识别');
      addMetadata(list, '来源识别', typeof record.attribution === 'object' ? JSON.stringify(record.attribution) : record.attribution);
      addMetadata(list, '数据大小', bytes(record.payload_size ?? record.request_body_size ?? requestBytes(record).length / 2));
      if (record.source === 'http') { addMetadata(list, '请求正文', `${bytes(record.request_body_size)} · ${bodyStatusText(record, 'request')}`); if (bodyPresent(record, 'response')) addMetadata(list, '响应正文', `${bytes(record.response_body_size)} · ${bodyStatusText(record, 'response')}`); addMetadata(list, '响应状态', record.status_code); addMetadata(list, '总耗时', record.duration_ms !== null && record.duration_ms !== undefined ? `${Number(record.duration_ms).toFixed(0)} ms` : '等待响应'); }
      if (record.matched_rule || record.rule_name) addMetadata(list, '命中规则', record.rule_name || record.matched_rule);
      target.append(list);
    } else if (s.tab === 'request') {
      if (record.source === 'http') {
        addCode(target, 'REQUEST LINE', `${record.method || 'GET'} ${record.url || ''}`);
        addCode(target, '请求头', headerText(record.request_headers));
        renderHttpBody(target, record, 'request');
      } else {
        const packetText = packetPayloadText(record);
        target.append(element('p', `此包已保存 ${bytes(requestBytes(record).length / 2 || record.payload_size)} 载荷 · UTF-8 原文`, 'detail-note'));
        addCode(target, '单包载荷 · 全部已保存字节的文本视图', packetText, 'packet-full-body');
        if (packetText.includes('\ufffd')) target.append(element('p', '单包可能在 UTF-8 字符中间分割，也可能包含二进制数据。请查看 TCP 会话重组文本，或用 HEX 查看原始字节。', 'detail-note'));
        if (!requestBytes(record) && !record.payload_text) target.append(element('p', '此包没有应用载荷，可能是 TCP 握手、确认或关闭报文；连接内容请查看 TCP 会话。', 'detail-note'));
      }
    } else if (s.tab === 'response') {
      if (record.source !== 'http') {
        if (record.response_body_text) addCode(target, '重发连接返回的载荷', record.response_body_text);
        else target.append(element('p', record.protocol === 'TCP' ? '每条网络包记录只保存当前方向的一个包。打开上方关联的 TCP 会话，并切换方向，可查看此连接已捕获的返回内容。' : 'UDP 数据报没有独立的 HTTP 响应。可按反向地址查找返回的数据报。', 'detail-note'));
        if (record.protocol === 'TCP' && record.tcp_session_id && record.tcp_session_available !== false) addSessionLink(target, record.tcp_session_id, record.tcp_session_direction === 'client' ? 'server' : record.tcp_session_direction === 'server' ? 'client' : null, '查看此连接的返回方向 →');
      }
      else if (!bodyPresent(record, 'response')) target.append(element('p', record.state === 'pending' ? '请求正在等待放行，尚无响应。' : record.state === 'dropped' ? '请求已丢弃，没有响应。' : record.response_streaming ? '流式响应已开始，正在等待第一段正文。' : '尚未收到响应，或当前记录没有响应内容。', 'detail-note'));
      else { addCode(target, 'HTTP 状态', record.status_code); addCode(target, '响应头', headerText(record.response_headers)); renderHttpBody(target, record, 'response'); }
    } else {
      renderHex(target, record);
    }
    restoreReading(target, `${record.id}:${s.tab}:${s.bodyFormat[s.tab] || ''}:${s.hexSide}:${s.hexPage}`);
    target.dataset.readingReady = String(!['request', 'response'].includes(s.tab) || record.source !== 'http' || (s.bodyFormat[s.tab] === 'auto' ? readableBodyEntry(record, s.tab)?.state : bodyEntry(record, s.tab)?.state) === 'ready');
  }
  function openEditor() {
    if (isReadOnly()) { toast('当前为只读观察模式，不能修改流量。'); return; }
    if (!s.selected || !s.detailLoaded) return;
    if (s.editing) { $('edit-form').hidden = !$('edit-form').hidden; $('edit-button').textContent = $('edit-form').hidden ? '展开编辑草稿' : '收起编辑草稿'; return; }
    const record = s.selected;
    if (record.source === 'http' && bodyEntry(record, 'request')?.state !== 'ready') { toast('请等完整正文加载后再编辑。', true); return; }
    s.draftOriginal = { method: record.method || 'GET', url: record.url || '', headers: JSON.stringify(record.request_headers || [], null, 2), body: record.source === 'http' ? bodyEntry(record, 'request').text : '', hex: record.payload_hex || '' };
    fillEditor(); s.editing = true;
    $('edit-form').hidden = false; $('edit-button').textContent = '收起编辑草稿';
    $('http-editor').hidden = record.source !== 'http';
    $('packet-editor').hidden = record.source === 'http';
    $('body-edit-help').textContent = (record.request_body_text === null || record.request_body_binary || record.body_binary) ? '二进制正文：未编辑时保留原始字节。填写文本将替换整个请求正文。' : `已载入全部正文（${bytes(record.request_body_size)}）。未修改时保持原始字节；修改文本将替换整个正文。`;
    $('packet-edit-help').textContent = record.protocol === 'TCP' ? `TCP 只能等长修改。原始载荷 ${bytes(record.payload_size ?? String(record.payload_hex || '').replace(/\s/g, '').length / 2)}；空格与换行会被忽略。` : '每个字节以两位十六进制表示；空格与换行会被忽略。';
    (record.source === 'http' ? $('edit-url') : $('edit-hex')).focus();
  }
  function fillEditor() {
    const original = s.draftOriginal;
    if (!original) return;
    $('edit-method').value = original.method; $('edit-url').value = original.url; $('edit-headers').value = original.headers; $('edit-body').value = original.body; $('edit-hex').value = original.hex;
    $('draft-status').textContent = '修改仅在放行 / 重发时提交';
  }
  function draftDirty() {
    const original = s.draftOriginal;
    return s.editing && original && ($('edit-method').value !== original.method || $('edit-url').value !== original.url || $('edit-headers').value !== original.headers || $('edit-body').value !== original.body || $('edit-hex').value !== original.hex);
  }
  function edits() {
    if (!s.editing || !s.draftOriginal) return {};
    const original = s.draftOriginal;
    const result = {};
    if (s.selected.source === 'http') {
      if ($('edit-method').value !== original.method) {
        const method = $('edit-method').value.trim().toUpperCase();
        if (!/^[!#$%&'*+.^_`|~0-9A-Z-]+$/.test(method)) throw new Error('请输入有效的 HTTP 方法。');
        result.method = method;
      }
      if ($('edit-url').value !== original.url) {
        const value = $('edit-url').value.trim();
        let url; try { url = new URL(value); } catch (_) { throw new Error('请输入完整的 HTTP 或 HTTPS URL。'); }
        if (!['http:', 'https:'].includes(url.protocol)) throw new Error('URL 必须使用 http:// 或 https://。');
        result.url = value;
      }
      if ($('edit-headers').value !== original.headers) {
        let headers; try { headers = JSON.parse($('edit-headers').value); } catch (_) { throw new Error('请求头必须是 JSON 键值对数组，例如 [["Content-Type", "application/json"]]。'); }
        if (!Array.isArray(headers) || !headers.every((pair) => Array.isArray(pair) && pair.length === 2 && pair.every((part) => typeof part === 'string' && !/[\r\n]/.test(part)) && /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(pair[0]))) throw new Error('每条请求头需要一个有效名称和文本值，且不能包含换行。');
        result.headers = headers;
      }
      if ($('edit-body').value !== original.body) result.body_text = $('edit-body').value;
    } else if ($('edit-hex').value !== original.hex) {
      const value = $('edit-hex').value.replace(/\s/g, '');
      if (!/^(?:[0-9a-fA-F]{2})*$/.test(value)) throw new Error('HEX 内容必须由成对的十六进制字符组成。');
      if (s.selected.protocol === 'TCP' && value.length !== original.hex.replace(/\s/g, '').length) throw new Error('TCP 载荷修改必须保持原来的字节长度。');
      result.payload_hex = value;
    }
    return result;
  }
  function confirmAction(title, text, label = '确认') {
    if (confirmResolve) confirmResolve(false);
    $('confirm-title').textContent = title; $('confirm-text').textContent = text; $('confirm-ok').textContent = label;
    if (!$('confirm-dialog').open) $('confirm-dialog').showModal();
    return new Promise((resolve) => { confirmResolve = resolve; });
  }
  function finishConfirm(accepted) { $('confirm-dialog').close(); const resolve = confirmResolve; confirmResolve = null; if (resolve) resolve(accepted); }
  async function recordAction(action) {
    if (isReadOnly()) { toast('当前为只读观察模式，不能暂停、修改、丢弃或重发流量。'); return; }
    if (!s.selected || !s.detailLoaded || s.actionBusy) return;
    const record = s.selected;
    let edited;
    try { edited = action === 'drop' ? {} : edits(); } catch (error) { toast(error.message, true); return; }
    if (action === 'replay') {
      const explanation = record.source === 'http' ? '将发送一条新的 HTTP 请求，服务端可能再次执行写入、支付或其他操作。' : record.protocol === 'UDP' ? '将向记录中的目标发送一个新 UDP 数据报。' : '将向记录中的目标建立新 TCP 连接并发送载荷，不恢复原连接的握手或登录状态。';
      if (!await confirmAction('确认重发？', s.status?.mode === 'demo' ? '当前是演示模式，将创建一条模拟重发记录，不发送真实请求。' : explanation, '确认重发')) return;
    }
    if (action === 'drop' && !await confirmAction('丢弃这条请求？', '当前暂停的请求将被丢弃，目标程序可能遇到超时或连接错误。', '丢弃请求')) return;
    if (record.id !== s.selectedId) return;
    s.actionBusy = true; renderDetail();
    try {
      const result = await api(`/api/records/${encodeURIComponent(record.id)}/${action === 'replay' ? 'replay' : 'decision'}`, { method: 'POST', body: JSON.stringify(action === 'replay' ? { edits: edited } : { action, edits: edited }) });
      toast(action === 'replay' ? '重发操作已提交' : action === 'accept' ? '请求已放行' : '请求已丢弃');
      s.editing = false; s.draftOriginal = null; $('edit-form').hidden = true; $('edit-button').textContent = '编辑内容';
      if (action === 'replay' && result?.id) { s.selectedId = result.id; s.selected = result; s.detailLoaded = true; s.tab = 'content'; recordSession = null; recordSessionBodies.clear(); renderDetail(true); }
      else { const fresh = await api(`/api/records/${encodeURIComponent(record.id)}`); if (s.selectedId === record.id) { s.selected = fresh; s.detailLoaded = true; renderDetail(true); } }
      refresh(true);
    } catch (error) {
      if (error.outcomeUnknown) s.uncertainReplayId = record.id;
      toast(error.outcomeUnknown ? error.message : `操作失败：${error.message}`, true);
    }
    finally { s.actionBusy = false; renderDetail(); }
  }
  async function download(path, fallbackName) {
    try {
      const response = await api(path, { download: true });
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = element('a'); link.href = url; link.download = fallbackName; document.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast('下载已开始');
    } catch (error) { toast(`下载失败：${error.message}`, true); }
  }

  function makeBodyPane(workspace, side, title, subtitle = '') {
    const pane = element('section', null, 'body-pane'); pane.dataset.bodySide = side;
    const heading = element('div', null, 'body-pane-heading');
    heading.append(element('h3', title, 'body-pane-title'));
    if (subtitle) heading.append(element('p', subtitle, 'body-pane-subtitle'));
    pane.append(heading);
    const toolbar = element('div', null, 'body-pane-toolbar'); pane.append(toolbar);
    const content = element('div', null, 'body-pane-content'); pane.append(content); workspace.append(pane);
    return { pane, toolbar, content };
  }
  function addPaneDownload(target, caption, path, filename) {
    const button = element('button', caption, 'text-button'); button.addEventListener('click', () => download(path, filename)); target.append(button);
  }
  function addPaneSearch(pane, toolbar, key) {
    const search = element('input'); search.type = 'search'; search.placeholder = '搜索此处全文'; search.setAttribute('aria-label', '搜索此处全文'); search.value = paneSearchValues.get(key) || '';
    search.addEventListener('input', () => { paneSearchValues.set(key, search.value); if (paneSearchValues.size > 40) paneSearchValues.delete(paneSearchValues.keys().next().value); });
    const button = element('button', '查找', 'text-button');
    const find = () => {
      const query = search.value; if (!query) return;
      const blocks = [...pane.querySelectorAll('.body-pane-content pre')];
      const previous = Number(search.dataset.match || '-1'); let match = null;
      for (let index = 0; index < blocks.length; index++) {
        const start = index === Number(search.dataset.block) && search.dataset.query === query ? previous + 1 : 0;
        const at = blocks[index].textContent.toLocaleLowerCase().indexOf(query.toLocaleLowerCase(), start);
        if (at >= 0) { match = { block: blocks[index], index, at }; break; }
      }
      if (!match) { search.dataset.match = '-1'; search.dataset.block = '-1'; toast('此处后续内容没有匹配；再次查找将从开头开始。'); return; }
      search.dataset.query = query; search.dataset.match = String(match.at); search.dataset.block = String(match.index);
      const textNode = match.block.firstChild; if (!textNode || textNode.nodeType !== Node.TEXT_NODE) return;
      const range = document.createRange(); range.setStart(textNode, match.at); range.setEnd(textNode, match.at + query.length);
      const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range);
      const rect = range.getBoundingClientRect(); const box = match.block.getBoundingClientRect(); match.block.scrollTop += rect.top - box.top - 30;
    };
    button.addEventListener('click', find); search.addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); find(); } }); toolbar.append(search, button);
  }
  function renderPrimaryBodies(target, record) {
    const workspace = element('div', null, 'body-workspace'); target.append(workspace);
    if (record.source === 'http') {
      for (const side of ['request', 'response']) {
        const caption = side === 'request' ? '请求体' : '响应体';
        const { pane, toolbar, content } = makeBodyPane(workspace, side, caption, side === 'request' ? `${record.method || 'GET'} ${record.url || ''}` : record.status_code ? `HTTP ${record.status_code}${bodyStreaming(record, side) ? ' · 持续接收中' : ''}` : '等待服务器响应');
        if (side === 'response' && !bodyPresent(record, side)) {
          content.append(element('p', record.state === 'pending' ? '请求尚未放行，暂无响应正文。' : record.state === 'dropped' ? '请求已丢弃，没有响应正文。' : '正在等待响应正文。', 'body-empty-state'));
          continue;
        }
        const base = `/api/records/${encodeURIComponent(record.id)}`;
        addPaneDownload(toolbar, '下载原始正文', `${base}/body/${side}?view=raw&download=true`, `requestwatch-${record.id}-${side}.bin`);
        addPaneDownload(toolbar, side === 'request' ? '下载请求含头' : '下载响应含头', `${base}/message/${side}`, `requestwatch-${record.id}-${side}.http`);
        addPaneSearch(pane, toolbar, `${record.id}:${side}`);
        renderHttpBody(content, record, side, true);
        if (!record[`${side}_body_size`] && !bodyStreaming(record, side)) content.append(element('p', side === 'request' ? '无请求正文；请求行和请求头可在下方展开。' : '无响应正文。', 'body-empty-state'));
        const headers = element('details', null, 'body-pane-headers'); headers.append(element('summary', side === 'request' ? '请求行与请求头' : '响应头'));
        if (side === 'request') addCode(headers, '请求行', `${record.method || 'GET'} ${record.url || ''}`);
        addCode(headers, side === 'request' ? '请求头' : '响应头', headerText(record[`${side}_headers`])); pane.append(headers);
      }
      return;
    }
    if (record.protocol === 'TCP' && record.tcp_session_id && record.tcp_session_available !== false) {
      const entry = loadRecordSession(record);
      if (!entry?.session) {
        const { content } = makeBodyPane(workspace, 'connection', '正在读取此连接的双向内容');
        content.append(element('p', entry?.error ? `连接读取失败：${entry.error}` : '正在读取已捕获的完整连接，随后直接显示两个方向的内容。', 'body-empty-state'));
        if (entry?.error) { const retry = element('button', '重新读取连接', 'button secondary compact'); retry.addEventListener('click', () => { loadRecordSession(record, true); renderDetailBody(); }); content.append(retry); }
        return;
      }
      const session = entry.session;
      for (const side of ['client', 'server']) renderInlineTcpPane(workspace, record, session, side);
      const notes = sessionWarnings(session); if (entry.error) notes.unshift(`更新失败：${entry.error}；保留上次成功读取的内容。`);
      if (notes.length) { const details = element('details', null, 'body-capture-notes'); details.append(element('summary', '连接完整性说明'), element('p', notes.join(' '), 'detail-note')); target.append(details); }
      return;
    }
    const { content } = makeBodyPane(workspace, 'packet', record.protocol === 'TCP' ? '单包载荷 · 关联连接不可用' : 'UDP 数据报内容');
    if (record.protocol === 'TCP') content.append(element('p', record.tcp_session_error || record.tcp_session_unavailable_reason || '此记录没有可用的关联会话，下面仅是当前包，无法从一个包补出其余通信内容。', 'body-empty-state'));
    addCode(content, '全部已保存载荷', packetPayloadText(record), 'full-body packet-full-body');
    if (!record.payload_size) content.append(element('p', '此包没有应用载荷，可能是握手、确认或关闭报文。', 'body-empty-state'));
  }
  function loadRecordSession(record, refresh = false) {
    if (record.source === 'http' || record.protocol !== 'TCP' || !record.tcp_session_id || record.tcp_session_available === false) return null;
    const id = record.tcp_session_id;
    if (recordSession?.id !== id) { recordSession = { id, state: 'idle', session: null, error: '' }; recordSessionBodies.clear(); }
    const entry = recordSession;
    if (entry.state === 'loading' || (!refresh && entry.state !== 'idle')) return entry;
    entry.state = 'loading'; entry.error = '';
    api(`/api/sessions/${encodeURIComponent(id)}`)
      .then(session => { entry.session = session; entry.state = 'ready'; })
      .catch(error => { entry.error = error.message; entry.state = 'error'; })
      .finally(() => { if (recordSession === entry && s.selected?.tcp_session_id === id && s.tab === 'content') renderDetailBody(); });
    return entry;
  }
  function loadInlineTcpBody(session, side, format) {
    const slot = `${side}:${format}`; const key = sessionKey(session, side, format);
    const current = recordSessionBodies.get(slot); if (current?.key === key) return current;
    const entry = { key, state: 'loading', previous: current?.state === 'ready' ? current : current?.previous }; recordSessionBodies.set(slot, entry);
    const base = `/api/sessions/${encodeURIComponent(session.id)}`;
    const task = format === 'auto'
      ? api(`${base}/readable/${side}`, { timeoutMs: 120000 }).then(async meta => { entry.meta = meta; return await api(meta.content_url, { responseType: 'text', timeoutMs: 120000 }); })
      : api(`${base}/body/${side}?view=${format}`, { responseType: 'text', timeoutMs: 120000 });
    task.then(content => { entry.content = content; entry.state = 'ready'; entry.previous = null; })
      .catch(error => { entry.error = error.message; entry.state = 'error'; })
      .finally(() => { if (recordSession?.id === session.id && recordSessionBodies.get(slot) === entry && s.tab === 'content') renderDetailBody(); });
    return entry;
  }
  function renderInlineTcpPane(workspace, record, session, side) {
    const direction = session.directions?.[side] || {};
    const format = recordSessionFormats[side]; const entry = loadInlineTcpBody(session, side, format);
    const caption = sessionDirectionLabel(session, side);
    const from = side === 'client' ? endpoint(session.client_ip, session.client_port) : endpoint(session.server_ip, session.server_port);
    const to = side === 'client' ? endpoint(session.server_ip, session.server_port) : endpoint(session.client_ip, session.client_port);
    const { pane, toolbar, content } = makeBodyPane(workspace, side, caption, `${from} → ${to} · ${bytes(direction.byte_count)} 已保存`);
    pane.classList.toggle('packet-current-direction', record.tcp_session_direction === side);
    const select = element('select'); select.id = `inline-tcp-${side}-format`; select.setAttribute('aria-label', `${caption}内容格式`);
    select.append(new Option('自动解析', 'auto'), new Option('UTF-8 原文', 'text'), new Option('Latin-1 原文', 'latin1')); select.value = format;
    select.addEventListener('change', () => { recordSessionFormats[side] = select.value; renderDetailBody(); }); toolbar.append(select);
    addPaneDownload(toolbar, '下载全部原始字节', `/api/sessions/${encodeURIComponent(session.id)}/body/${side}?view=raw&download=true`, `requestwatch-session-${session.id}-${side}.bin`);
    if (entry.meta?.download_url) addPaneDownload(toolbar, '下载解析全文', entry.meta.download_url, `requestwatch-session-${session.id}-${side}.txt`);
    addPaneSearch(pane, toolbar, `${session.id}:${side}`);
    if (!direction.byte_count) content.append(element('p', session.state === 'open' ? '此方向尚未捕获到应用内容，收到后会继续显示。' : '此方向未保存应用内容。', 'body-empty-state'));
    const shown = entry.state === 'ready' ? entry : entry.previous;
    if (shown) {
      if (format === 'auto') appendReadable(content, shown, caption, 'inline-tcp-body');
      else addCode(content, caption, shown.content, 'full-body inline-tcp-body');
    }
    if (entry.state === 'loading') content.append(element('p', shown ? '正在更新此方向内容…' : '正在读取此方向全部已捕获内容…', 'detail-note'));
    if (entry.state === 'error') {
      content.append(element('p', `正文读取失败：${entry.error}`, 'detail-note body-error'));
      const retry = element('button', '重新读取正文', 'button secondary compact'); retry.addEventListener('click', () => { recordSessionBodies.delete(`${side}:${format}`); renderDetailBody(); }); content.append(retry);
    }
  }
  function packetPayloadText(record) {
    const hex = requestBytes(record);
    if (!hex || hex.length % 2 || !/^[0-9a-f]+$/i.test(hex)) return record.payload_text || '';
    return new TextDecoder('utf-8').decode(Uint8Array.from(hex.match(/../g), value => parseInt(value, 16)));
  }
  function renderPacketContext(record) {
    const target = $('packet-context'); target.replaceChildren(); target.hidden = record.source === 'http' || s.tab === 'content';
    if (target.hidden) return;
    const isTcp = record.protocol === 'TCP';
    target.append(element('p', isTcp ? '当前是一条 TCP 包，通常只包含请求或响应中的一小段。整段对话请打开关联会话，查看两个方向的重组内容。' : '当前是一条 UDP 数据报，下面显示本条数据报已保存的全部载荷。', 'detail-note'));
    if (!isTcp) return;
    if (record.tcp_session_id && record.tcp_session_available !== false) addSessionLink(target, record.tcp_session_id, record.tcp_session_direction, '打开关联 TCP 会话 · 查看完整通信 →');
    else if (s.detailLoaded) target.append(element('p', record.tcp_session_error ? `TCP 会话重组失败：${record.tcp_session_error}` : record.tcp_session_available === false ? (record.tcp_session_unavailable_reason || '关联会话已超过保留范围，无法从此单包恢复其余通信内容。') : '此记录未关联可用的 TCP 会话；可能是旧版本记录、重发载荷或采集时未保存连接。', 'detail-note body-error'));
  }
  function addSessionLink(target, id, side = null, caption = '查看此连接的 TCP 会话全文 →') {
    const button = element('button', caption, 'text-button session-link');
    button.addEventListener('click', () => { setView('sessions'); selectSession(id, side); }); target.append(button);
  }
  function sessionState(session) {
    return { open: '采集中', closed: '已关闭', reset: '连接复位', interrupted: '采集中断' }[session.state] || session.state || '未知';
  }
  function sessionKey(session, side, format) {
    const direction = session.directions?.[side] || {};
    return `${session.id}:${side}:${format}:${direction.byte_count}:${direction.segment_count}:${direction.first_offset}:${direction.gap_count}:${direction.missing_bytes}:${direction.overlap_conflicts}:${direction.sequence_anomalies}:${direction.truncated_packets}:${session.state}:${session.complete}:${session.direction_inferred ?? session.midstream}`;
  }
  function renderSessions() {
    const target = $('sessions-body'); target.replaceChildren();
    s.sessions.forEach((session) => {
      const row = element('tr'); row.dataset.id = session.id; row.tabIndex = 0; row.classList.toggle('selected', s.sessionId === session.id); row.setAttribute('aria-selected', String(s.sessionId === session.id));
      const started = element('td'); started.append(element('div', time(session.created_at), 'cell-time'), badge(sessionState(session), session.complete ? 'state-forwarded' : 'state-pending'));
      const peers = element('td'); peers.append(element('div', endpoint(session.server_ip, session.server_port), 'cell-title'), element('div', `← ${endpoint(session.client_ip, session.client_port)}`, 'cell-subtitle'), element('div', session.container_name || '本机 / 未识别', 'cell-container-detail'));
      const size = element('td'); size.append(element('div', `↑ ${bytes(session.directions?.client?.byte_count)}`, 'cell-time'), element('div', `↓ ${bytes(session.directions?.server?.byte_count)}`, 'cell-time'));
      row.append(started, peers, size); row.addEventListener('click', () => selectSession(session.id)); row.addEventListener('keydown', (event) => { if (['Enter', ' '].includes(event.key)) { event.preventDefault(); selectSession(session.id); } }); target.append(row);
    });
    $('session-count').textContent = `${s.sessionTotal.toLocaleString('zh-CN')} 条会话`;
    $('sessions-empty').hidden = Boolean(s.sessions.length);
    if (!s.sessions.length) emptyState($('sessions-empty'), '没有匹配的 TCP 会话', $('session-query').value || $('session-container').value ? '调整全文关键词或容器筛选后重试。' : 'Ubuntu 抓包引擎接收到 TCP 包后，会在这里按连接重组。HTTP 代理的解密内容请查看网络流量。');
    $('session-page-info').textContent = s.sessionTotal ? `${s.sessionOffset + 1}–${Math.min(s.sessionOffset + s.sessions.length, s.sessionTotal)} / ${s.sessionTotal} 条` : '每页 50 条';
    $('session-previous').disabled = s.sessionOffset === 0; $('session-next').disabled = s.sessionOffset + 50 >= s.sessionTotal;
  }
  async function refreshSessions() {
    const version = s.sessionVersion;
    const query = new URLSearchParams({ q: $('session-query').value.trim(), container_id: $('session-container').value, limit: '50', offset: String(s.sessionOffset) });
    const result = await api(`/api/sessions?${query}`);
    if (version !== s.sessionVersion) return;
    s.sessions = result.items || []; s.sessionTotal = Number(result.total || 0);
    if (s.sessionOffset >= s.sessionTotal && s.sessionOffset > 0) { s.sessionOffset = Math.max(0, Math.floor((s.sessionTotal - 1) / 50) * 50); s.refreshAgain = true; }
    renderSessions();
    if (s.sessionId) {
      const id = s.sessionId;
      try { const session = await api(`/api/sessions/${encodeURIComponent(id)}`); if (id === s.sessionId) { s.sessionSelected = session; renderSession(); } }
      catch (error) { if (id === s.sessionId) message('session-alert', `会话更新失败：${error.message}。当前内容为上次读取的结果。`, 'compact danger'); }
    }
  }
  async function selectSession(id, preferredSide = null) {
    if (s.sessionId !== id) { s.sessionId = id; s.sessionSelected = null; s.sessionHexPage = 0; s.sessionSide = 'client'; sessionBodyCache.clear(); }
    if (['client', 'server'].includes(preferredSide)) s.sessionSide = preferredSide;
    renderSessions();
    delete $('session-content').dataset.renderKey;
    $('session-detail-empty').hidden = true; $('session-detail').hidden = false; $('session-content').replaceChildren(element('p', '正在读取会话详情…', 'detail-note'));
    try { const session = await api(`/api/sessions/${encodeURIComponent(id)}`); if (s.sessionId === id) { s.sessionSelected = session; renderSession(); } }
    catch (error) { if (s.sessionId === id) message('session-alert', `会话加载失败：${error.message}`, 'compact danger'); }
  }
  function sessionWarnings(session) {
    const notes = [];
    if (session.midstream) notes.push('捕获从连接中途开始，未观察到完整握手。');
    if (session.direction_inferred ?? session.midstream) notes.push('端点 A/B 按首个观测包确定；客户端与服务端方向仅为推测。');
    if (session.state === 'open') notes.push('连接仍在采集，下方是截至当前已保存的全部字节。');
    if (session.state === 'interrupted') notes.push('采集曾中断，不能确认整个连接完整。');
    if (session.state === 'reset') notes.push('连接以 TCP 复位结束。');
    for (const side of ['client', 'server']) {
      const direction = session.directions?.[side] || {};
      const label = sessionDirectionLabel(session, side);
      if (direction.missing_bytes || direction.gap_count) notes.push(`${label}缺失 ${direction.missing_bytes || 0} 字节、${direction.gap_count || 0} 处缺口；缺口已省略，并非完整连接。`);
      if (direction.overlap_conflicts) notes.push(`${label}有 ${direction.overlap_conflicts} 处重叠冲突。`);
      if (direction.sequence_anomalies) notes.push(`${label}有 ${direction.sequence_anomalies} 处序列号异常，不能确认内容完整。`);
      if (direction.truncated_packets) notes.push(`${label}有 ${direction.truncated_packets} 个截断包。`);
    }
    if (!session.complete && !notes.length) notes.push('尚未观察到双向完整握手和正常结束，不能确认整个连接完整。');
    return notes;
  }
  function sessionDirectionLabel(session, side) {
    if (session.direction_inferred ?? session.midstream) return side === 'client' ? '端点 A → B（方向推测）' : '端点 B → A（方向推测）';
    return side === 'client' ? '客户端 → 服务端' : '服务端 → 客户端';
  }
  function renderSession() {
    const session = s.sessionSelected; if (!session) return;
    $('session-detail-empty').hidden = true; $('session-detail').hidden = false;
    $('session-title').textContent = `TCP · ${sessionState(session)}`;
    $('session-endpoints').textContent = `${endpoint(session.client_ip, session.client_port)} ⇄ ${endpoint(session.server_ip, session.server_port)}`;
    const warnings = sessionWarnings(session);
    message('session-alert', warnings.length ? warnings.join(' ') : '已观察到完整连接，双向内容均已保存。', `compact ${warnings.length ? 'warning' : ''}`);
    const metadata = element('dl', null, 'metadata');
    addMetadata(metadata, '开始时间', time(session.created_at, true)); addMetadata(metadata, '最后更新', time(session.updated_at, true)); addMetadata(metadata, '捕获包数', session.packet_count); addMetadata(metadata, 'Docker 容器', session.container_name || '本机 / 未识别');
    $('session-metadata').replaceChildren(metadata);
    document.querySelectorAll('[data-session-side]').forEach((button) => { const active = button.dataset.sessionSide === s.sessionSide; button.classList.toggle('active', active); button.setAttribute('aria-selected', String(active)); button.textContent = sessionDirectionLabel(session, button.dataset.sessionSide); });
    const direction = session.directions?.[s.sessionSide] || {};
    $('session-content-size').textContent = `${Number(direction.byte_count || 0).toLocaleString('zh-CN')} 字节 · ${direction.segment_count || 0} 个片段`;
    renderSessionBody();
  }
  function renderSessionBody() {
    const session = s.sessionSelected; if (!session) return;
    const side = s.sessionSide; const format = s.sessionFormat;
    const direction = session.directions?.[side] || {};
    const target = $('session-content');
    const activePage = format === 'hex' ? Math.min(s.sessionHexPage, Math.max(0, Math.ceil(Number(direction.byte_count || 0) / HEX_PAGE_BYTES) - 1)) : null;
    const activeKey = sessionKey(session, side, format) + (activePage === null ? '' : `:${activePage}`);
    const renderKey = JSON.stringify([activeKey, sessionBodyCache.get(activeKey)?.state, sessionBodyCache.get(activeKey)?.error]);
    if (target.dataset.renderKey === renderKey) return;
    target.dataset.renderKey = renderKey;
    rememberReading(target); target.replaceChildren();
    let start = 0; let key = sessionKey(session, side, format);
    if (format === 'hex') {
      const total = Number(direction.byte_count || 0); const pages = Math.max(1, Math.ceil(total / HEX_PAGE_BYTES)); s.sessionHexPage = Math.min(s.sessionHexPage, pages - 1); start = s.sessionHexPage * HEX_PAGE_BYTES; key += `:${s.sessionHexPage}`;
      const controls = element('div', null, 'hex-controls');
      const previous = element('button', '上一页', 'button secondary compact'); previous.disabled = !s.sessionHexPage; previous.id = 'session-hex-previous'; previous.addEventListener('click', () => { s.sessionHexPage--; renderSessionBody(); });
      const input = element('input'); input.type = 'number'; input.min = '1'; input.max = String(pages); input.value = String(s.sessionHexPage + 1); input.id = 'session-hex-page'; input.setAttribute('aria-label', 'TCP 字节页码'); input.addEventListener('change', () => { s.sessionHexPage = Math.min(pages - 1, Math.max(0, (Number.parseInt(input.value, 10) || 1) - 1)); renderSessionBody(); });
      const next = element('button', '下一页', 'button secondary compact'); next.disabled = s.sessionHexPage + 1 >= pages; next.id = 'session-hex-next'; next.addEventListener('click', () => { s.sessionHexPage++; renderSessionBody(); });
      controls.append(previous, input, element('span', `/ ${pages} 页`, 'detail-note'), next); target.append(controls, element('p', `全部 ${total} 字节 · 当前 ${total ? start + 1 : 0}–${Math.min(start + HEX_PAGE_BYTES, total)} · 偏移为已保存内容的字节位置`, 'detail-note'));
    }
    let entry = sessionBodyCache.get(key);
    if (!entry) {
      entry = { state: 'loading' }; sessionBodyCache.set(key, entry); if (sessionBodyCache.size > 8) sessionBodyCache.delete(sessionBodyCache.keys().next().value);
      const options = format === 'hex' ? { responseType: 'bytes', headers: Number(direction.byte_count) ? { Range: `bytes=${start}-${Math.min(start + HEX_PAGE_BYTES, Number(direction.byte_count)) - 1}` } : {}, timeoutMs: 120000 } : { responseType: 'text', timeoutMs: 120000 };
      const request = format === 'auto'
        ? api(`/api/sessions/${encodeURIComponent(session.id)}/readable/${side}`, { timeoutMs: 120000 }).then(async (meta) => { entry.meta = meta; return await api(meta.content_url, { responseType: 'text', timeoutMs: 120000 }); })
        : api(`/api/sessions/${encodeURIComponent(session.id)}/body/${side}?view=${format === 'hex' ? 'raw' : format}`, options);
      request.then((result) => { entry.content = format === 'hex' ? hexForBytes(result.status === 206 ? result.data : result.data.subarray(start, start + HEX_PAGE_BYTES)) : result; entry.state = 'ready'; })
        .catch((error) => { entry.error = error.message; entry.state = 'error'; })
        .finally(() => { if (s.sessionId === session.id && s.sessionSide === side && s.sessionFormat === format) renderSessionBody(); });
    }
    if (entry.state === 'ready') {
      target.append(element('p', format === 'hex' ? '此页原始字节已载入；使用页码可访问所有已保存字节。' : '已载入此方向全部已保存内容；文本不设预览截断。', 'detail-note'));
      if (format === 'auto') appendReadable(target, entry, sessionDirectionLabel(session, side), 'session-full-body');
      else addCode(target, sessionDirectionLabel(session, side), format === 'hex' ? formatHex(entry.content, start) : entry.content, format === 'hex' ? 'hex' : 'full-body session-full-body');
    } else if (entry.state === 'loading') target.append(element('p', format === 'hex' ? '正在读取此页原始字节…' : '正在读取此方向的完整已保存内容…', 'detail-note'));
    else { target.append(element('p', `内容加载失败：${entry.error}`, 'detail-note body-error')); const retry = element('button', '重新读取', 'button secondary compact'); retry.addEventListener('click', () => { sessionBodyCache.delete(key); renderSessionBody(); }); target.append(retry); }
    if (direction.gaps?.length) {
      const details = element('details', null, 'session-gaps'); details.append(element('summary', `缺失片段位置 · ${direction.gap_count || direction.gaps.length} 处`));
      addCode(details, 'TCP 序列区间', direction.gaps.map((gap) => `${gap.start}–${gap.end}：缺失 ${gap.size} 字节`).join('\n')); target.append(details);
    }
    $('session-download-readable').hidden = format !== 'auto';
    $('session-download-readable').disabled = entry.state !== 'ready' || !entry.meta?.download_url;
    restoreReading(target, `${session.id}:${side}:${format}:${format === 'hex' ? s.sessionHexPage : ''}`);
    target.dataset.readingReady = String(entry.state === 'ready');
  }
  function sessionFilterChanged() { s.sessionOffset = 0; s.sessionVersion++; refresh(true); }


  function settingsControls() {
    const data = settingsState.data;
    const pending = data?.pending || [];
    const busy = settingsState.saving || settingsState.applying || settingsState.restartDone;
    $('settings-save').disabled = busy || !settingsState.dirty;
    $('settings-apply').disabled = busy || settingsState.dirty || !pending.length || (!data?.restart_supported && !data?.demo);
    $('settings-reload').disabled = busy;
    $('settings-apply').textContent = settingsState.applying ? '正在应用…' : data?.demo ? '模拟应用设置' : '重启服务并应用';
    $('settings-save-state').textContent = settingsState.saving ? '正在保存设置…' : settingsState.dirty ? '有尚未保存的修改' : pending.length ? `${pending.length} 项设置等待应用` : data?.restart_rollback ? '当前使用已回退配置' : '设置已应用';
    $('settings-pending').textContent = settingsState.dirty ? '保存后再应用，当前服务继续使用已生效的设置。' : pending.length ? `等待应用：${pending.map((name) => settingNames[name] || name).join('、')}。${!data.restart_supported && !data.demo ? '当前启动方式不支持自动重启；请使用 RequestWatch CLI 启动服务。' : ''}` : data?.restart_rollback ? '服务已恢复上次可用配置。修正设置后可重新保存并应用。' : '当前设置已生效，没有等待重启的修改。';
  }
  function fillSettings(data) {
    settingsState.data = data; settingsState.dirty = false; settingsState.restartDone = false;
    const values = data.saved || {};
    document.querySelectorAll('[data-setting]').forEach((input) => {
      const value = values[input.dataset.setting];
      if (input.type === 'checkbox') input.checked = Boolean(value);
      else input.value = Array.isArray(value) ? value.join(',') : value ?? '';
    });
    $('setting-token').value = ''; $('setting-token').type = 'password'; $('settings-show-token').textContent = '显示';
    $('setting-proxy-auth').value = ''; $('setting-clear-proxy-auth').checked = false; $('setting-proxy-auth').disabled = false;
    $('setting-token-state').textContent = values.token_configured ? '已配置 · 不回显' : '尚未配置';
    $('setting-proxy-auth-state').textContent = values.proxy_auth_configured ? '已配置 · 不回显' : '未启用认证';
    $('settings-data-dir').textContent = data.data_dir || '—'; $('settings-file').textContent = data.settings_path || '—';
    $('settings-interfaces').replaceChildren(new Option('全部网卡', 'any'), ...(data.interfaces || []).map((name) => new Option(name, name)));
    $('settings-rollback').hidden = !data.restart_rollback;
    $('settings-demo').hidden = !data.demo; $('settings-loading').hidden = true; $('settings-form').hidden = false;
    if (!data.pending?.includes('token')) settingsState.pendingToken = '';
    settingsControls();
  }
  async function loadSettings(force = false) {
    if (settingsState.data && !force) return;
    try { const data = await api('/api/settings'); fillSettings(data); message('settings-error', ''); }
    catch (error) { $('settings-loading').hidden = true; message('settings-error', `读取设置失败：${error.message}`, 'danger'); throw error; }
  }
  function collectSettings() {
    const values = {};
    document.querySelectorAll('[data-setting]').forEach((input) => {
      const name = input.dataset.setting;
      if (input.type === 'checkbox') values[name] = input.checked;
      else if (input.type === 'number') { const value = Number(input.value); if (!Number.isFinite(value) || !input.value.trim()) throw new Error(`${settingNames[name]}需要填写有效数字。`); values[name] = value; }
      else if (name === 'protected_ports') {
        const parts = input.value.split(/[,，]/).map((value) => value.trim()).filter(Boolean);
        if (parts.some((value) => !/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 65535)) throw new Error('保护端口必须是 1–65535 的整数，用英文逗号分隔。');
        values[name] = [...new Set(parts.map(Number))];
      } else values[name] = input.value.trim();
    });
    if ($('setting-token').value) values.token = $('setting-token').value;
    if ($('setting-clear-proxy-auth').checked) values.proxy_auth = '';
    else if ($('setting-proxy-auth').value) values.proxy_auth = $('setting-proxy-auth').value;
    return Object.fromEntries(Object.entries(values).filter(([name, value]) => ['token', 'proxy_auth'].includes(name) || JSON.stringify(value) !== JSON.stringify(settingsState.data?.saved?.[name])));
  }
  async function saveSettings(event) {
    event.preventDefault(); if (settingsState.saving || settingsState.applying || !$('settings-form').reportValidity()) return;
    let values; try { values = collectSettings(); } catch (error) { message('settings-error', error.message, 'danger'); return; }
    settingsState.saving = true; settingsControls(); message('settings-error', ''); $('settings-apply-result').hidden = true;
    try {
      const result = await api('/api/settings', { method: 'PUT', body: JSON.stringify(values) });
      if (values.token) settingsState.pendingToken = values.token;
      fillSettings(result); toast(result.demo ? '演示设置已保存，点击模拟应用即可查看效果' : '设置已保存，点击重启服务并应用即可生效');
    } catch (error) { message('settings-error', `保存失败：${error.message}`, 'danger'); }
    finally { settingsState.saving = false; settingsControls(); }
  }
  function nextAccessUrl(next) {
    let hostname = next.host;
    if (!hostname || ['0.0.0.0', '::', '[::]'].includes(hostname)) hostname = location.hostname;
    if (hostname.includes(':') && !hostname.startsWith('[')) hostname = `[${hostname}]`;
    return new URL(`${location.protocol}//${hostname}:${next.port}/#settings`);
  }
  async function waitForRestart(instanceId) {
    const deadline = Date.now() + 60000;
    while (Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      try {
        const response = await fetch('/healthz', { cache: 'no-store', signal: AbortSignal.timeout(3000) });
        const health = await response.json();
        if (response.ok && health.instance_id && health.instance_id !== instanceId) return health;
      } catch (_) { /* The listener is briefly unavailable during its restart. */ }
    }
    return false;
  }
  async function applySettings() {
    if (settingsState.applying || settingsState.dirty || !settingsState.data?.pending?.length) return;
    const originalToken = token;
    const originalUrl = new URL('/#settings', location.origin);
    settingsState.applying = true; settingsControls(); message('settings-error', ''); $('settings-next-link').hidden = true; $('settings-login-help').hidden = true; $('settings-recovery-help').hidden = true;
    $('settings-apply-result').hidden = false; $('settings-apply-message').textContent = '正在提交应用请求…';
    try {
      const result = await api('/api/settings/apply', { method: 'POST', body: '{}' });
      if (result.demo) {
        await loadSettings(true);
        $('settings-apply-message').textContent = '演示设置已模拟应用。真实监听、访问令牌和网络引擎保持演示模式。';
        toast('演示设置已应用');
      } else {
        const next = nextAccessUrl(result.next);
        $('settings-next-link').href = next.href; $('settings-next-link').textContent = `打开工作台：${next.origin} →`; $('settings-next-link').hidden = false;
        $('settings-login-help').hidden = next.origin === location.origin && !result.next.token_changed;
        if (next.origin === location.origin) {
          if (result.next.token_changed && settingsState.pendingToken) storeToken(settingsState.pendingToken);
          $('settings-apply-message').textContent = '服务正在重启，等待使用新设置重新连接…'; connection('offline', '正在重启');
          const health = await waitForRestart(result.instance_id);
          if (health) {
            if (health.restart_rollback) storeToken(originalToken);
            settingsState.data = null; await loadSettings(true);
            $('settings-apply-message').textContent = health.restart_rollback ? '新设置启动失败，服务已自动回退到上次可用配置。原地址和原令牌已恢复，当前已重新连接。' : '服务已重启，新设置已生效。';
            connection('online', health.restart_rollback ? '已恢复原配置' : '服务已连接');
          }
          else { settingsState.restartDone = true; $('settings-apply-message').textContent = '服务尚未重新连接。可打开上方地址检查启动结果；如果轮换了令牌，请使用新令牌登录。'; }
        } else {
          settingsState.restartDone = true;
          $('settings-recovery-help').hidden = false;
          $('settings-original-link').href = originalUrl.href; $('settings-original-link').textContent = `返回原地址：${originalUrl.origin} →`;
          $('settings-apply-message').textContent = '应用请求已提交。监听地址即将变更，请从下方新地址打开工作台并重新登录。';
          connection('offline', '访问地址已变更');
        }
      }
    } catch (error) { $('settings-apply-message').textContent = `应用未完成：${error.message}`; message('settings-error', '请确认当前服务状态后重新读取设置。', 'danger'); }
    finally { settingsState.applying = false; settingsControls(); }
  }

  async function loadRules() {
    const data = await api('/api/rules');
    const fingerprint = JSON.stringify(data.items || []);
    s.rules = data.items || [];
    if (fingerprint !== s.rulesFingerprint) { s.rulesFingerprint = fingerprint; renderRules(); }
  }
  function renderRules() {
    const target = $('rules-list'); target.replaceChildren();
    if (!s.rules.length) { const empty = element('div', null, 'empty-state'); emptyState(empty, '尚未创建拦截规则', '通过容器、目标地址或关键词限定范围，让需要检查的请求停在队列中。', { text: '+ 新建第一条规则', run: () => openRule() }); target.append(empty); return; }
    s.rules.forEach((rule) => {
      const card = element('article', null, `rule-card${rule.enabled ? '' : ' disabled'}`);
      const copy = element('div', null, 'rule-copy'); copy.append(element('h3', rule.name || '未命名规则'));
      const conditions = element('div', null, 'rule-conditions');
      const labels = [];
      if (rule.source && rule.source !== 'any') labels.push(rule.source === 'http' ? 'HTTP 代理' : '网络包');
      if (rule.protocol && rule.protocol !== 'any') labels.push(rule.protocol);
      if (rule.container_id) labels.push(`容器：${s.containers.find((container) => container.id === rule.container_id)?.name || rule.container_id.slice(0, 12)}`);
      if (rule.host) labels.push(`目标：${rule.host}`);
      if (rule.port) labels.push(`端口：${rule.port}`);
      if (rule.keyword) labels.push(`关键词：${rule.keyword}`);
      if (!labels.length) labels.push('匹配全部可拦截流量');
      labels.forEach((label) => conditions.append(element('span', label, 'rule-condition')));
      copy.append(conditions, element('p', `${rule.enabled ? '已启用' : '已停用'} · 等待 ${rule.timeout_seconds || 30} 秒 · 条件同时满足`, 'rule-caption'));
      const actions = element('div', null, 'rule-buttons');
      const toggle = element('button', rule.enabled ? '停用' : '启用', 'button secondary compact');
      toggle.addEventListener('click', async () => { toggle.disabled = true; try { await api(`/api/rules/${encodeURIComponent(rule.id)}`, { method: 'PUT', body: JSON.stringify(rulePayload(rule, !rule.enabled)) }); await loadRules(); toast(rule.enabled ? '规则已停用' : '规则已启用'); } catch (error) { toast(error.message, true); toggle.disabled = false; } });
      const edit = element('button', '编辑', 'text-button'); edit.addEventListener('click', () => openRule(rule));
      const remove = element('button', '删除', 'text-button'); remove.addEventListener('click', async () => { if (!await confirmAction('删除拦截规则？', `「${rule.name}」删除后，将不再暂停匹配这条规则的新流量。`, '删除规则')) return; try { await api(`/api/rules/${encodeURIComponent(rule.id)}`, { method: 'DELETE' }); await loadRules(); toast('规则已删除'); } catch (error) { toast(error.message, true); } });
      actions.append(toggle, edit, remove); card.append(element('span', null, 'rule-status'), copy, actions); target.append(card);
    });
  }
  function rulePayload(rule, enabled = rule.enabled) { return { name: rule.name, enabled, source: rule.source || 'any', protocol: rule.protocol || 'any', container_id: rule.container_id || '', host: rule.host || '', port: rule.port || null, keyword: rule.keyword || '', timeout_seconds: rule.timeout_seconds || 30 }; }
  function openRule(rule = {}) {
    $('rule-form').reset();
    $('rule-dialog-title').textContent = rule.id ? '编辑拦截规则' : '新建拦截规则';
    $('rule-id').value = rule.id || ''; $('rule-name').value = rule.name || ''; $('rule-source').value = rule.source || 'any'; $('rule-protocol').value = rule.protocol || 'any';
    if (rule.container_id && !Array.from($('rule-container').options).some((option) => option.value === rule.container_id)) $('rule-container').add(new Option(rule.container_id.slice(0, 12), rule.container_id));
    $('rule-container').value = rule.container_id || ''; $('rule-host').value = rule.host || ''; $('rule-port').value = rule.port || ''; $('rule-keyword').value = rule.keyword || ''; $('rule-timeout').value = rule.timeout_seconds || settingsState.data?.current?.default_timeout_seconds || s.status?.default_timeout_seconds || 30; $('rule-enabled').checked = rule.enabled !== false;
    message('rule-error', ''); $('rule-dialog').showModal();
  }
  async function saveRule(event) {
    event.preventDefault();
    const rule = { name: $('rule-name').value.trim(), enabled: $('rule-enabled').checked, source: $('rule-source').value, protocol: $('rule-protocol').value, container_id: $('rule-container').value, host: $('rule-host').value.trim(), port: $('rule-port').value ? Number($('rule-port').value) : null, keyword: $('rule-keyword').value, timeout_seconds: Number($('rule-timeout').value) };
    if (!rule.name) { message('rule-error', '请输入规则名称。'); return; }
    if (rule.source === 'http' && ['TCP', 'UDP'].includes(rule.protocol) || rule.source === 'packet' && ['HTTP', 'HTTPS'].includes(rule.protocol)) { message('rule-error', '接入类型与协议不一致：HTTP 代理请选择 HTTP / HTTPS，原始网络包请选择 TCP / UDP。'); return; }
    if (!rule.container_id && !rule.host && !rule.port && !rule.keyword) { message('rule-error', '至少指定容器、目标地址、端口或关键词之一，避免暂停全部网络。'); return; }
    $('save-rule').disabled = true;
    try {
      const id = $('rule-id').value;
      await api(`/api/rules${id ? `/${encodeURIComponent(id)}` : ''}`, { method: id ? 'PUT' : 'POST', body: JSON.stringify(rule) });
      $('rule-dialog').close(); toast('规则已保存'); await loadRules();
    } catch (error) { message('rule-error', error.message); }
    finally { $('save-rule').disabled = false; }
  }
  function renderContainers() {
    const target = $('containers-list'); target.replaceChildren();
    if (!s.containers.length) { const empty = element('div', null, 'empty-state'); emptyState(empty, '没有发现 Docker 容器', '确认 Docker 已启动，且 RequestWatch 可以访问 Docker socket。主机流量仍可通过网络流量页面查看。'); target.append(empty); return; }
    s.containers.forEach((container) => {
      const card = element('article', null, 'container-card');
      const heading = element('div', null, 'container-heading'); heading.append(element('h3', container.name || container.id.slice(0, 12)), badge(container.status || '未知', container.status === 'running' ? 'state-forwarded' : ''));
      const list = element('dl', null, 'metadata'); addMetadata(list, '容器 ID', container.id.slice(0, 12), true); addMetadata(list, '镜像', container.image, true); addMetadata(list, '网络模式', container.network_mode, true); addMetadata(list, 'IP 地址', (container.ips || []).join(', '), true);
      const button = element('button', '查看此容器流量 →', 'text-button'); button.addEventListener('click', () => { $('filter-container').value = container.id; setView('traffic'); });
      card.append(heading, list, button); target.append(card);
    });
  }

  document.querySelectorAll('[data-view]').forEach((button) => button.addEventListener('click', () => setView(button.dataset.view)));
  document.querySelector('.brand').addEventListener('click', (event) => { event.preventDefault(); setView('traffic'); });
  document.querySelectorAll('[data-tab]').forEach((button) => button.addEventListener('click', () => { s.tab = button.dataset.tab; renderDetail(); }));


  $('settings-form').addEventListener('submit', saveSettings);
  $('settings-form').addEventListener('input', () => { settingsState.dirty = true; $('setting-proxy-auth').disabled = $('setting-clear-proxy-auth').checked; settingsControls(); });
  $('settings-reload').addEventListener('click', async () => { if (settingsState.dirty && !await confirmAction('重新读取设置？', '未保存的设置修改会被已保存配置替换。', '重新读取')) return; try { await loadSettings(true); } catch (_) { /* Inline settings error already explains the failure. */ } });
  $('settings-apply').addEventListener('click', applySettings);
  $('settings-show-token').addEventListener('click', () => { const shown = $('setting-token').type === 'password'; $('setting-token').type = shown ? 'text' : 'password'; $('settings-show-token').textContent = shown ? '隐藏' : '显示'; });
  $('settings-generate-token').addEventListener('click', () => { const values = new Uint8Array(32); crypto.getRandomValues(values); $('setting-token').value = Array.from(values, (value) => value.toString(16).padStart(2, '0')).join(''); settingsState.dirty = true; settingsControls(); toast('随机令牌已填入，保存并应用后生效'); });

  $('refresh-sessions').addEventListener('click', () => refresh(true));
  $('session-filter-form').addEventListener('submit', (event) => { event.preventDefault(); clearTimeout(sessionSearchTimer); sessionFilterChanged(); });
  $('session-query').addEventListener('input', () => { clearTimeout(sessionSearchTimer); sessionSearchTimer = setTimeout(sessionFilterChanged, 350); });
  $('session-container').addEventListener('change', sessionFilterChanged);
  $('session-reset').addEventListener('click', () => { $('session-query').value = ''; $('session-container').value = ''; sessionFilterChanged(); });
  $('session-previous').addEventListener('click', () => { s.sessionOffset = Math.max(0, s.sessionOffset - 50); s.sessionVersion++; refresh(true); });
  $('session-next').addEventListener('click', () => { if (s.sessionOffset + 50 < s.sessionTotal) { s.sessionOffset += 50; s.sessionVersion++; refresh(true); } });
  document.querySelectorAll('[data-session-side]').forEach((button) => button.addEventListener('click', () => { s.sessionSide = button.dataset.sessionSide; s.sessionHexPage = 0; renderSession(); }));
  $('session-format').addEventListener('change', () => { s.sessionFormat = $('session-format').value; s.sessionHexPage = 0; renderSessionBody(); });
  $('session-download-readable').addEventListener('click', () => { const session = s.sessionSelected; if (!session) return; const entry = sessionBodyCache.get(sessionKey(session, s.sessionSide, 'auto')); if (entry?.meta?.download_url) download(entry.meta.download_url, `requestwatch-session-${session.id}-${s.sessionSide}-readable.txt`); });
  ['raw', 'text', 'json'].forEach((kind) => $(`session-download-${kind}`).addEventListener('click', () => { if (!s.sessionId) return; const format = kind === 'text' && s.sessionFormat === 'latin1' ? 'latin1' : kind; download(`/api/sessions/${encodeURIComponent(s.sessionId)}${kind === 'json' ? '' : `/body/${s.sessionSide}?view=${format}&download=true`}`, `requestwatch-session-${s.sessionId}-${s.sessionSide}.${kind === 'raw' ? 'bin' : kind === 'json' ? 'json' : 'txt'}`); }));

  $('filter-form').addEventListener('submit', (event) => { event.preventDefault(); clearTimeout(searchTimer); filterChanged(); });
  $('filter-query').addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(filterChanged, 350); });
  ['filter-protocol', 'filter-container', 'filter-state'].forEach((id) => $(id).addEventListener('change', filterChanged));
  $('reset-filters').addEventListener('click', resetFilters);
  $('refresh-button').addEventListener('click', () => refresh(true));
  $('poll-button').addEventListener('click', () => { s.polling = !s.polling; $('poll-button').setAttribute('aria-pressed', String(s.polling)); $('poll-button').className = `button ${s.polling ? 'primary' : 'secondary'}`; $('poll-button').replaceChildren(...(s.polling ? [element('span', null, 'live-dot'), element('span', '实时刷新')] : [element('span', '继续刷新')])); renderCaptureSummary(); if (s.polling) refresh(true); toast(s.polling ? '已恢复每 2 秒刷新' : '已暂停页面刷新，服务端仍会继续采集'); });
  $('previous-page').addEventListener('click', () => { s.offset = Math.max(0, s.offset - s.limit); s.requestVersion++; refresh(true); });
  $('next-page').addEventListener('click', () => { if (s.offset + s.limit < s.total) { s.offset += s.limit; s.requestVersion++; refresh(true); } });
  $('detail-refresh').addEventListener('click', () => refresh(true));
  $('close-detail').addEventListener('click', closeRecordDetail);
  $('detail-backdrop').addEventListener('click', closeRecordDetail);
  document.addEventListener('keydown', event => {
    if ($('record-detail-drawer').hidden || document.querySelector('dialog[open]')) return;
    if (event.key === 'Escape') { event.preventDefault(); closeRecordDetail(); }
    if (event.key === 'Tab') {
      const controls = [...$('record-detail-drawer').querySelectorAll('button, input, select, textarea, a[href], summary, [tabindex]')].filter(node => !node.disabled && node.tabIndex >= 0 && node.getClientRects().length);
      if (!controls.length) return;
      const first = controls[0]; const last = controls[controls.length - 1];
      if (event.shiftKey && (document.activeElement === first || !$('record-detail-drawer').contains(document.activeElement))) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }
  });
  $('detail-retry').addEventListener('click', () => { if (s.selectedId) selectRecord(s.selectedId); });
  $('edit-button').addEventListener('click', openEditor);
  $('edit-form').addEventListener('submit', (event) => event.preventDefault());
  $('edit-form').addEventListener('input', () => { $('draft-status').textContent = draftDirty() ? '存在未提交的修改' : '修改仅在放行 / 重发时提交'; });
  $('discard-draft').addEventListener('click', fillEditor);
  $('accept-button').addEventListener('click', () => recordAction('accept'));
  $('drop-button').addEventListener('click', () => recordAction('drop'));
  $('replay-button').addEventListener('click', () => recordAction('replay'));
  ['body-download', 'message-download'].forEach((id) => $(id).addEventListener('click', () => { if (!s.selectedId) return; const side = s.tab === 'response' ? 'response' : s.tab === 'hex' ? s.hexSide : 'request'; const isBody = id === 'body-download'; download(`/api/records/${encodeURIComponent(s.selectedId)}/${isBody ? 'body' : 'message'}/${side}${isBody ? '?view=raw&download=true' : ''}`, `requestwatch-${s.selectedId}-${side}.${isBody ? 'bin' : 'http'}`); }));
  $('export-button').addEventListener('click', () => { if (s.selectedId) download(`/api/records/${encodeURIComponent(s.selectedId)}/export`, `requestwatch-${s.selectedId}.json`); });
  $('download-ca').addEventListener('click', () => download('/api/ca', 'requestwatch-ca.pem'));
  $('auth-button').addEventListener('click', () => openAuth());
  $('guide-auth-button').addEventListener('click', () => openAuth());
  $('close-auth').addEventListener('click', () => $('auth-dialog').close());
  $('clear-token').addEventListener('click', () => { storeToken(''); $('auth-token').value = ''; s.authenticated = false; connection('offline', '令牌已清除'); message('auth-error', '令牌已清除，请输入新的访问令牌。'); });
  $('auth-form').addEventListener('submit', async (event) => {
    event.preventDefault(); storeToken($('auth-token').value.trim()); $('login-button').disabled = true; message('auth-error', '');
    try { const status = await api('/api/status'); s.authenticated = true; renderStatus(status); $('auth-dialog').close(); toast('已连接工作台'); refresh(true); }
    catch (error) { message('auth-error', `连接失败：${error.message}`); }
    finally { $('login-button').disabled = false; }
  });
  $('generate-demo-request').addEventListener('click', async () => {
    if (s.editing && draftDirty() && !await confirmAction('查看新的演示请求？', '当前编辑草稿尚未提交，打开演示请求后将丢弃此草稿。', '生成并查看')) return;
    $('generate-demo-request').disabled = true;
    try {
      const record = await api('/api/demo/intercept', { method: 'POST' });
      toast(record.state === 'pending' ? '演示请求已进入拦截队列' : '演示请求已生成');
      s.selectedId = record.id; s.selected = record; s.detailLoaded = true; s.tab = 'content'; recordSession = null; recordSessionBodies.clear(); s.editing = false; s.draftOriginal = null;
      $('edit-form').hidden = true; $('edit-button').textContent = '编辑内容';
      setView(record.state === 'pending' ? 'pending' : 'traffic'); renderDetail(true);
    } catch (error) { toast(`生成失败：${error.message}`, true); }
    finally { $('generate-demo-request').disabled = false; }
  });
  $('new-rule').addEventListener('click', () => openRule());
  $('rule-form').addEventListener('submit', saveRule);
  $('close-rule').addEventListener('click', () => $('rule-dialog').close());
  $('cancel-rule').addEventListener('click', () => $('rule-dialog').close());
  $('confirm-ok').addEventListener('click', () => finishConfirm(true));
  $('confirm-cancel').addEventListener('click', () => finishConfirm(false));
  $('confirm-dialog').addEventListener('cancel', (event) => { event.preventDefault(); finishConfirm(false); });
  $('refresh-containers').addEventListener('click', async () => { $('refresh-containers').disabled = true; try { await loadContainers(); toast('容器列表已刷新'); } catch (error) { toast(error.message, true); } finally { $('refresh-containers').disabled = false; } });
  document.addEventListener('keydown', (event) => { if (event.key === '/' && !/INPUT|TEXTAREA|SELECT/.test(event.target.tagName) && !document.querySelector('dialog[open]')) { event.preventDefault(); if (!['traffic', 'pending'].includes(s.view)) setView('traffic'); $('filter-query').focus(); } });
  window.addEventListener('beforeunload', (event) => { if (draftDirty() || settingsState.dirty) { event.preventDefault(); event.returnValue = ''; } });
  window.addEventListener('hashchange', () => { const view = location.hash.slice(1); if (titles[view] && view !== s.view) setView(view); });
  setInterval(() => { if (s.polling && s.authenticated && !document.hidden) refresh(); }, 2000);
  setView(titles[location.hash.slice(1)] ? location.hash.slice(1) : 'traffic');
})();
