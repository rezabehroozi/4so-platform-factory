'use strict';

(() => {
  const AUTHORITY = 'BOUNDED_RESOURCE_EXPLORER_AUTHORITY_V1';
  const OWNER_POLICY = 'OWNER_PRODUCT_API_ONLY';
  const PAGE_LIMIT = 25;
  const COPY = {
    en: {
      heading: 'Inspect scoped resource state', loading: 'Loading bounded resource state…', unavailable: 'Resource inspection unavailable.',
      authorityFailed: 'The bounded read authority could not be verified.', requestFailed: 'The resource authority request failed.',
      noMutation: 'No mutation action is exposed from this view.', readOnly: 'READ ONLY', taskJourney: 'Task journey', next: 'Next bounded page',
      empty: 'No resources match the current bounded page.', evidence: 'Evidence', unavailableValue: 'unavailable', inventoryStale: 'inventory stale', observed: 'observed',
      boundedHelp: 'This view is bounded, evidence-linked and never exposes raw Kubernetes mutation.',
      identityReady: 'Exact identity observed; continue only through a typed Product API owner workflow.',
      identityUnknown: 'Resource identity is incomplete; owner actions stay unavailable until exact API identity and UID are observed.'
    },
    fa: {
      heading: 'بررسی وضعیت محدودشده منابع', loading: 'در حال دریافت وضعیت محدودشده منابع…', unavailable: 'بررسی منابع در دسترس نیست.',
      authorityFailed: 'مرجع خواندن محدودشده قابل تأیید نیست.', requestFailed: 'درخواست مرجع منابع ناموفق بود.',
      noMutation: 'در این نما هیچ اقدام تغییردهنده‌ای ارائه نمی‌شود.', readOnly: 'فقط خواندنی', taskJourney: 'مسیر کار', next: 'صفحه محدود بعدی',
      empty: 'هیچ منبعی با این صفحه محدود تطبیق ندارد.', evidence: 'شواهد', unavailableValue: 'ناموجود', inventoryStale: 'موجودی قدیمی است', observed: 'مشاهده‌شده',
      boundedHelp: 'این نما محدود، متصل به شواهد و بدون دسترسی مستقیم برای تغییر منابع Kubernetes است.',
      identityReady: 'هویت دقیق مشاهده شده است؛ ادامه تغییر فقط باید از جریان کاری نوع‌دار Product API مالک انجام شود.',
      identityUnknown: 'هویت منبع کامل نیست؛ تا مشاهده API identity و UID دقیق، اقدام مالک در دسترس نمی‌شود.'
    }
  };
  const FA_TASKS = {
    operator: ['بررسی وضعیت منبع', 'بازکردن جریان کاری نوع‌دار مالک', 'بررسی اثر و تأیید', 'پیگیری عملیات و شواهد'],
    'platform-engineer': ['بررسی وضعیت منبع در محدوده مجاز', 'برنامه‌ریزی تغییر پلتفرم', 'بازکردن جریان کاری نوع‌دار مالک', 'پیگیری پیشرفت عملیات'],
    developer: ['بررسی وضعیت workload پروژه', 'بازکردن جریان کاری اپلیکیشن یا Workspace', 'پیگیری پیشرفت استقرار']
  };
  let activeClusterId = '';
  let loadGeneration = 0;

  const htmlEscape = value => String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');

  function locale() {
    return typeof state !== 'undefined' && state?.locale === 'fa' ? 'fa' : 'en';
  }

  function text(key) {
    const selected = locale();
    return COPY[selected]?.[key] || COPY.en[key] || key;
  }

  function personaForSession() {
    const roles = typeof sessionRoles === 'function' ? sessionRoles() : [];
    if (roles.includes('platform-admin')) return 'operator';
    if (roles.includes('platform-operator')) return 'platform-engineer';
    return 'developer';
  }

  function journeyFor(payload) {
    const persona = personaForSession();
    const journeys = Array.isArray(payload?.personaJourneys) ? payload.personaJourneys : [];
    return journeys.find(item => item?.persona === persona && item?.taskLanguageFirst === true) || null;
  }

  function tasksFor(payload) {
    const persona = personaForSession();
    const journey = journeyFor(payload);
    if (locale() === 'fa') return FA_TASKS[persona] || FA_TASKS.developer;
    return journey?.tasks || ['Inspect scoped resource state', 'Open a typed owner workflow only when exact ownership is known', 'Follow operation progress and evidence'];
  }

  function resourcePath(clusterId, cursor = '') {
    const query = new URLSearchParams({limit: String(PAGE_LIMIT)});
    if (cursor) query.set('cursor', cursor);
    return `/api/v1/clusters/${encodeURIComponent(clusterId)}/workloads?${query.toString()}`;
  }

  async function readResourcePage(clusterId, cursor = '') {
    const path = resourcePath(clusterId, cursor);
    if (typeof api === 'function') return api(path);
    const response = await fetch(path, {headers: {Accept: 'application/json'}});
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.error?.message || `HTTP ${response.status}`);
    return payload;
  }

  function authorityValid(payload) {
    return payload?.resourceExplorerAuthority === AUTHORITY &&
      payload?.resourcePage?.authority === AUTHORITY &&
      payload?.resourceReadOnly === true &&
      payload?.rawKubernetesMutation === false &&
      payload?.mutationContinuationPolicy === OWNER_POLICY;
  }

  function stateBadge(stateValue) {
    const normalized = String(stateValue || 'UNKNOWN').toUpperCase();
    const className = normalized === 'FRESH' ? 'success' : normalized === 'STALE' ? 'warning' : 'neutral';
    return `<span class="badge ${className}">${htmlEscape(normalized)}</span>`;
  }

  function resourceRow(item) {
    const key = item?.key || {};
    const identityComplete = Boolean(key.apiVersion && key.uid);
    const identity = [key.kind || 'Resource', key.namespace || '', key.name || 'unknown'].filter(Boolean).join(' · ');
    const evidence = String(item?.sourceDigest || '');
    const summary = item?.summary || {};
    const observed = item?.observedAt ? new Date(item.observedAt).toLocaleString(locale() === 'fa' ? 'fa-IR' : 'en-US') : '—';
    const ownerMessage = identityComplete ? text('identityReady') : text('identityUnknown');
    return `<div class="activity-item" data-resource-truth="${htmlEscape(item?.state || 'UNKNOWN')}">
      <div class="activity-main"><span class="check-icon">${identityComplete ? '○' : '?'}</span><div>
        <strong>${htmlEscape(identity)}</strong>
        <small>${stateBadge(item?.state)} · ${htmlEscape(text('observed'))} ${htmlEscape(observed)}</small>
        <small>${htmlEscape(ownerMessage)}</small>
        <small>${htmlEscape(text('evidence'))} <span class="technical">${htmlEscape(evidence ? evidence.slice(0, 19) + '…' : text('unavailableValue'))}</span>${summary.inventoryAuthorityFresh === 'false' ? ` · ${htmlEscape(text('inventoryStale'))}` : ''}</small>
      </div></div>
    </div>`;
  }

  function renderAuthorityFailure(host, message) {
    host.innerHTML = `<div class="warning-banner" data-resource-explorer-bounded="blocked"><strong>${htmlEscape(text('unavailable'))}</strong> ${htmlEscape(message)} ${htmlEscape(text('noMutation'))}</div>`;
  }

  function renderPage(host, payload, append = false) {
    if (!authorityValid(payload)) {
      renderAuthorityFailure(host, text('authorityFailed'));
      return;
    }
    const page = payload.resourcePage || {};
    const items = Array.isArray(page.items) ? page.items : [];
    const tasks = tasksFor(payload);
    const rows = items.map(resourceRow).join('') || `<p>${htmlEscape(text('empty'))}</p>`;
    const next = page.hasMore && page.nextCursor
      ? `<button type="button" class="secondary small-button" data-resource-explorer-next="${htmlEscape(page.nextCursor)}">${htmlEscape(text('next'))}</button>`
      : '';
    const content = `<div data-resource-explorer-bounded="ready" data-authority="${AUTHORITY}">
      <div class="resource-meta">${stateBadge(items.some(item => item?.state === 'UNKNOWN') ? 'UNKNOWN' : items.some(item => item?.state === 'STALE') ? 'STALE' : 'FRESH')}<span class="badge neutral">${htmlEscape(text('readOnly'))}</span></div>
      <h4>${htmlEscape(text('heading'))}</h4>
      <p>${htmlEscape(tasks[0])}. ${htmlEscape(text('boundedHelp'))}</p>
      <details><summary>${htmlEscape(text('taskJourney'))}</summary><ol>${tasks.map(task => `<li>${htmlEscape(task)}</li>`).join('')}</ol></details>
      <div class="activity-list" data-resource-explorer-items>${rows}</div>
      <div class="resource-actions">${next}</div>
    </div>`;
    if (append) {
      const list = host.querySelector('[data-resource-explorer-items]');
      if (list) list.insertAdjacentHTML('beforeend', rows);
      const actions = host.querySelector('.resource-actions');
      if (actions) actions.innerHTML = next;
      return;
    }
    host.innerHTML = content;
  }

  async function loadInto(host, clusterId, cursor = '', append = false) {
    const generation = ++loadGeneration;
    if (!append) host.innerHTML = `<p data-resource-explorer-bounded="loading">${htmlEscape(text('loading'))}</p>`;
    try {
      const payload = await readResourcePage(clusterId, cursor);
      if (generation !== loadGeneration || clusterId !== activeClusterId) return;
      renderPage(host, payload, append);
    } catch (error) {
      if (generation !== loadGeneration || clusterId !== activeClusterId) return;
      renderAuthorityFailure(host, error?.message || text('requestFailed'));
    }
  }

  function enhanceCurrentDetail() {
    if (!activeClusterId) return;
    const detail = document.getElementById('detail-content');
    const legacy = detail?.querySelector('[data-authority="WORKLOAD_EXPLORER_READ_AUTHORITY_V1"]');
    if (!legacy) return;
    let host = legacy.querySelector('[data-resource-explorer-enhancement]');
    if (!host) {
      host = document.createElement('div');
      host.dataset.resourceExplorerEnhancement = 'true';
      host.className = 'resource-explorer-enhancement';
      legacy.insertBefore(host, legacy.firstChild?.nextSibling || null);
      loadInto(host, activeClusterId);
    }
  }

  document.addEventListener('click', event => {
    const inspect = event.target.closest('[data-cluster-action="inspect"]');
    if (inspect?.dataset?.id) {
      activeClusterId = inspect.dataset.id;
      loadGeneration += 1;
      queueMicrotask(enhanceCurrentDetail);
      setTimeout(enhanceCurrentDetail, 0);
      return;
    }
    const next = event.target.closest('[data-resource-explorer-next]');
    if (!next || !activeClusterId) return;
    const host = next.closest('[data-resource-explorer-enhancement]');
    const cursor = next.dataset.resourceExplorerNext || '';
    if (host && cursor) loadInto(host, activeClusterId, cursor, true);
  });

  const detail = document.getElementById('detail-content');
  if (detail) {
    new MutationObserver(enhanceCurrentDetail).observe(detail, {childList: true, subtree: true});
  }
})();
