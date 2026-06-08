/*
 * Kiro-Go admin UI logic.
 */
(() => {
  'use strict';

  // State
  const baseUrl = location.origin;
  if (localStorage.getItem('kiro_remember') !== '1') {
    localStorage.removeItem('admin_password');
    localStorage.removeItem('admin_login_time');
  }
  let password = sessionStorage.getItem('admin_password') || localStorage.getItem('admin_password') || '';
  let currentLang = localStorage.getItem('kiro_lang') || 'zh';
  const dict = { en: null, zh: null };
  let accountsData = [];
  const selectedAccounts = new Set();
  let filterKeyword = '';
  let filterStatus = 'all';
  let privacyModeEnabled = true;
  let promptRules = [];
  let builderIdSession = '';
  let builderIdPollTimer = null;
  let iamSession = '';
  let exportSelectedIds = new Set();
  let currentVersion = '';
  let testLogs = [];
  let testModalAccountId = '';
  let testModalModels = [];
  let testModalLoadingModels = false;
  let testModalModelError = false;
  let testModalRunning = false;
  let customSelectUid = 0;
  let customSelectObserver = null;
  let customSelectRefreshQueued = false;

  // DOM helpers
  const $ = (id) => document.getElementById(id);
  const qsa = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  function escapeHtml(s) {
    const d = document.createElement('div');
    d.textContent = s == null ? '' : String(s);
    return d.innerHTML;
  }
  function escapeAttr(s) {
    return escapeHtml(s).replace(/"/g, '&quot;');
  }
  async function copyText(input) {
    const isPromise = input && typeof input.then === 'function';
    if (isPromise && typeof ClipboardItem !== 'undefined' && navigator.clipboard && navigator.clipboard.write) {
      const blobPromise = Promise.resolve(input).then(t => new Blob([String(t == null ? '' : t)], { type: 'text/plain' }));
      await navigator.clipboard.write([new ClipboardItem({ 'text/plain': blobPromise })]);
      return;
    }
    const text = isPromise ? await input : input;
    const str = String(text == null ? '' : text);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      try {
        await navigator.clipboard.writeText(str);
        return;
      } catch (e) { }
    }
    const ta = document.createElement('textarea');
    ta.value = str;
    ta.readOnly = true;
    ta.className = 'clipboard-proxy';
    document.body.appendChild(ta);
    const range = document.createRange();
    range.selectNodeContents(ta);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    ta.setSelectionRange(0, str.length);
    document.execCommand('copy');
    sel.removeAllRanges();
    document.body.removeChild(ta);
  }
  function renderEndpointCode(id, value) {
    const el = $(id);
    if (!el) return;
    const raw = String(value || '');
    el.dataset.rawValue = raw;
    try {
      const url = new URL(raw);
      const path = url.pathname + url.search + url.hash;
      el.innerHTML =
        '<span class="api-code-protocol">' + escapeHtml(url.protocol + '//') + '</span>' +
        '<span class="api-code-host">' + escapeHtml(url.host) + '</span>' +
        '<span class="api-code-path">' + escapeHtml(path) + '</span>';
    } catch (e) {
      el.textContent = raw;
    }
  }

  // i18n
  async function loadLocale(lang) {
    if (dict[lang]) return dict[lang];
    try {
      const res = await fetch('/admin/locales/' + lang + '.json?v=' + Date.now(), { cache: 'no-store' });
      dict[lang] = await res.json();
    } catch (e) {
      dict[lang] = {};
    }
    return dict[lang];
  }
  function t(key, ...args) {
    const active = dict[currentLang] || {};
    const fallback = dict.zh || {};
    let text = active[key] || fallback[key] || key;
    args.forEach((arg, idx) => { text = text.replace('{' + idx + '}', arg); });
    return text;
  }
  function applyTranslations() {
    qsa('[data-i18n]').forEach(el => { el.textContent = t(el.dataset.i18n); });
    qsa('[data-i18n-placeholder]').forEach(el => { el.placeholder = t(el.dataset.i18nPlaceholder); });
    qsa('[data-i18n-title]').forEach(el => { el.title = t(el.dataset.i18nTitle); });
    qsa('[data-i18n-aria-label]').forEach(el => { el.setAttribute('aria-label', t(el.dataset.i18nAriaLabel)); });
    document.title = t('app.title');
    document.documentElement.lang = currentLang;
    updateLangButtons();
    applyTheme(getThemePref());
    refreshCustomSelects();
  }
  async function setLang(lang) {
    currentLang = lang;
    localStorage.setItem('kiro_lang', lang);
    await loadLocale(lang);
    applyTranslations();
    renderVersionBadge();
    renderAccounts();
    renderPromptRules();
    renderLogs(logsCache);
  }
  function updateLangButtons() {
    qsa('.lang-btn').forEach(btn => btn.classList.toggle('active', btn.dataset.lang === currentLang));
    qsa('.lang-toggle').forEach(btn => {
      const label = btn.querySelector('.lang-toggle-label');
      if (label) label.textContent = currentLang === 'zh' ? t('lang.zh') : t('lang.en');
    });
  }
  function toggleLang() {
    setLang(currentLang === 'zh' ? 'en' : 'zh');
  }

  // Custom select
  function getCustomSelectLabel(select) {
    const option = select.selectedOptions && select.selectedOptions[0];
    return ((option && option.textContent) || select.value || '').trim();
  }
  function syncCustomSelect(select) {
    const wrap = select && select.__customSelect;
    if (!wrap) return;
    const value = wrap.querySelector('.custom-select-value');
    const trigger = wrap.querySelector('.custom-select-trigger');
    if (value) value.textContent = getCustomSelectLabel(select);
    if (trigger) trigger.disabled = select.disabled;
    wrap.classList.toggle('is-disabled', select.disabled);
    qsa('.custom-select-option', wrap).forEach(option => {
      const selected = option.dataset.index === String(select.selectedIndex);
      option.classList.toggle('is-selected', selected);
      option.setAttribute('aria-selected', String(selected));
    });
  }
  function renderCustomSelectOptions(select) {
    const wrap = select && select.__customSelect;
    if (!wrap) return;
    const content = wrap.querySelector('.custom-select-content');
    const trigger = wrap.querySelector('.custom-select-trigger');
    if (!content) return;
    if (trigger) labelCustomSelect(select, trigger, content, select.id);
    content.innerHTML = '';
    Array.from(select.options).forEach((option, index) => {
      const item = document.createElement('button');
      item.type = 'button';
      item.className = 'custom-select-option';
      item.setAttribute('role', 'option');
      item.dataset.index = String(index);
      item.disabled = option.disabled;
      item.textContent = (option.textContent || option.value || '').trim();
      content.appendChild(item);
    });
    syncCustomSelect(select);
  }
  function placeCustomSelectContent(select) {
    const wrap = select && select.__customSelect;
    if (!wrap || !wrap.classList.contains('is-open')) return;
    const trigger = wrap.querySelector('.custom-select-trigger');
    const content = wrap.querySelector('.custom-select-content');
    if (!trigger || !content) return;
    const rect = trigger.getBoundingClientRect();
    const gap = 4;
    const below = window.innerHeight - rect.bottom - gap;
    const above = rect.top - gap;
    const openUp = below < 180 && above > below;
    const available = Math.max(96, Math.min(224, (openUp ? above : below) - 4));
    content.style.left = Math.round(rect.left) + 'px';
    content.style.width = Math.round(rect.width) + 'px';
    content.style.maxHeight = Math.round(available) + 'px';
    content.style.top = openUp ? 'auto' : Math.round(rect.bottom + gap) + 'px';
    content.style.bottom = openUp ? Math.round(window.innerHeight - rect.top + gap) + 'px' : 'auto';
    content.dataset.side = openUp ? 'top' : 'bottom';
  }
  function setCustomSelectOpen(select, open) {
    const wrap = select && select.__customSelect;
    if (!wrap) return;
    const trigger = wrap.querySelector('.custom-select-trigger');
    const content = wrap.querySelector('.custom-select-content');
    if (!trigger || !content) return;
    if (open && !select.disabled) {
      closeAllCustomSelects(select);
      renderCustomSelectOptions(select);
      wrap.classList.add('is-open');
      trigger.setAttribute('aria-expanded', 'true');
      content.hidden = false;
      placeCustomSelectContent(select);
      requestAnimationFrame(() => placeCustomSelectContent(select));
      const selected = content.querySelector('.custom-select-option.is-selected:not(:disabled)') || content.querySelector('.custom-select-option:not(:disabled)');
      if (selected) selected.focus({ preventScroll: true });
    } else {
      wrap.classList.remove('is-open');
      trigger.setAttribute('aria-expanded', 'false');
      content.hidden = true;
    }
  }
  function closeAllCustomSelects(except) {
    qsa('select.custom-select-native').forEach(select => {
      if (select !== except) setCustomSelectOpen(select, false);
    });
  }
  function chooseCustomSelectOption(select, index) {
    const option = select.options[index];
    if (!option || option.disabled) return;
    select.value = option.value;
    select.dispatchEvent(new Event('input', { bubbles: true }));
    select.dispatchEvent(new Event('change', { bubbles: true }));
    syncCustomSelect(select);
    setCustomSelectOpen(select, false);
    const trigger = select.__customSelect && select.__customSelect.querySelector('.custom-select-trigger');
    if (trigger && trigger.isConnected) trigger.focus({ preventScroll: true });
  }
  function focusSiblingCustomOption(current, dir) {
    const options = qsa('.custom-select-option:not(:disabled)', current.parentElement);
    const index = options.indexOf(current);
    const next = options[(index + dir + options.length) % options.length];
    if (next) next.focus({ preventScroll: true });
  }
  function getCustomSelectLabelElement(select) {
    const explicit = qsa('label').find(label => label.htmlFor === select.id);
    if (explicit) return explicit;
    const group = select.closest('.form-group');
    return group ? group.querySelector('label') : null;
  }
  function labelCustomSelect(select, trigger, content, id) {
    trigger.id = id + '-trigger';
    const valueId = id + '-value';
    const value = trigger.querySelector('.custom-select-value');
    if (value) value.id = valueId;
    const label = getCustomSelectLabelElement(select);
    if (label) {
      if (!label.id) label.id = id + '-label';
      trigger.removeAttribute('aria-label');
      trigger.setAttribute('aria-labelledby', label.id + ' ' + valueId);
    } else {
      trigger.removeAttribute('aria-labelledby');
      trigger.setAttribute('aria-label', select.getAttribute('aria-label') || getCustomSelectLabel(select));
    }
    content.setAttribute('aria-labelledby', trigger.id);
  }
  function enhanceCustomSelect(select) {
    if (!select || select.__customSelect || select.dataset.nativeSelect === 'true') return;

    const id = select.id || 'custom-select-' + (++customSelectUid);
    if (!select.id) select.id = id;

    const wrap = document.createElement('div');
    wrap.className = 'custom-select';
    wrap.dataset.customSelect = 'true';
    if (select.id === 'filterStatusSelect') wrap.classList.add('custom-select-filter');

    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'custom-select-trigger';
    trigger.setAttribute('aria-haspopup', 'listbox');
    trigger.setAttribute('aria-expanded', 'false');
    trigger.setAttribute('aria-controls', id + '-menu');
    trigger.innerHTML =
      '<span class="custom-select-value"></span>' +
      '<i class="fa-solid fa-chevron-down custom-select-icon" aria-hidden="true"></i>';

    const content = document.createElement('div');
    content.id = id + '-menu';
    content.className = 'custom-select-content';
    content.setAttribute('role', 'listbox');
    content.hidden = true;
    labelCustomSelect(select, trigger, content, id);

    wrap.appendChild(trigger);
    wrap.appendChild(content);
    select.insertAdjacentElement('afterend', wrap);
    select.classList.add('custom-select-native');
    select.setAttribute('aria-hidden', 'true');
    select.tabIndex = -1;
    select.__customSelect = wrap;
    wrap.__nativeSelect = select;

    trigger.addEventListener('click', () => setCustomSelectOpen(select, !wrap.classList.contains('is-open')));
    trigger.addEventListener('keydown', e => {
      if (['ArrowDown', 'ArrowUp', 'Enter', ' '].includes(e.key)) {
        e.preventDefault();
        setCustomSelectOpen(select, true);
      }
    });
    content.addEventListener('click', e => {
      const option = e.target.closest('.custom-select-option');
      if (!option) return;
      chooseCustomSelectOption(select, parseInt(option.dataset.index, 10));
    });
    content.addEventListener('keydown', e => {
      const option = e.target.closest('.custom-select-option');
      if (!option) return;
      if (e.key === 'ArrowDown') { e.preventDefault(); focusSiblingCustomOption(option, 1); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); focusSiblingCustomOption(option, -1); }
      else if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); chooseCustomSelectOption(select, parseInt(option.dataset.index, 10)); }
      else if (e.key === 'Escape') { e.preventDefault(); setCustomSelectOpen(select, false); trigger.focus({ preventScroll: true }); }
    });
    select.addEventListener('change', () => syncCustomSelect(select));
    renderCustomSelectOptions(select);
  }
  function enhanceCustomSelects(root) {
    qsa('select:not(.custom-select-native)', root || document).forEach(enhanceCustomSelect);
  }
  function refreshCustomSelects(root) {
    enhanceCustomSelects(root);
    qsa('select.custom-select-native', root || document).forEach(renderCustomSelectOptions);
  }
  function positionOpenCustomSelects() {
    qsa('select.custom-select-native').forEach(placeCustomSelectContent);
  }
  function queueCustomSelectRefresh() {
    if (customSelectRefreshQueued) return;
    customSelectRefreshQueued = true;
    requestAnimationFrame(() => {
      customSelectRefreshQueued = false;
      refreshCustomSelects();
      positionOpenCustomSelects();
    });
  }
  function initCustomSelectObserver() {
    if (customSelectObserver || !document.body || typeof MutationObserver === 'undefined') return;
    customSelectObserver = new MutationObserver(mutations => {
      let shouldRefresh = false;
      for (const mutation of mutations) {
        const target = mutation.target;
        if (target && target.closest && target.closest('.custom-select')) continue;
        if (target && target.matches && target.matches('select')) {
          shouldRefresh = true;
          break;
        }
        for (const node of mutation.addedNodes || []) {
          if (node.nodeType !== 1) continue;
          if ((node.matches && node.matches('select')) || (node.querySelector && node.querySelector('select'))) {
            shouldRefresh = true;
            break;
          }
        }
        if (shouldRefresh) break;
      }
      if (shouldRefresh) queueCustomSelectRefresh();
    });
    customSelectObserver.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['disabled', 'class', 'id', 'data-native-select']
    });
  }

  // Theme
  const THEME_ORDER = ['system', 'light', 'dark'];
  const themeMQ = window.matchMedia('(prefers-color-scheme: dark)');
  function resolveTheme(pref) {
    if (pref === 'dark') return 'dark';
    if (pref === 'light') return 'light';
    return themeMQ.matches ? 'dark' : 'light';
  }
  function applyTheme(pref) {
    const resolved = resolveTheme(pref);
    const root = document.documentElement;
    root.classList.toggle('dark', resolved === 'dark');
    root.dataset.themePref = pref;
    qsa('.theme-toggle').forEach(btn => {
      btn.dataset.theme = pref;
      const themeLabel = t('theme.status', t('theme.' + pref));
      btn.setAttribute('aria-label', themeLabel);
      btn.setAttribute('title', themeLabel);
    });
  }
  function getThemePref() {
    const saved = localStorage.getItem('kiro_theme');
    return THEME_ORDER.includes(saved) ? saved : 'system';
  }
  function initTheme() {
    applyTheme(getThemePref());
    themeMQ.addEventListener('change', () => {
      if (getThemePref() === 'system') applyTheme('system');
    });
  }
  function toggleTheme() {
    const cur = getThemePref();
    const next = THEME_ORDER[(THEME_ORDER.indexOf(cur) + 1) % THEME_ORDER.length];
    localStorage.setItem('kiro_theme', next);
    applyTheme(next);
  }

  // Privacy and email mask
  function initPrivacyMode() {
    const saved = localStorage.getItem('privacyMode');
    privacyModeEnabled = saved === null ? true : saved === 'true';
    const toggle = $('privacyModeToggle');
    if (toggle) toggle.checked = privacyModeEnabled;
  }
  function maskEmail(email) {
    if (!privacyModeEnabled || !email || email.indexOf('@') === -1) return email;
    const [local, domain] = email.split('@');
    const maskedLocal = local.length <= 2 ? local : local.substring(0, 2) + '***';
    const parts = domain.split('.');
    if (parts.length >= 2) {
      const tld = parts[parts.length - 1];
      const sld = parts[parts.length - 2];
      const maskedSld = sld.length <= 2 ? sld : sld.substring(0, 2) + '***';
      const subs = parts.slice(0, -2).map(s => s.length <= 2 ? s : s.substring(0, 2) + '***');
      return maskedLocal + '@' + [...subs, maskedSld, tld].join('.');
    }
    return maskedLocal + '@' + domain;
  }
  function getDisplayEmail(email, id) {
    const raw = email || (id ? id.substring(0, 12) + '...' : '-');
    return maskEmail(raw);
  }

  // Toast bridge
  const toast = function (msg, variant, opts) {
    if (typeof window.toast === 'function') return window.toast(msg, variant, opts);
    try { console.warn('[toast missing]', variant, msg); } catch (_) { }
    return function () {};
  };
  const toastPrimary = (msg, opts) => toast(msg, 'primary', opts);
  const toastWarning = (msg, opts) => toast(msg, 'warning', opts);
  const toastError = (msg, opts) => toast(msg, 'error', opts);

  // Modal helpers
  let modalScrollY = 0;
  let confirmResolve = null;
  const modalFocusStack = [];
  function lockModalScroll() {
    if (document.body.classList.contains('modal-open')) return;
    modalScrollY = window.scrollY || document.documentElement.scrollTop || 0;
    document.body.style.top = '-' + modalScrollY + 'px';
    document.body.classList.add('modal-open');
  }
  function unlockModalScrollIfIdle() {
    if (qsa('.modal.active').length > 0) return;
    if (!document.body.classList.contains('modal-open')) return;
    document.body.classList.remove('modal-open');
    document.body.style.top = '';
    window.scrollTo(0, modalScrollY);
  }
  function getModalFocusable(modal) {
    return qsa('a[href], button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])', modal)
      .filter(el => !el.closest('[hidden]'));
  }
  function prepareDialog(modal) {
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.setAttribute('aria-hidden', 'false');
    if (!modal.hasAttribute('tabindex')) modal.tabIndex = -1;
    const title = modal.querySelector('.modal-title');
    if (title) {
      if (!title.id) title.id = modal.id + 'Title';
      modal.setAttribute('aria-labelledby', title.id);
    }
  }
  function focusDialog(modal) {
    if (modal.contains(document.activeElement) && document.activeElement !== modal) return;
    const focusable = getModalFocusable(modal);
    const target = focusable[0] || modal;
    if (target && target.focus) target.focus({ preventScroll: true });
  }
  function trapDialogFocus(e) {
    const modal = e.currentTarget;
    if (e.key !== 'Tab' || !modal.classList.contains('active')) return;
    const focusable = getModalFocusable(modal);
    if (!focusable.length) {
      e.preventDefault();
      modal.focus({ preventScroll: true });
      return;
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus({ preventScroll: true });
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus({ preventScroll: true });
    }
  }
  function openDialog(id) {
    const modal = $(id);
    if (!modal) return;
    prepareDialog(modal);
    modalFocusStack.push({ id, el: document.activeElement });
    modal.removeEventListener('keydown', trapDialogFocus);
    modal.addEventListener('keydown', trapDialogFocus);
    modal.classList.add('active');
    lockModalScroll();
    focusDialog(modal);
    setTimeout(() => focusDialog(modal), 0);
  }
  function closeDialog(id) {
    const modal = $(id);
    if (!modal) return;
    modal.classList.remove('active');
    modal.setAttribute('aria-hidden', 'true');
    const stackIndex = modalFocusStack.map(item => item.id).lastIndexOf(id);
    const previous = stackIndex >= 0 ? modalFocusStack.splice(stackIndex, 1)[0].el : null;
    unlockModalScrollIfIdle();
    if (previous && previous.isConnected && previous.focus) {
      requestAnimationFrame(() => previous.focus({ preventScroll: true }));
    }
  }
  function bindDialogBackdropClose(id, closeFn) {
    const modal = $(id);
    if (!modal) return;
    let startedOnBackdrop = false;
    modal.addEventListener('pointerdown', e => {
      startedOnBackdrop = e.target === modal;
    });
    modal.addEventListener('click', e => {
      if (startedOnBackdrop && e.target === modal) closeFn();
      startedOnBackdrop = false;
    });
  }
  function closeConfirm(value) {
    if (!confirmResolve) return;
    const resolve = confirmResolve;
    confirmResolve = null;
    closeDialog('confirmModal');
    resolve(!!value);
  }
  function confirmAction(message, opts) {
    opts = opts || {};
    if (confirmResolve) closeConfirm(false);
    const modal = $('confirmModal');
    const title = $('confirmTitle');
    const msg = $('confirmMessage');
    const ok = $('confirmOk');
    const cancel = $('confirmCancel');
    const close = $('confirmClose');
    if (!modal || !title || !msg || !ok || !cancel || !close) {
      return Promise.resolve(false);
    }
    title.textContent = opts.title || t('common.confirm');
    msg.textContent = message || '';
    ok.textContent = opts.confirmText || t('common.confirm');
    cancel.textContent = opts.cancelText || t('common.cancel');
    ok.className = 'btn ' + (opts.variant === 'danger' ? 'btn-danger' : 'btn-primary');
    cancel.className = 'btn btn-secondary';
    ok.onclick = () => closeConfirm(true);
    cancel.onclick = () => closeConfirm(false);
    close.onclick = () => closeConfirm(false);
    const pending = new Promise(resolve => { confirmResolve = resolve; });
    openDialog('confirmModal');
    ok.focus({ preventScroll: true });
    return pending;
  }

  // Fetch wrapper
  function api(path, opts) {
    opts = opts || {};
    opts.headers = Object.assign({ 'X-Admin-Password': password }, opts.headers || {});
    if (opts.body && !opts.headers['Content-Type']) opts.headers['Content-Type'] = 'application/json';
    return fetch('/admin/api' + path, opts);
  }

  // Login
  function clearActivePassword() {
    sessionStorage.removeItem('admin_password');
    sessionStorage.removeItem('admin_login_time');
    localStorage.removeItem('admin_password');
    localStorage.removeItem('admin_login_time');
    password = '';
  }
  function getActiveLoginTime() {
    const storage = sessionStorage.getItem('admin_password') ? sessionStorage : localStorage;
    return parseInt(storage.getItem('admin_login_time') || '0', 10);
  }
  function setActivePassword(nextPassword, remember) {
    const now = Date.now().toString();
    password = nextPassword;
    sessionStorage.setItem('admin_password', nextPassword);
    sessionStorage.setItem('admin_login_time', now);
    if (remember) {
      localStorage.setItem('admin_password', nextPassword);
      localStorage.setItem('admin_login_time', now);
      localStorage.setItem('kiro_remember', '1');
      localStorage.setItem('kiro_remembered_pwd', nextPassword);
    } else {
      localStorage.removeItem('admin_password');
      localStorage.removeItem('admin_login_time');
      localStorage.removeItem('kiro_remember');
      localStorage.removeItem('kiro_remembered_pwd');
    }
  }
  async function tryAutoLogin() {
    if (!password) return;
    const loginTime = getActiveLoginTime();
    if (loginTime && Date.now() - loginTime > 72 * 3600 * 1000) {
      clearActivePassword();
      return;
    }
    try {
      const res = await api('/status');
      if (res.ok) { showMain(); loadData(); }
    } catch (e) { }
  }
  async function login() {
    password = $('pwdField').value;
    try {
      const res = await api('/status');
      if (res.ok) {
        const remember = $('rememberPwd');
        setActivePassword(password, !!(remember && remember.checked));
        showMain(); loadData();
      } else {
        toast(t('login.error'), 'error');
      }
    } catch (e) {
      toast(t('login.connectError'), 'error');
    }
  }
  function initRememberMe() {
    const remember = $('rememberPwd');
    const field = $('pwdField');
    if (!remember || !field) return;
    if (localStorage.getItem('kiro_remember') === '1') {
      remember.checked = true;
      const saved = localStorage.getItem('kiro_remembered_pwd');
      if (saved) field.value = saved;
    }
  }
  function logout() {
    clearActivePassword();
    location.reload();
  }
  function showMain() {
    $('loginPage').classList.add('hidden');
    $('mainPage').classList.remove('hidden');
  }

  // Data loaders
  async function loadData() {
    await Promise.all([loadStats(), loadAccounts(), loadSettings(), loadVersion()]);
    renderEndpointCode('claudeEndpoint', baseUrl + '/v1/messages');
    renderEndpointCode('openaiEndpoint', baseUrl + '/v1/chat/completions');
    renderEndpointCode('openaiResponsesEndpoint', baseUrl + '/v1/responses');
    renderEndpointCode('modelsEndpoint', baseUrl + '/v1/models');
    renderEndpointCode('statsEndpoint', baseUrl + '/v1/stats');
    setTimeout(checkUpdate, 2000);
  }
  async function loadStats() {
    const res = await api('/status');
    const d = await res.json();
    $('statAccounts').textContent = d.accounts || 0;
    $('statRequests').textContent = d.totalRequests || 0;
    $('statSuccess').textContent = d.successRequests || 0;
    $('statFailed').textContent = d.failedRequests || 0;
    $('statTokens').textContent = formatNum(d.totalTokens || 0);
    $('statCredits').textContent = (d.totalCredits || 0).toFixed(1);
  }

  // ===== Logs =====
  let logsFilter = 'all';
  let logsAutoTimer = null;
  let logsCache = [];

  function errorTypeLabel(type) {
    if (!type) return '';
    const key = 'errors.type' + type.charAt(0).toUpperCase() + type.slice(1);
    return t(key) || type;
  }

  function formatLogTime(ts) {
    const d = new Date(ts * 1000);
    const pad = n => String(n).padStart(2, '0');
    return pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' +
      pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
  }

  function accountLabel(id) {
    if (!id) return '-';
    const acc = accountsData.find(a => a.id === id);
    if (acc && acc.email) {
      return privacyModeEnabled ? maskEmail(acc.email) : acc.email;
    }
    return id.slice(0, 8);
  }

  async function loadLogs() {
    try {
      const res = await api('/logs');
      const d = await res.json();
      const logs = d.logs || [];
      renderLogs(logs);
    } catch (e) {
      // silent
    }
  }

  function renderLogs(logs) {
    logsCache = logs;
    const list = $('logsList');
    const summary = $('logsSummary');
    if (!list) return;

    const total = logs.length;
    const okCount = logs.filter(l => l.status === 'success').length;
    const errCount = total - okCount;
    summary.innerHTML =
      '<span>' + escapeHtml(t('logs.total')) + ': <strong>' + total + '</strong></span>' +
      '<span>' + escapeHtml(t('logs.success')) + ': <strong>' + okCount + '</strong></span>' +
      '<span>' + escapeHtml(t('logs.errors')) + ': <strong>' + errCount + '</strong></span>';

    const filtered = logs.filter(l => logsFilter === 'all' || l.status === logsFilter);

    if (!filtered.length) {
      list.innerHTML = '<p class="text-muted">' + escapeHtml(t('logs.empty')) + '</p>';
      return;
    }

    let html = '<table class="logs-table"><thead><tr>' +
      '<th>' + escapeHtml(t('logs.time')) + '</th>' +
      '<th>' + escapeHtml(t('logs.status')) + '</th>' +
      '<th>' + escapeHtml(t('logs.endpoint')) + '</th>' +
      '<th>' + escapeHtml(t('logs.model')) + '</th>' +
      '<th>' + escapeHtml(t('logs.account')) + '</th>' +
      '<th>' + escapeHtml(t('logs.tokens')) + '</th>' +
      '<th>' + escapeHtml(t('logs.duration')) + '</th>' +
      '<th>' + escapeHtml(t('logs.detail')) + '</th>' +
      '</tr></thead><tbody>';
    for (const l of filtered) {
      const isErr = l.status === 'error';
      const statusCell = '<span class="log-status log-status--' + escapeAttr(l.status) + '">' +
        escapeHtml(isErr ? t('logs.statusError') : t('logs.statusSuccess')) + '</span>';
      let detailCell;
      if (isErr) {
        detailCell = '<span class="err-badge err-badge--' + escapeAttr(l.errorType || 'unknown') + '">' +
          escapeHtml(errorTypeLabel(l.errorType || 'unknown')) + '</span> ' +
          '<span class="log-msg" title="' + escapeAttr(l.error) + '">' + escapeHtml(l.error) + '</span>';
      } else {
        detailCell = '<span class="text-muted">' + (l.credits ? (l.credits.toFixed(3) + ' cr') : '-') + '</span>';
      }
      html += '<tr>' +
        '<td>' + escapeHtml(formatLogTime(l.time)) + '</td>' +
        '<td>' + statusCell + '</td>' +
        '<td>' + escapeHtml(l.endpoint) + '</td>' +
        '<td>' + escapeHtml(l.model || '-') + '</td>' +
        '<td>' + escapeHtml(accountLabel(l.accountId)) + '</td>' +
        '<td>' + (l.tokens ? formatNum(l.tokens) : '-') + '</td>' +
        '<td>' + (l.duration ? (l.duration + 'ms') : '-') + '</td>' +
        '<td>' + detailCell + '</td>' +
        '</tr>';
    }
    html += '</tbody></table>';
    list.innerHTML = html;
  }

  async function clearLogs() {
    if (!confirm(t('logs.clearConfirm'))) return;
    await api('/logs', { method: 'DELETE' });
    renderLogs([]);
    toast(t('logs.cleared'), 'success');
  }

  function toggleLogsAutoRefresh() {
    const on = $('logsAutoRefresh').checked;
    if (logsAutoTimer) { clearInterval(logsAutoTimer); logsAutoTimer = null; }
    if (on) {
      logsAutoTimer = setInterval(() => {
        if (!$('tabLogs').classList.contains('hidden')) loadLogs();
      }, 5000);
    }
  }

  async function loadAccounts() {
    const res = await api('/accounts');
    accountsData = await res.json();
    renderAccounts();
  }

  // Account list
  function getFilteredAccounts() {
    return accountsData.filter(a => {
      if (filterStatus === 'enabled' && !a.enabled) return false;
      if (filterStatus === 'disabled' && (a.enabled || (a.banStatus && a.banStatus !== 'ACTIVE'))) return false;
      if (filterStatus === 'banned' && (!a.banStatus || a.banStatus === 'ACTIVE')) return false;
      if (filterKeyword) {
        const kw = filterKeyword.toLowerCase();
        if (!(a.email || '').toLowerCase().includes(kw)) return false;
      }
      return true;
    });
  }
  function onFilterChange() {
    filterKeyword = $('filterSearch').value;
    filterStatus = $('filterStatusSelect').value;
    renderAccounts();
  }
  function toggleSelectAll(checked) {
    const filtered = getFilteredAccounts();
    if (checked) filtered.forEach(a => selectedAccounts.add(a.id));
    else selectedAccounts.clear();
    renderAccounts();
    updateBatchBar();
  }
  function toggleSelectAccount(id) {
    if (selectedAccounts.has(id)) selectedAccounts.delete(id);
    else selectedAccounts.add(id);
    updateBatchBar();
  }
  function updateBatchBar() {
    const bar = $('batchBar');
    const count = selectedAccounts.size;
    const cb = $('selectAllCheckbox');
    if (cb) {
      const filtered = getFilteredAccounts();
      const selectedFiltered = filtered.filter(a => selectedAccounts.has(a.id)).length;
      cb.checked = filtered.length > 0 && selectedFiltered === filtered.length;
      cb.indeterminate = selectedFiltered > 0 && selectedFiltered < filtered.length;
    }
    if (count > 0) {
      bar.classList.remove('hidden');
      $('batchCount').textContent = String(count);
    } else {
      bar.classList.add('hidden');
    }
  }

  function formatSubscriptionLabel(type) {
    const s = (type || '').toUpperCase();
    if (s.includes('POWER')) return t('subscription.power');
    if (s.includes('PRO_PLUS') || s.includes('PROPLUS')) return t('subscription.proPlus');
    if (s.includes('PRO')) return t('subscription.pro');
    if (s.includes('FREE')) return t('subscription.free');
    return type || t('subscription.free');
  }
  function getSubBadge(type) {
    const s = (type || '').toUpperCase();
    if (s.includes('POWER')) return '<span class="badge badge-power">' + escapeHtml(formatSubscriptionLabel(type)) + '</span>';
    if (s.includes('PRO_PLUS') || s.includes('PROPLUS')) return '<span class="badge badge-proplus">' + escapeHtml(formatSubscriptionLabel(type)) + '</span>';
    if (s.includes('PRO')) return '<span class="badge badge-pro">' + escapeHtml(formatSubscriptionLabel(type)) + '</span>';
    return '<span class="badge badge-free">' + escapeHtml(formatSubscriptionLabel(type)) + '</span>';
  }
  function getTrialBadge(a) {
    if (a.trialStatus === 'ACTIVE' && a.trialUsageLimit > 0) {
      return '<span class="badge badge-trial">' + escapeHtml(t('accounts.trial')) + '</span>';
    }
    return '';
  }
  function formatTrialExpiry(ts) {
    if (!ts) return '';
    const date = new Date(ts * 1000);
    const diffDays = Math.ceil((date - new Date()) / (1000 * 60 * 60 * 24));
    if (diffDays < 0) return '(' + t('accounts.trialExpired') + ')';
    if (diffDays === 0) return '(' + t('accounts.trialToday') + ')';
    if (diffDays <= 7) return '(' + diffDays + t('accounts.trialDays') + ')';
    return '';
  }
  function formatAuthMethod(method) {
    if (!method) return '-';
    const normalized = String(method).toLowerCase();
    if (normalized === 'idc') return t('auth.enterprise');
    if (normalized === 'social') return t('auth.social');
    if (normalized === 'builderid') return 'BuilderID';
    if (normalized === 'github') return t('local.providerGithub');
    if (normalized === 'google') return t('local.providerGoogle');
    return method;
  }
  function getStatusBadge(a) {
    const out = [];
    const isBanned = a.banStatus && a.banStatus !== 'ACTIVE';
    if (isBanned) {
      if (a.banStatus === 'BANNED') out.push('<span class="badge badge-banned">' + escapeHtml(t('accounts.banned')) + '</span>');
      else if (a.banStatus === 'SUSPENDED') out.push('<span class="badge badge-suspended">' + escapeHtml(t('accounts.suspended')) + '</span>');
      out.push('<span class="badge badge-warning">' + escapeHtml(t('accounts.disabled')) + '</span>');
    } else {
      if (!a.hasToken)
        out.push('<span class="badge badge-error">' + escapeHtml(t('accounts.noToken')) + '</span>');
      else if (a.expiresAt && a.expiresAt < Date.now() / 1000)
        out.push('<span class="badge badge-warning">' + escapeHtml(t('accounts.expired')) + '</span>');
      else
        out.push('<span class="badge badge-success">' + escapeHtml(t('accounts.normal')) + '</span>');
      out.push(a.enabled
        ? '<span class="badge badge-info">' + escapeHtml(t('accounts.enabled')) + '</span>'
        : '<span class="badge badge-warning">' + escapeHtml(t('accounts.disabled')) + '</span>');
    }
    return out.join('');
  }
  function formatTokenExpiry(ts) {
    if (!ts) return '-';
    const diff = ts - Date.now() / 1000;
    if (diff <= 0) return t('time.expired');
    if (diff < 3600) return Math.floor(diff / 60) + t('time.minutes');
    if (diff < 86400) return Math.floor(diff / 3600) + t('time.hours');
    return Math.floor(diff / 86400) + t('time.days');
  }
  function formatNum(n) {
    if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
    return n.toString();
  }
  function applyUsageBars(root) {
    qsa('.usage-fill[data-usage-pct]', root).forEach(el => {
      const pct = Math.max(0, Math.min(100, parseFloat(el.dataset.usagePct) || 0));
      el.style.width = pct + '%';
    });
  }

  function renderAccounts() {
    const container = $('accountsList');
    if (!container) return;
    const filtered = getFilteredAccounts();
    if (filtered.length === 0) {
      container.innerHTML = '<div class="empty-state">' + escapeHtml(t('accounts.empty')) + '</div>';
      return;
    }
    container.innerHTML = filtered.map(a => {
      const usagePct = (a.usagePercent || 0) * 100;
      const usageClass = usagePct > 90 ? 'critical' : usagePct > 70 ? 'high' : '';
      const trialPct = (a.trialUsagePercent || 0) * 100;
      const trialClass = trialPct > 90 ? 'critical' : trialPct > 70 ? 'high' : '';
      const isSelected = selectedAccounts.has(a.id);
      const weight = a.weight || 0;
      const weightBadge = weight >= 2 ? '<span class="badge badge-warning">' + escapeHtml(t('accounts.weightShort')) + ':' + weight + '</span>' : '';
      const overageBadge = renderOverageBadge(a);
      const banned = a.banStatus && a.banStatus !== 'ACTIVE';
      const idAttr = escapeAttr(a.id);
      const displayEmail = getDisplayEmail(a.email, a.id);
      const selectLabel = t('accounts.selectAccount', displayEmail);

      const refreshSvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>';
      const userSvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>';
      const copySvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';

      return '' +
        '<div class="account-card' + (isSelected ? ' selected' : '') + '" data-id="' + idAttr + '">' +
        '<div class="account-header">' +
        '<div class="account-info">' +
        '<input type="checkbox" class="account-checkbox" ' + (isSelected ? 'checked' : '') + ' data-id="' + idAttr + '" aria-label="' + escapeAttr(selectLabel) + '" />' +
        '<div class="account-info-text">' +
        '<div class="account-email">' + escapeHtml(displayEmail) + '</div>' +
        '<div class="account-meta">' +
        getSubBadge(a.subscriptionType) +
        getTrialBadge(a) +
        weightBadge +
        overageBadge +
        '<span class="badge badge-info">' + escapeHtml(formatAuthMethod(a.provider || a.authMethod)) + '</span>' +
        getStatusBadge(a) +
        '</div>' +
        '</div>' +
        '</div>' +
        '<div class="account-actions">' +
        '<button class="btn btn-icon btn-sm btn-ghost" data-action="refresh" data-id="' + idAttr + '" title="' + escapeAttr(t('accounts.refresh')) + '">' + refreshSvg + '</button>' +
        '<button class="btn btn-icon btn-sm btn-ghost" data-action="detail" data-id="' + idAttr + '" title="' + escapeAttr(t('accounts.detail')) + '">' + userSvg + '</button>' +
        '<button class="btn btn-icon btn-sm btn-ghost" data-action="copyJSON" data-id="' + idAttr + '" title="' + escapeAttr(t('accounts.copyJSON')) + '">' + copySvg + '</button>' +
        (banned ? '' :
          '<button class="btn btn-sm ' + (a.enabled ? 'btn-outline' : 'btn-primary') + '" data-action="toggle" data-id="' + idAttr + '" data-enabled="' + (!a.enabled) + '">' +
          escapeHtml(a.enabled ? t('accounts.disable') : t('accounts.enable')) +
          '</button>') +
        '<button class="btn btn-sm btn-secondary" data-action="test" data-id="' + idAttr + '" id="test-' + idAttr + '">' + escapeHtml(t('accounts.test')) + '</button>' +
        '<button class="btn btn-sm btn-danger" data-action="delete" data-id="' + idAttr + '">' + escapeHtml(t('accounts.delete')) + '</button>' +
        '</div>' +
        '</div>' +
        (a.usageLimit > 0 ?
          '<div class="account-usage">' +
          '<div class="usage-label">' + escapeHtml(t('accounts.mainQuota')) + '</div>' +
          '<div class="usage-bar"><div class="usage-fill ' + usageClass + '" data-usage-pct="' + escapeAttr(usagePct) + '"></div></div>' +
          '<div class="usage-text"><span>' + (a.usageCurrent != null ? a.usageCurrent.toFixed(1) : 0) + ' / ' + (a.usageLimit != null ? a.usageLimit.toFixed(0) : 0) + '</span><span>' + usagePct.toFixed(1) + '%</span></div>' +
          '</div>' : '') +
        (a.trialUsageLimit > 0 ?
          '<div class="account-usage">' +
          '<div class="usage-label">' + escapeHtml(t('accounts.trialQuota')) + ' ' + escapeHtml(formatTrialExpiry(a.trialExpiresAt)) + '</div>' +
          '<div class="usage-bar"><div class="usage-fill ' + trialClass + '" data-usage-pct="' + escapeAttr(trialPct) + '"></div></div>' +
          '<div class="usage-text"><span>' + (a.trialUsageCurrent != null ? a.trialUsageCurrent.toFixed(1) : 0) + ' / ' + (a.trialUsageLimit != null ? a.trialUsageLimit.toFixed(0) : 0) + '</span><span>' + trialPct.toFixed(1) + '%</span></div>' +
          '</div>' : '') +
        '<div class="account-stats">' +
        '<div class="account-stat"><div class="account-stat-value">' + (a.requestCount || 0) + '</div><div class="account-stat-label">' + escapeHtml(t('accounts.requests')) + '</div></div>' +
        '<div class="account-stat"><div class="account-stat-value">' + formatNum(a.totalTokens || 0) + '</div><div class="account-stat-label">' + escapeHtml(t('accounts.tokens')) + '</div></div>' +
        '<div class="account-stat"><div class="account-stat-value">' + (a.totalCredits || 0).toFixed(1) + '</div><div class="account-stat-label">' + escapeHtml(t('accounts.credits')) + '</div></div>' +
        '<div class="account-stat"><div class="account-stat-value">' + escapeHtml(formatTokenExpiry(a.expiresAt)) + '</div><div class="account-stat-label">' + escapeHtml(t('accounts.expiry')) + '</div></div>' +
        '</div>' +
        '</div>';
    }).join('');
    applyUsageBars(container);
    enhanceCustomSelects(container);
  }

  // Account actions
  async function refreshAccount(id, card) {
    if (card) card.classList.add('loading');
    try {
      const res = await api('/accounts/' + id + '/refresh', { method: 'POST' });
      const d = await res.json();
      if (d.success) loadAccounts();
      else toastError(t('accounts.refreshFailed') + ': ' + (d.error || ''));
    } catch (e) {
      toastError(t('accounts.refreshFailed'));
    }
    if (card) card.classList.remove('loading');
  }
  async function toggleAccount(id, enabled) {
    await api('/accounts/' + id, { method: 'PUT', body: JSON.stringify({ enabled }) });
    loadAccounts();
  }
  async function deleteAccount(id) {
    const ok = await confirmAction(t('accounts.confirmDelete'), {
      title: t('accounts.delete'),
      confirmText: t('accounts.delete'),
      variant: 'danger'
    });
    if (!ok) return;
    try {
      const res = await api('/accounts/' + id, { method: 'DELETE' });
      const d = await res.json().catch(() => ({}));
      if (!res.ok || d.success === false) throw new Error(d.error || t('common.failed'));
      toast(t('accounts.deleteSuccess'), 'danger', { icon: 'fa-solid fa-trash' });
      loadAccounts(); loadStats();
    } catch (e) {
      toast((e && e.message) || t('common.failed'), 'error');
    }
  }
  async function copyAccountJSON(id, btn) {
    try {
      const jsonPromise = api('/accounts/' + id + '/full').then(async res => {
        if (!res.ok) throw new Error('Failed');
        const a = await res.json();
        const { clientId, clientSecret, accessToken, refreshToken } = a;
        return JSON.stringify({ clientId, clientSecret, accessToken, refreshToken }, null, 2);
      });
      await copyText(jsonPromise);
      flashCopySuccess(btn);
      toastPrimary(t('accounts.copyJSONSuccess'));
    } catch (e) {
      toastError(t('common.failed'));
    }
  }
  function flashCopySuccess(btn) {
    if (!btn) return;
    const html = btn.innerHTML, cls = btn.className;
    btn.disabled = true;
    btn.className = 'btn btn-icon btn-sm btn-success';
    btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
    setTimeout(() => { btn.disabled = false; btn.className = cls; btn.innerHTML = html; }, 800);
  }

  // Batch actions
  async function batchAction(action) {
    const ids = Array.from(selectedAccounts);
    if (!ids.length) return;
    const confirmKey = 'batch.confirm' + action.charAt(0).toUpperCase() + action.slice(1);
    const ok = await confirmAction(t(confirmKey, ids.length), {
      title: t('common.confirm'),
      confirmText: t('common.confirm'),
      variant: action === 'disable' ? 'danger' : 'primary'
    });
    if (!ok) return;
    const dismiss = toast(t('batch.processing'), 'info', { duration: 0 });
    try {
      const res = await api('/accounts/batch', { method: 'POST', body: JSON.stringify({ ids, action }) });
      const d = await res.json();
      if (!res.ok || !d.success) throw new Error(d.error || t('common.failed'));
      dismiss();
      if (action === 'refresh') {
        toast(t('batch.refreshResult', d.refreshed || 0, d.failed || 0), d.failed ? 'warning' : 'success');
      } else if (action === 'enable') {
        toast(t('batch.enableResult', d.count || ids.length), 'success');
      } else if (action === 'disable') {
        toast(t('batch.disableResult', d.count || ids.length), 'success');
      } else {
        toast(t('batch.done'), 'success');
      }
      selectedAccounts.clear();
      updateBatchBar();
      loadAccounts(); loadStats();
    } catch (e) {
      dismiss();
      toast((e && e.message) || t('common.failed'), 'error');
    }
  }
  async function batchRefreshModels() {
    const ids = Array.from(selectedAccounts);
    if (!ids.length) return;
    const confirmed = await confirmAction(t('batch.confirmRefreshModels', ids.length), {
      title: t('models.refreshAll'),
      confirmText: t('common.confirm')
    });
    if (!confirmed) return;
    const dismiss = toast(t('detail.refreshModelCache') + '…', 'info', { duration: 0 });
    let ok = 0, fail = 0;
    for (const id of ids) {
      try {
        const res = await api('/accounts/' + id + '/models/refresh', { method: 'POST' });
        const d = await res.json();
        if (d.success) ok++; else fail++;
      } catch { fail++; }
    }
    dismiss();
    toast(t('batch.refreshModelsResult', ok, fail), fail ? 'warning' : 'success');
    selectedAccounts.clear();
    updateBatchBar();
    loadAccounts();
  }
  async function batchDelete() {
    const ids = Array.from(selectedAccounts);
    if (!ids.length) return;
    const confirmed = await confirmAction(t('batch.confirmDelete', ids.length), {
      title: t('accounts.delete'),
      confirmText: t('accounts.delete'),
      variant: 'danger'
    });
    if (!confirmed) return;
    const dismiss = toast(t('batch.deleting'), 'info', { duration: 0 });
    let ok = 0, fail = 0;
    for (const id of ids) {
      try {
        const res = await api('/accounts/' + id, { method: 'DELETE' });
        const d = await res.json().catch(() => ({}));
        if (res.ok && d.success !== false) ok++; else fail++;
      } catch { fail++; }
    }
    dismiss();
    toast(t('batch.deleteResult', ok, fail), fail ? 'warning' : 'success', { icon: 'fa-solid fa-trash' });
    selectedAccounts.clear();
    updateBatchBar();
    loadAccounts(); loadStats();
  }
  async function refreshAllModels() {
    const ok = await confirmAction(t('models.confirmRefreshAll'), {
      title: t('models.refreshAll'),
      confirmText: t('models.refreshAll')
    });
    if (!ok) return;
    const dismiss = toast(t('detail.refreshModelCache') + '…', 'info', { duration: 0 });
    try {
      const res = await api('/accounts/models/refresh', { method: 'POST' });
      const d = await res.json();
      dismiss();
      toast(t('models.refreshAllDone', d.refreshed || 0), 'success');
    } catch (e) {
      dismiss();
      toast(t('common.failed'), 'error');
    }
  }
  async function refreshAccountModels(id) {
    const dismiss = toast(t('detail.refreshModelCache') + '…', 'info', { duration: 0 });
    try {
      const res = await api('/accounts/' + id + '/models/refresh', { method: 'POST' });
      const d = await res.json();
      dismiss();
      if (d.success) toast(t('detail.refreshModelCache') + ' · ' + (d.count || 0), 'success');
      else toast(t('common.failed') + (d.error ? ': ' + d.error : ''), 'error');
    } catch (e) {
      dismiss();
      toast(t('common.failed'), 'error');
    }
  }

  // Detail modal
  function detailItem(label, value) {
    return '<div class="detail-item"><div class="detail-label">' + escapeHtml(label) + '</div><div class="detail-value">' + escapeHtml(value) + '</div></div>';
  }
  function showDetail(id) {
    const a = accountsData.find(x => x.id === id);
    if (!a) return;
    const idAttr = escapeAttr(id);
    $('detailBody').innerHTML =
      '<div class="detail-section"><h4>' + escapeHtml(t('detail.basicInfo')) + '</h4><div class="detail-grid">' +
      detailItem(t('detail.email'), getDisplayEmail(a.email, null)) +
      detailItem(t('detail.userId'), a.userId || '-') +
      detailItem(t('detail.authMethod'), formatAuthMethod(a.provider || a.authMethod)) +
      detailItem(t('detail.region'), a.region || 'us-east-1') +
      '</div></div>' +

      '<div class="detail-section"><h4>' + escapeHtml(t('detail.machineId')) + '</h4><div class="machine-id-row">' +
      '<input type="text" id="machineIdInput" value="' + escapeAttr(a.machineId || '') + '" placeholder="UUID" />' +
      '<button class="btn btn-sm btn-outline" id="generateMachineIdBtn" type="button">' + escapeHtml(t('detail.generate')) + '</button>' +
      '<button class="btn btn-sm btn-primary" data-detail-action="saveMachineId" data-id="' + idAttr + '" type="button">' + escapeHtml(t('detail.save')) + '</button>' +
      '</div></div>' +

      '<div class="detail-section"><h4>' + escapeHtml(t('detail.weight')) + '</h4>' +
      '<div class="form-group">' +
      '<input type="number" id="weightInput" value="' + (a.weight || 0) + '" min="0" max="10" />' +
      '<small>' + escapeHtml(t('detail.weightHint')) + '</small>' +
      '</div>' +
      '<button class="btn btn-sm btn-primary" data-detail-action="saveWeight" data-id="' + idAttr + '" type="button">' + escapeHtml(t('detail.save')) + '</button>' +
      '</div>' +

      '<div class="detail-section">' +
      '<h4>' + escapeHtml(t('detail.overage')) +
      ' <button class="btn btn-sm btn-outline" data-detail-action="refreshOverage" data-id="' + idAttr + '" type="button">' + escapeHtml(t('detail.overageRefresh')) + '</button>' +
      '</h4>' +
      '<p class="help-block">' + escapeHtml(t('detail.overageHint')) + '</p>' +
      renderOverageBlock(a, idAttr) +
      '</div>' +

      '<div class="detail-section"><h4>' + escapeHtml(t('detail.proxyURL')) + '</h4><div class="machine-id-row">' +
      '<input type="text" id="proxyURLInput" value="' + escapeAttr(a.proxyURL || '') + '" placeholder="socks5://host:port" />' +
      '<button class="btn btn-sm btn-primary" data-detail-action="saveProxyURL" data-id="' + idAttr + '" type="button">' + escapeHtml(t('detail.save')) + '</button>' +
      '</div><p class="help-block">' + escapeHtml(t('detail.proxyHint')) + '</p></div>' +

      '<div class="detail-section"><h4>' + escapeHtml(t('detail.subscription')) + '</h4><div class="detail-grid">' +
      detailItem(t('detail.subscriptionType'), a.subscriptionTitle || (a.subscriptionType ? formatSubscriptionLabel(a.subscriptionType) : '-')) +
      detailItem(t('detail.tokenExpiry'), a.expiresAt ? new Date(a.expiresAt * 1000).toLocaleString() : '-') +
      detailItem(t('detail.mainQuota'), (a.usageCurrent != null ? a.usageCurrent.toFixed(1) : 0) + ' / ' + (a.usageLimit != null ? a.usageLimit.toFixed(0) : 0)) +
      detailItem(t('detail.resetDate'), a.nextResetDate || '-') +
      (a.trialUsageLimit > 0 ?
        detailItem(t('detail.trialQuota'), (a.trialUsageCurrent != null ? a.trialUsageCurrent.toFixed(1) : 0) + ' / ' + a.trialUsageLimit.toFixed(0)) +
        detailItem(t('detail.trialStatus'), a.trialStatus || '-') +
        detailItem(t('detail.trialExpiry'), a.trialExpiresAt ? new Date(a.trialExpiresAt * 1000).toLocaleString() : '-')
        : '') +
      '</div></div>' +

      '<div class="detail-section"><h4>' + escapeHtml(t('detail.statistics')) + '</h4><div class="detail-grid">' +
      detailItem(t('detail.requestCount'), a.requestCount || 0) +
      detailItem(t('detail.errorCount'), a.errorCount || 0) +
      detailItem(t('detail.totalTokens'), formatNum(a.totalTokens || 0)) +
      detailItem(t('detail.totalCredits'), (a.totalCredits || 0).toFixed(2)) +
      '</div></div>' +

      '<div class="detail-section">' +
      '<h4>' + escapeHtml(t('detail.models')) +
      ' <button class="btn btn-sm btn-outline" data-detail-action="loadModels" data-id="' + idAttr + '" type="button">' + escapeHtml(t('detail.loadModels')) + '</button>' +
      ' <button class="btn btn-sm btn-outline" data-detail-action="refreshModels" data-id="' + idAttr + '" type="button">' + escapeHtml(t('detail.refreshModelCache')) + '</button>' +
      '</h4>' +
      '<div id="modelsList" class="model-list"></div>' +
      '</div>';

    openDialog('detailModal');
  }
  async function loadModels(id) {
    const c = $('modelsList');
    c.innerHTML = '<p class="empty-state">' + escapeHtml(t('detail.loading')) + '</p>';
    try {
      const res = await api('/accounts/' + id + '/models');
      const d = await res.json();
      if (d.success && d.models) {
        const sorted = d.models.slice().sort((a, b) => {
          if (a.modelId === 'auto') return -1;
          if (b.modelId === 'auto') return 1;
          return (a.rateMultiplier || 1) - (b.rateMultiplier || 1);
        });
        c.innerHTML = sorted.map(m => {
          const ratio = m.rateMultiplier || 1;
          return '<div class="model-item">' +
            '<div class="model-name">' + escapeHtml(m.modelId) + '</div>' +
            '<div class="model-credit"><span class="credit-ratio">' + escapeHtml(t('detail.creditMultiplier', ratio)) + '</span></div>' +
            '<div class="model-info">' + escapeHtml(m.description || '') + '</div>' +
            '</div>';
        }).join('') || '<p class="empty-state">' + escapeHtml(t('detail.noModels')) + '</p>';
      } else {
        c.innerHTML = '<p class="message message-error">' + escapeHtml(t('detail.loadFailed')) + ': ' + escapeHtml(d.error || '') + '</p>';
        toast(t('detail.loadFailed') + (d.error ? ': ' + d.error : ''), 'error');
      }
    } catch (e) {
      c.innerHTML = '<p class="message message-error">' + escapeHtml(t('detail.loadFailed')) + '</p>';
      toast(t('detail.loadFailed'), 'error');
    }
  }
  async function generateMachineId() {
    try {
      const res = await api('/generate-machine-id');
      const d = await res.json();
      if (d.machineId) $('machineIdInput').value = d.machineId;
    } catch (e) {
      toast(t('detail.generateFailed'), 'error');
    }
  }
  async function putAccount(id, body, successMsg) {
    try {
      const res = await api('/accounts/' + id, { method: 'PUT', body: JSON.stringify(body) });
      const d = await res.json();
      if (d.success) {
        toast(successMsg, 'success');
        loadAccounts();
      } else {
        toast(t('detail.saveFailed') + (d.error ? ': ' + d.error : ''), 'error');
      }
    } catch (e) {
      toast(t('detail.saveFailed'), 'error');
    }
  }
  async function saveMachineId(id) {
    const m = $('machineIdInput').value.trim();
    if (m && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(m) && !/^[0-9a-f]{32}$/i.test(m)) {
      toast(t('detail.machineIdError'), 'warning'); return;
    }
    await putAccount(id, { machineId: m }, t('detail.saved'));
  }
  async function saveWeight(id) {
    const weight = parseInt($('weightInput').value, 10) || 0;
    await putAccount(id, { weight }, t('detail.saved'));
  }
  function renderOverageBadge(a) {
    const status = (a.overageStatus || '').toUpperCase();
    if (status === 'ENABLED') {
      return '<span class="badge badge-warning">' + escapeHtml(t('accounts.overageOn')) + '</span>';
    }
    if (status === 'DISABLED') {
      return '<span class="badge badge-muted">' + escapeHtml(t('accounts.overageOff')) + '</span>';
    }
    return '';
  }
  function renderOverageBlock(a, idAttr) {
    const status = (a.overageStatus || '').toUpperCase();
    const capable = !a.overageCapability || a.overageCapability === 'OVERAGE_CAPABLE';
    const checked = status === 'ENABLED';
    const checkedAt = a.overageCheckedAt ? new Date(a.overageCheckedAt * 1000).toLocaleString() : '-';
    const statusText = status === 'ENABLED' ? t('detail.overageEnabled')
      : status === 'DISABLED' ? t('detail.overageDisabled')
      : t('detail.overageUnknown');
    const disabledAttr = capable ? '' : ' disabled';
    return '<div class="form-group flex items-center gap-2">' +
      '<label class="switch"><input type="checkbox" id="overageSwitchInput-' + idAttr + '" data-detail-action="toggleOverage" data-id="' + idAttr + '" ' + (checked ? 'checked' : '') + disabledAttr + ' /><span class="slider"></span></label>' +
      '<span id="overageSwitchLabel-' + idAttr + '">' + escapeHtml(statusText) + '</span>' +
      '</div>' +
      (capable ? '' : '<p class="help-block" style="color:#ef4444">' + escapeHtml(t('detail.overageNotCapable')) + '</p>') +
      '<div class="detail-grid">' +
      detailItem(t('detail.overageStatus'), status || '-') +
      detailItem(t('detail.overageCap'), a.overageCap ? '$' + Number(a.overageCap).toFixed(2) : '-') +
      detailItem(t('detail.overageRate'), a.overageRate ? '$' + Number(a.overageRate).toFixed(4) : '-') +
      detailItem(t('detail.overageCurrent'), a.currentOverages ? '$' + Number(a.currentOverages).toFixed(4) : '$0') +
      detailItem(t('detail.overageCheckedAt'), checkedAt) +
      '</div>';
  }
  async function toggleOverageSwitch(id, inputEl) {
    const desired = inputEl.checked;
    const labelEl = $('overageSwitchLabel-' + id);
    const oldLabel = labelEl ? labelEl.textContent : '';
    inputEl.disabled = true;
    if (labelEl) labelEl.textContent = t('detail.overageSwitching');
    try {
      const res = await api('/accounts/' + encodeURIComponent(id) + '/overage', {
        method: 'POST',
        body: JSON.stringify({ enabled: desired }),
      });
      const d = await res.json().catch(() => ({}));
      if (!res.ok || d.success === false) {
        throw new Error(d.error || t('accounts.overageSwitchFailed'));
      }
      if (labelEl) {
        labelEl.textContent = d.overageStatus === 'ENABLED' ? t('detail.overageEnabled')
          : d.overageStatus === 'DISABLED' ? t('detail.overageDisabled')
          : t('detail.overageUnknown');
      }
      inputEl.checked = d.overageStatus === 'ENABLED';
      await loadAccounts();
    } catch (e) {
      inputEl.checked = !desired;
      if (labelEl) labelEl.textContent = oldLabel;
      toast(t('accounts.overageSwitchFailed') + ': ' + (e.message || e), 'warning');
    } finally {
      inputEl.disabled = false;
    }
  }
  async function refreshAccountOverage(id) {
    try {
      const res = await api('/accounts/' + encodeURIComponent(id) + '/overage', { method: 'GET' });
      const d = await res.json().catch(() => ({}));
      if (!res.ok || d.success === false) {
        throw new Error(d.error || t('accounts.overageSwitchFailed'));
      }
      await loadAccounts();
      showDetail(id);
    } catch (e) {
      toast(t('accounts.overageSwitchFailed') + ': ' + (e.message || e), 'warning');
    }
  }
  async function saveProxyURL(id) {
    const url = $('proxyURLInput').value.trim();
    if (url && !/^(socks5|socks5h|http|https):\/\//.test(url)) {
      toast(t('detail.proxyFormatError'), 'warning'); return;
    }
    await putAccount(id, { proxyURL: url }, t('detail.proxySaved'));
  }
  function closeDetailModal() { closeDialog('detailModal'); }

  // Test flow
  function getTestAccount(id) {
    return accountsData.find(a => a.id === id) || null;
  }
  function getTestModelValue() {
    const choice = $('testModelChoice');
    return (choice && choice.value.trim()) || 'claude-sonnet-4';
  }
  function renderTestLog() {
    const c = $('testModalLog');
    if (!c) return;
    if (!testLogs.length) {
      c.innerHTML = '<div class="test-log-empty">' + escapeHtml(t('accounts.testLog.empty')) + '</div>';
      return;
    }
    c.innerHTML = testLogs.map(log =>
      '<div class="test-log-line ' + escapeAttr(log.type || 'info') + '">' +
      '<span class="test-log-time">' + escapeHtml(log.time) + '</span>' +
      '<span class="test-log-message">' + escapeHtml(log.msg) + '</span>' +
      '</div>'
    ).join('');
    c.scrollTop = c.scrollHeight;
  }
  function addTestLog(msg, type) {
    const time = new Date().toLocaleTimeString();
    testLogs.push({ time, msg, type });
    if (testLogs.length > 100) testLogs.shift();
    renderTestLog();
  }
  function clearTestLog() {
    testLogs = [];
    renderTestLog();
  }
  function renderTestModal() {
    const body = $('testBody');
    if (!body) return;
    const acc = getTestAccount(testModalAccountId);
    const idAttr = escapeAttr(testModalAccountId);
    const email = acc ? getDisplayEmail(acc.email, acc.id) : testModalAccountId;
    const proxy = acc ? (acc.proxyURL || t('accounts.testLog.globalProxy')) : '?';
    const statusText = testModalLoadingModels
      ? t('accounts.testModelsLoading')
      : testModalModelError
        ? t('accounts.testModelsFallback')
        : t('accounts.testModelsReady', testModalModels.length);
    const modelField = testModalLoadingModels
      ? '<div class="test-model-loading">' + escapeHtml(t('accounts.testModelsLoading')) + '</div>'
      : testModalModels.length
        ? '<select id="testModelChoice">' +
        testModalModels.map(m => '<option value="' + escapeAttr(m) + '">' + escapeHtml(m) + '</option>').join('') +
        '</select>'
        : '<input type="text" id="testModelChoice" placeholder="claude-sonnet-4" value="claude-sonnet-4" />';

    body.innerHTML =
      '<div class="test-modal-account">' +
      '<div class="test-modal-account-main">' +
      '<div class="test-modal-email">' + escapeHtml(email) + '</div>' +
      '<div class="test-modal-meta">' +
      '<span>' + escapeHtml(formatAuthMethod(acc && (acc.provider || acc.authMethod))) + '</span>' +
      '<span>' + escapeHtml(proxy) + '</span>' +
      '</div>' +
      '</div>' +
      '<span class="test-modal-status">' + escapeHtml(statusText) + '</span>' +
      '</div>' +
      '<div class="test-modal-grid">' +
      '<div class="form-group test-model-field">' +
      '<label for="testModelChoice">' + escapeHtml(t('accounts.selectModel')) + '</label>' +
      modelField +
      '</div>' +
      '<div class="test-log-card">' +
      '<div class="test-log-header">' +
      '<span class="test-log-title">' + escapeHtml(t('accounts.testLog.title')) + '</span>' +
      '<button class="btn btn-xs btn-outline test-log-clear" id="testLogClear" type="button">' + escapeHtml(t('accounts.testLog.clear')) + '</button>' +
      '</div>' +
      '<div class="test-log-content" id="testModalLog"></div>' +
      '</div>' +
      '</div>' +
      '<div class="modal-footer">' +
      '<button class="btn btn-secondary" id="testModalCancelBtn" type="button">' + escapeHtml(t('common.close')) + '</button>' +
      '<button class="btn btn-primary" id="testRunBtn" data-id="' + idAttr + '" type="button" ' + (testModalLoadingModels ? 'disabled' : '') + '>' + escapeHtml(t('accounts.test')) + '</button>' +
      '</div>';

    if (!testModalLoadingModels) enhanceCustomSelects(body);
    renderTestLog();
  }
  async function testAccount(id) {
    testModalAccountId = id;
    testModalModels = [];
    testModalLoadingModels = true;
    testModalModelError = false;
    testModalRunning = false;
    testLogs = [];
    renderTestModal();
    openDialog('testModal');
    try {
      const res = await api('/accounts/' + id + '/models/cached');
      const d = await res.json();
      testModalModels = Array.isArray(d.models) ? d.models.slice().sort() : [];
    } catch (e) {
      testModalModelError = true;
    } finally {
      testModalLoadingModels = false;
      renderTestModal();
    }
  }
  function closeTestModal() {
    closeAllCustomSelects();
    closeDialog('testModal');
  }
  async function runTestAccount(id, model) {
    if (testModalRunning) return;
    testModalRunning = true;
    const modalBtn = $('testRunBtn');
    if (modalBtn) modalBtn.setAttribute('aria-busy', 'true');
    const acc = accountsData.find(a => a.id === id);
    const email = acc ? getDisplayEmail(acc.email, acc.id) : id;
    const proxy = acc ? (acc.proxyURL || t('accounts.testLog.globalProxy')) : '?';
    addTestLog(t('accounts.testLog.start', email, model, proxy), 'info');
    try {
      const startTime = Date.now();
      const res = await api('/accounts/' + id + '/test', { method: 'POST', body: JSON.stringify({ model }) });
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      const d = await res.json();
      if (d.success) {
        addTestLog(t('accounts.testLog.success', email, elapsed, d.reply), 'ok');
      } else {
        addTestLog(t('accounts.testLog.failed', email, elapsed, d.error || t('common.unknownError')), 'err');
      }
    } catch (e) {
      addTestLog(t('accounts.testLog.error', email, e.message), 'err');
    }
    testModalRunning = false;
    if (modalBtn) modalBtn.removeAttribute('aria-busy');
  }

  // Settings
  async function loadSettings() {
    const res = await api('/settings');
    const d = await res.json();
    $('requireApiKey').checked = d.requireApiKey;
    $('allowOverUsage').checked = d.allowOverUsage || false;
    await Promise.all([loadThinkingConfig(), loadEndpointConfig(), loadProxyConfig(), loadPromptFilter(), loadApiKeys()]);
    refreshCustomSelects();
  }
  async function loadThinkingConfig() {
    const res = await api('/thinking');
    const d = await res.json();
    $('thinkingSuffix').value = d.suffix || '-thinking';
    $('openaiThinkingFormat').value = d.openaiFormat || 'reasoning_content';
    $('claudeThinkingFormat').value = d.claudeFormat || 'thinking';
  }
  async function saveThinkingConfig() {
    const res = await api('/thinking', {
      method: 'POST', body: JSON.stringify({
        suffix: $('thinkingSuffix').value || '-thinking',
        openaiFormat: $('openaiThinkingFormat').value,
        claudeFormat: $('claudeThinkingFormat').value
      })
    });
    const d = await res.json();
    if (d.success) toast(t('settings.thinkingSaved'), 'success');
    else toast(t('common.saveFailed') + ': ' + (d.error || ''), 'error');
  }
  async function loadEndpointConfig() {
    const res = await api('/endpoint');
    const d = await res.json();
    $('preferredEndpoint').value = d.preferredEndpoint || 'auto';
    $('endpointFallback').checked = d.endpointFallback !== false;
  }
  async function saveEndpointConfig() {
    const res = await api('/endpoint', {
      method: 'POST', body: JSON.stringify({
        preferredEndpoint: $('preferredEndpoint').value,
        endpointFallback: $('endpointFallback').checked
      })
    });
    const d = await res.json();
    if (d.success) toast(t('settings.endpointSaved'), 'success');
    else toast(t('common.saveFailed') + ': ' + (d.error || ''), 'error');
  }
  async function loadProxyConfig() {
    const res = await api('/proxy');
    const d = await res.json();
    const url = d.proxyURL || '';
    if (!url) {
      $('proxyType').value = 'none';
      $('proxyFields').classList.add('hidden');
      return;
    }
    try {
      const u = new URL(url);
      const scheme = u.protocol.replace(':', '');
      $('proxyType').value = scheme.startsWith('socks5') ? 'socks5' : 'http';
      $('proxyHost').value = u.hostname;
      $('proxyPort').value = u.port;
      $('proxyUsername').value = decodeURIComponent(u.username);
      $('proxyPassword').value = decodeURIComponent(u.password);
      $('proxyFields').classList.remove('hidden');
    } catch (e) {
      $('proxyType').value = 'none';
      $('proxyFields').classList.add('hidden');
    }
  }
  function onProxyTypeChange() {
    const type = $('proxyType').value;
    $('proxyFields').classList.toggle('hidden', type === 'none');
  }
  async function saveProxyConfig() {
    const type = $('proxyType').value;
    let url = '';
    if (type !== 'none') {
      const host = $('proxyHost').value.trim();
      const port = $('proxyPort').value.trim();
      if (!host || !port) { toast(t('settings.proxyHostRequired'), 'warning'); return; }
      const u = $('proxyUsername').value.trim();
      const p = $('proxyPassword').value.trim();
      const auth = u ? (p ? encodeURIComponent(u) + ':' + encodeURIComponent(p) + '@' : encodeURIComponent(u) + '@') : '';
      url = type + '://' + auth + host + ':' + port;
    }
    const res = await api('/proxy', { method: 'POST', body: JSON.stringify({ proxyURL: url }) });
    const d = await res.json();
    if (d.success) toast(t('settings.proxySaved'), 'success');
    else toast(t('common.saveFailed') + ': ' + (d.error || ''), 'error');
  }
  async function saveRequireApiKey() {
    try {
      const requireApiKey = $('requireApiKey').checked;
      if (requireApiKey) {
        const hasEnabledKey = Array.isArray(apiKeysCache) && apiKeysCache.some(k => k && k.enabled);
        if (!hasEnabledKey) {
          if (!confirm(t('apiKeys.requireWithoutEnabledKeyWarning'))) {
            $('requireApiKey').checked = false;
            return;
          }
        }
      }
      const res = await api('/settings', { method: 'POST', body: JSON.stringify({ requireApiKey }) });
      const d = await res.json().catch(() => ({}));
      if (!res.ok || d.success === false) throw new Error(d.error || t('common.saveFailed'));
      toast(t('detail.saved'), 'success');
    } catch (e) {
      toast((e && e.message) || t('common.saveFailed'), 'error');
    }
  }
  async function saveOverUsageConfig() {
    const allowOverUsage = $('allowOverUsage').checked;
    await api('/settings', { method: 'POST', body: JSON.stringify({ allowOverUsage }) });
    toast(t('settings.overUsageSaved'), 'success');
  }
  async function changePassword() {
    const np = $('newPassword').value;
    if (!np) return toast(t('settings.passwordRequired'), 'warning');
    try {
      const res = await api('/settings', { method: 'POST', body: JSON.stringify({ password: np }) });
      const d = await res.json().catch(() => ({}));
      if (!res.ok || d.success === false) throw new Error(d.error || t('common.saveFailed'));
      setActivePassword(np, localStorage.getItem('kiro_remember') === '1');
      toast(t('settings.passwordChanged'), 'success');
      $('newPassword').value = '';
    } catch (e) {
      toast((e && e.message) || t('common.saveFailed'), 'error');
    }
  }
  async function resetStats() {
    const ok = await confirmAction(t('settings.confirmReset'), {
      title: t('settings.statistics'),
      confirmText: t('settings.resetStats'),
      variant: 'danger'
    });
    if (!ok) return;
    try {
      const res = await api('/stats/reset', { method: 'POST' });
      if (!res.ok) throw new Error(t('common.failed'));
      loadStats();
      toastPrimary(t('settings.statsReset'));
    } catch (e) {
      toastError((e && e.message) || t('common.failed'));
    }
  }
  // Multi API Key management
  let apiKeysCache = [];
  let apiKeyEditingId = '';
  let apiKeyModalSubmitting = false;

  async function loadApiKeys() {
    const list = $('apiKeysList');
    if (!list) return;
    try {
      const res = await api('/api-keys');
      if (!res.ok) throw new Error('http ' + res.status);
      const d = await res.json();
      apiKeysCache = Array.isArray(d.apiKeys) ? d.apiKeys : [];
      renderApiKeys();
    } catch (e) {
      apiKeysCache = [];
      list.innerHTML = '<div class="muted-text" style="padding:0.5rem 0;">' + escapeHtml(t('apiKeys.loadFailed')) + '</div>';
    }
  }

  function formatNumber(n) {
    if (n == null || isNaN(n)) return '0';
    if (Math.abs(n) >= 1 && Math.floor(n) === n) return Number(n).toLocaleString('en-US');
    return Number(n).toLocaleString('en-US', { maximumFractionDigits: 4 });
  }

  function usageBar(used, limit) {
    if (!limit || limit <= 0) return '';
    const ratio = Math.max(0, Math.min(1, used / limit));
    const pct = (ratio * 100).toFixed(1);
    let color = '#3b82f6';
    if (ratio >= 0.95) color = '#ef4444';
    else if (ratio >= 0.8) color = '#f59e0b';
    return '<div style="height:6px;background:rgba(127,127,127,0.2);border-radius:3px;overflow:hidden;margin-top:4px;">' +
      '<div style="height:100%;width:' + pct + '%;background:' + color + ';transition:width 0.3s;"></div>' +
      '</div>';
  }

  function usageLine(label, used, limit, options) {
    options = options || {};
    const fmt = options.fmt || formatNumber;
    if (!limit || limit <= 0) {
      return '<div class="text-xs muted-text">' + escapeHtml(label) + ': ' + escapeHtml(fmt(used)) + ' / ' + escapeHtml(t('apiKeys.unlimited')) + '</div>';
    }
    return '<div class="text-xs muted-text">' + escapeHtml(label) + ': ' + escapeHtml(fmt(used)) + ' / ' + escapeHtml(fmt(limit)) + '</div>' + usageBar(used, limit);
  }

  function renderApiKeys() {
    const list = $('apiKeysList');
    if (!list) return;
    if (!apiKeysCache.length) {
      list.innerHTML = '<div class="muted-text" style="padding:0.5rem 0;">' + escapeHtml(t('apiKeys.empty')) + '</div>';
      return;
    }
    const html = apiKeysCache.map(item => {
      const id = escapeAttr(item.id || '');
      const name = item.name ? escapeHtml(item.name) : '<span class="muted-text">' + escapeHtml(t('apiKeys.unnamed')) + '</span>';
      const masked = escapeHtml(item.keyMasked || '');
      const migrated = item.migrated
        ? '<span class="text-xs" style="background:rgba(59,130,246,0.15);color:#3b82f6;padding:1px 6px;border-radius:4px;">' + escapeHtml(t('apiKeys.migrated')) + '</span>'
        : '';
      const disabled = !item.enabled
        ? '<span class="text-xs" style="background:rgba(239,68,68,0.15);color:#ef4444;padding:1px 6px;border-radius:4px;">' + escapeHtml(t('apiKeys.disabled')) + '</span>'
        : '';
      const tokensLine = usageLine(t('apiKeys.tokens'), item.tokensUsed || 0, item.tokenLimit || 0);
      const creditsLine = usageLine(t('apiKeys.credits'), item.creditsUsed || 0, item.creditLimit || 0);
      const requestsLine = '<div class="text-xs muted-text">' + escapeHtml(t('apiKeys.requests')) + ': ' + escapeHtml(formatNumber(item.requestsCount || 0)) + '</div>';
      return '<div class="card" data-apikey-id="' + id + '" style="margin-top:0.5rem;padding:0.75rem;">' +
        '<div class="flex items-center gap-2" style="flex-wrap:wrap;justify-content:space-between;">' +
          '<div class="flex items-center gap-2" style="flex-wrap:wrap;">' +
            '<span class="font-semibold">' + name + '</span>' +
            migrated +
            disabled +
            '<span class="text-xs muted-text font-mono">' + masked + '</span>' +
          '</div>' +
          '<div class="flex items-center gap-2">' +
            '<label class="switch" title="' + escapeAttr(item.enabled ? t('accounts.disable') : t('accounts.enable')) + '">' +
              '<input type="checkbox" data-apikey-action="toggle" data-id="' + id + '"' + (item.enabled ? ' checked' : '') + ' />' +
              '<span class="slider"></span>' +
            '</label>' +
            '<button class="btn btn-outline btn-sm" type="button" data-apikey-action="edit" data-id="' + id + '">' + escapeHtml(t('apiKeys.actionEdit')) + '</button>' +
            '<button class="btn btn-outline btn-sm" type="button" data-apikey-action="reset" data-id="' + id + '">' + escapeHtml(t('apiKeys.actionReset')) + '</button>' +
            '<button class="btn btn-danger btn-sm" type="button" data-apikey-action="delete" data-id="' + id + '">' + escapeHtml(t('apiKeys.actionDelete')) + '</button>' +
          '</div>' +
        '</div>' +
        '<div style="margin-top:0.5rem;display:grid;gap:0.35rem;">' +
          tokensLine +
          creditsLine +
          requestsLine +
        '</div>' +
      '</div>';
    }).join('');
    list.innerHTML = html;
  }

  function openApiKeyModal(entry) {
    apiKeyEditingId = entry ? (entry.id || '') : '';
    const titleEl = $('apiKeyModalTitle');
    titleEl.textContent = t(apiKeyEditingId ? 'apiKeys.modalTitleEdit' : 'apiKeys.modalTitleCreate');
    $('apiKeyForm_name').value = entry ? (entry.name || '') : '';
    const keyEl = $('apiKeyForm_key');
    if (apiKeyEditingId) {
      keyEl.value = entry.keyMasked || '';
      keyEl.readOnly = true;
    } else {
      keyEl.value = '';
      keyEl.readOnly = false;
    }
    $('apiKeyForm_enabled').checked = entry ? !!entry.enabled : true;
    $('apiKeyForm_tokenLimit').value = entry ? String(entry.tokenLimit || 0) : '0';
    $('apiKeyForm_creditLimit').value = entry ? String(entry.creditLimit || 0) : '0';
    apiKeyModalSubmitting = false;
    $('apiKeyModalSaveBtn').disabled = false;
    openDialog('apiKeyModal');
  }

  function closeApiKeyModal() {
    closeDialog('apiKeyModal');
    apiKeyEditingId = '';
    apiKeyModalSubmitting = false;
    $('apiKeyModalSaveBtn').disabled = false;
  }

  async function submitApiKeyModal() {
    if (apiKeyModalSubmitting) return;
    apiKeyModalSubmitting = true;
    const saveBtn = $('apiKeyModalSaveBtn');
    saveBtn.disabled = true;
    try {
      const name = $('apiKeyForm_name').value.trim();
      const enabled = $('apiKeyForm_enabled').checked;
      const tokenLimit = parseInt($('apiKeyForm_tokenLimit').value, 10);
      const creditLimit = parseFloat($('apiKeyForm_creditLimit').value);
      const payload = {
        name: name,
        enabled: enabled,
        tokenLimit: isNaN(tokenLimit) || tokenLimit < 0 ? 0 : tokenLimit,
        creditLimit: isNaN(creditLimit) || creditLimit < 0 ? 0 : creditLimit
      };
      let res, d;
      if (apiKeyEditingId) {
        res = await api('/api-keys/' + encodeURIComponent(apiKeyEditingId), { method: 'PUT', body: JSON.stringify(payload) });
        d = await res.json().catch(() => ({}));
        if (!res.ok || d.success === false) throw new Error(d.error || t('common.saveFailed'));
        toast(t('apiKeys.updated'), 'success');
        closeApiKeyModal();
        await loadApiKeys();
      } else {
        const keyVal = $('apiKeyForm_key').value.trim();
        if (keyVal) payload.key = keyVal;
        res = await api('/api-keys', { method: 'POST', body: JSON.stringify(payload) });
        d = await res.json().catch(() => ({}));
        if (!res.ok || d.success === false) throw new Error(d.error || t('common.saveFailed'));
        toast(t('apiKeys.created'), 'success');
        closeApiKeyModal();
        await loadApiKeys();
        if (d.key) showNewApiKey(d.key);
      }
    } catch (e) {
      toast((e && e.message) || t('common.saveFailed'), 'error');
      apiKeyModalSubmitting = false;
      saveBtn.disabled = false;
    }
  }

  async function toggleApiKeyEntry(id, enabled) {
    try {
      const res = await api('/api-keys/' + encodeURIComponent(id), { method: 'PUT', body: JSON.stringify({ enabled }) });
      const d = await res.json().catch(() => ({}));
      if (!res.ok || d.success === false) throw new Error(d.error || t('common.saveFailed'));
      const item = apiKeysCache.find(x => x.id === id);
      if (item) item.enabled = enabled;
      renderApiKeys();
    } catch (e) {
      toast((e && e.message) || t('common.saveFailed'), 'error');
      await loadApiKeys();
    }
  }

  async function deleteApiKeyEntry(id, name) {
    const ok = await confirmAction(t('apiKeys.confirmDelete', name || t('apiKeys.unnamed')), {
      title: t('apiKeys.actionDelete'),
      confirmText: t('apiKeys.actionDelete'),
      variant: 'danger'
    });
    if (!ok) return;
    try {
      const res = await api('/api-keys/' + encodeURIComponent(id), { method: 'DELETE' });
      const d = await res.json().catch(() => ({}));
      if (!res.ok || d.success === false) throw new Error(d.error || t('common.failed'));
      toast(t('apiKeys.deleteSuccess'), 'success');
      await loadApiKeys();
    } catch (e) {
      toast((e && e.message) || t('common.failed'), 'error');
    }
  }

  async function resetApiKeyUsageEntry(id, name) {
    const ok = await confirmAction(t('apiKeys.confirmReset', name || t('apiKeys.unnamed')), {
      title: t('apiKeys.actionReset'),
      confirmText: t('apiKeys.actionReset')
    });
    if (!ok) return;
    try {
      const res = await api('/api-keys/' + encodeURIComponent(id) + '/reset-usage', { method: 'POST' });
      const d = await res.json().catch(() => ({}));
      if (!res.ok || d.success === false) throw new Error(d.error || t('common.failed'));
      toast(t('apiKeys.usageReset'), 'success');
      await loadApiKeys();
    } catch (e) {
      toast((e && e.message) || t('common.failed'), 'error');
    }
  }

  function showNewApiKey(plaintext) {
    $('apiKeyShowValue').value = plaintext || '';
    openDialog('apiKeyShowModal');
    setTimeout(() => {
      const el = $('apiKeyShowValue');
      if (el) { try { el.select(); } catch (_) { } }
    }, 0);
  }

  function closeShowApiKeyModal() {
    closeDialog('apiKeyShowModal');
    $('apiKeyShowValue').value = '';
  }

  async function copyNewApiKey() {
    const val = $('apiKeyShowValue').value;
    if (!val) return;
    try {
      await copyText(val);
      toast(t('apiKeys.copySuccess'), 'success');
    } catch (e) {
      toast(t('common.failed'), 'error');
    }
  }

  function bindApiKeyEvents() {
    const list = $('apiKeysList');
    if (list) {
      list.addEventListener('click', e => {
        const btn = e.target.closest('[data-apikey-action]');
        if (!btn) return;
        const action = btn.dataset.apikeyAction;
        const id = btn.dataset.id;
        if (!id) return;
        const entry = apiKeysCache.find(x => x.id === id);
        const name = entry ? entry.name : '';
        if (action === 'edit') openApiKeyModal(entry);
        else if (action === 'delete') deleteApiKeyEntry(id, name);
        else if (action === 'reset') resetApiKeyUsageEntry(id, name);
      });
      list.addEventListener('change', e => {
        const cb = e.target.closest('input[data-apikey-action="toggle"]');
        if (!cb) return;
        const id = cb.dataset.id;
        if (!id) return;
        toggleApiKeyEntry(id, cb.checked);
      });
    }
    const addBtn = $('addApiKeyBtn');
    if (addBtn) addBtn.addEventListener('click', () => openApiKeyModal(null));
    const saveBtn = $('apiKeyModalSaveBtn');
    if (saveBtn) saveBtn.addEventListener('click', submitApiKeyModal);
    const cancelBtn = $('apiKeyModalCancelBtn');
    if (cancelBtn) cancelBtn.addEventListener('click', closeApiKeyModal);
    const closeBtn = $('apiKeyModalClose');
    if (closeBtn) closeBtn.addEventListener('click', closeApiKeyModal);
    const showCloseBtn = $('apiKeyShowCloseBtn');
    if (showCloseBtn) showCloseBtn.addEventListener('click', closeShowApiKeyModal);
    const showCloseX = $('apiKeyShowClose');
    if (showCloseX) showCloseX.addEventListener('click', closeShowApiKeyModal);
    const copyBtn = $('apiKeyShowCopyBtn');
    if (copyBtn) copyBtn.addEventListener('click', copyNewApiKey);
    bindDialogBackdropClose('apiKeyModal', closeApiKeyModal);
    bindDialogBackdropClose('apiKeyShowModal', closeShowApiKeyModal);
  }

  // Prompt filter rules
  async function loadPromptFilter() {
    const res = await api('/prompt-filter');
    const d = await res.json();
    $('filterClaudeCode').checked = !!d.filterClaudeCode;
    $('filterEnvNoise').checked = !!d.filterEnvNoise;
    $('filterStripBoundaries').checked = !!d.filterStripBoundaries;
    promptRules = d.rules || [];
    renderPromptRules();
  }
  async function savePromptFilter() {
    const res = await api('/prompt-filter', {
      method: 'POST', body: JSON.stringify({
        filterClaudeCode: $('filterClaudeCode').checked,
        filterEnvNoise: $('filterEnvNoise').checked,
        filterStripBoundaries: $('filterStripBoundaries').checked,
        rules: promptRules
      })
    });
    const d = await res.json();
    if (d.success) toast(t('settings.promptFilterSaved'), 'success');
    else toast(t('common.saveFailed') + ': ' + (d.error || ''), 'error');
  }
  function renderPromptRules() {
    const c = $('promptFilterRules');
    if (!c) return;
    if (!promptRules.length) {
      c.innerHTML = '<small class="text-xs muted-text">' + escapeHtml(t('promptFilter.noRules')) + '</small>';
      return;
    }
    c.innerHTML = promptRules.map((r, i) => {
      const isContains = r.type === 'lines-containing';
      const typeLabel = isContains ? t('promptFilter.typeContains') : t('promptFilter.typeRegex');
      const matchPh = isContains ? t('promptFilter.matchPlaceholderContains') : t('promptFilter.matchPlaceholderRegex');
      const replaceRow = !isContains
        ? '<div class="rule-field"><label>' + escapeHtml(t('promptFilter.replace')) + '</label>' +
        '<input value="' + escapeAttr(r.replace || '') + '" data-rule-idx="' + i + '" data-rule-field="replace" placeholder="' + escapeAttr(t('promptFilter.emptyRemove')) + '" />' +
        '</div>'
        : '';
      return '<div class="rule-card' + (r.enabled ? '' : ' disabled') + '">' +
        '<div class="rule-header">' +
        '<label class="switch"><input type="checkbox" ' + (r.enabled ? 'checked' : '') + ' data-rule-toggle="' + i + '" /><span class="slider"></span></label>' +
        '<div class="rule-meta">' +
        '<input class="rule-name-input" value="' + escapeAttr(r.name || '') + '" data-rule-idx="' + i + '" data-rule-field="name" placeholder="' + escapeAttr(t('promptFilter.unnamed')) + '" />' +
        '<span class="rule-type">' + escapeHtml(typeLabel) + '</span>' +
        '</div>' +
        '<button class="rule-remove" data-rule-remove="' + i + '" type="button" aria-label="' + escapeAttr(t('common.remove')) + '">&times;</button>' +
        '</div>' +
        '<div class="rule-body">' +
        '<div class="rule-field"><label>' + escapeHtml(t('promptFilter.match')) + '</label>' +
        '<input value="' + escapeAttr(r.match || '') + '" data-rule-idx="' + i + '" data-rule-field="match" placeholder="' + escapeAttr(matchPh) + '" />' +
        '</div>' +
        replaceRow +
        '</div>' +
        '</div>';
    }).join('');
  }
  function addPromptRule(type) {
    promptRules.push({ id: 'rule-' + Date.now(), name: '', type, match: '', replace: '', enabled: true });
    renderPromptRules();
  }

  // Add-account modal templates
  var METHOD_ICONS = {
    builderid: 'fa-solid fa-id-card',
    iam: 'fa-solid fa-key',
    sso: 'fa-solid fa-shield-halved',
    local: 'fa-solid fa-folder-open',
    credentials: 'fa-solid fa-code',
    cookie: 'fa-solid fa-cookie-bite'
  };
  function methodCard(type, title, desc) {
    var icon = METHOD_ICONS[type] || 'fa-solid fa-circle-plus';
    return '<button type="button" class="method-card" data-method="' + escapeAttr(type) + '">' +
      '<span class="method-icon"><i class="' + icon + '" aria-hidden="true"></i></span>' +
      '<span class="method-body">' +
      '<span class="method-title">' + escapeHtml(title) + '</span>' +
      '<span class="method-desc">' + escapeHtml(desc) + '</span>' +
      '</span>' +
      '<span class="method-arrow" aria-hidden="true"><i class="fa-solid fa-chevron-right"></i></span>' +
      '</button>';
  }
  function showModal(type) {
    const modal = $('addModal');
    const title = $('modalTitle');
    const body = $('modalBody');
    if (type === 'add') modalAdd(title, body);
    else if (type === 'builderid') modalBuilderId(title, body);
    else if (type === 'iam') modalIam(title, body);
    else if (type === 'sso') modalSso(title, body);
    else if (type === 'local') modalLocal(title, body);
    else if (type === 'credentials') modalCredentials(title, body);
    else if (type === 'cookie') modalCookie(title, body);
    if (!modal.classList.contains('active')) openDialog('addModal');
    enhanceCustomSelects(body);
  }
  function closeModal() {
    closeDialog('addModal');
    iamSession = '';
    if (builderIdPollTimer) { clearTimeout(builderIdPollTimer); builderIdPollTimer = null; }
    builderIdSession = '';
  }
  function modalAdd(title, body) {
    title.textContent = t('modal.addAccount');
    body.innerHTML =
      '<div class="method-list">' +
      methodCard('builderid', t('modal.builderIdTitle'), t('modal.builderIdDesc')) +
      methodCard('iam', t('modal.iamTitle'), t('modal.iamDesc')) +
      methodCard('sso', t('modal.ssoTitle'), t('modal.ssoDesc')) +
      methodCard('local', t('modal.localTitle'), t('modal.localDesc')) +
      methodCard('credentials', t('modal.credentialsTitle'), t('modal.credentialsDesc')) +
      methodCard('cookie', t('modal.cookieTitle'), t('modal.cookieDesc')) +
      '</div>' +
      '<div class="modal-footer"><button class="btn btn-secondary" data-close-add="1" type="button">' + escapeHtml(t('common.cancel')) + '</button></div>';
  }
  function modalBuilderId(title, body) {
    title.textContent = t('modal.builderIdTitle');
    body.innerHTML =
      '<p class="help-block">' + escapeHtml(t('modal.builderIdDesc')) + '</p>' +
      '<div id="builderIdStep1">' +
      '<div class="form-group"><label>' + escapeHtml(t('detail.region')) + '</label><input type="text" id="builderIdRegion" value="us-east-1" /></div>' +
      '<div class="modal-footer">' +
      '<button class="btn btn-secondary" data-modal-goto="add" type="button">' + escapeHtml(t('common.back')) + '</button>' +
      '<button class="btn btn-primary" id="startBuilderIdBtn" type="button">' + escapeHtml(t('builderid.startLogin')) + '</button>' +
      '</div>' +
      '</div>' +
      '<div id="builderIdStep2" class="hidden">' +
      '<div class="message message-info message-center"><p class="builder-code" id="builderIdUserCode"></p><p class="text-xs mt-2">' + escapeHtml(t('builderid.verifyCode')) + '</p></div>' +
      '<div class="form-group mt-4"><label>' + escapeHtml(t('builderid.verifyUrl')) + '</label>' +
      '<div class="endpoint"><span id="builderIdVerifyUrl" class="font-mono text-xs"></span></div>' +
      '<div class="flex gap-2 mt-2">' +
      '<button class="btn btn-sm btn-outline flex-1" id="builderIdOpenBtn" type="button">' + escapeHtml(t('builderid.open')) + '</button>' +
      '<button class="btn btn-sm btn-outline flex-1" id="builderIdCopyBtn" type="button">' + escapeHtml(t('common.copy')) + '</button>' +
      '</div>' +
      '</div>' +
      '<p id="builderIdStatus" class="text-center text-sm mt-4 muted-text">' + escapeHtml(t('builderid.waiting')) + '</p>' +
      '<div class="modal-footer"><button class="btn btn-secondary" id="builderIdCancelBtn" type="button">' + escapeHtml(t('common.cancel')) + '</button></div>' +
      '</div>';
    $('startBuilderIdBtn').addEventListener('click', startBuilderIdLogin);
  }
  function modalIam(title, body) {
    title.textContent = t('modal.iamTitle');
    body.innerHTML =
      '<p class="help-block">' + escapeHtml(t('modal.iamDesc')) + '</p>' +
      '<div class="form-group"><label>' + escapeHtml(t('iam.startUrl')) + '</label><input type="text" id="iamStartUrl" placeholder="https://xxx.awsapps.com/start" /></div>' +
      '<div class="form-group"><label>' + escapeHtml(t('detail.region')) + '</label><input type="text" id="iamRegion" value="us-east-1" /></div>' +
      '<div id="iamStep2" class="hidden">' +
      '<div class="form-group"><label>' + escapeHtml(t('iam.loginUrl')) + '</label>' +
      '<div class="endpoint"><span id="iamAuthUrl" class="font-mono text-xs"></span></div>' +
      '<div class="flex gap-2 mt-2">' +
      '<button class="btn btn-sm btn-outline flex-1" id="iamOpenBtn" type="button">' + escapeHtml(t('builderid.open')) + '</button>' +
      '<button class="btn btn-sm btn-outline flex-1" id="iamCopyBtn" type="button">' + escapeHtml(t('common.copy')) + '</button>' +
      '</div>' +
      '</div>' +
      '<p class="text-sm mt-3 success-text">' + escapeHtml(t('iam.completeLogin')) + '</p>' +
      '<div class="form-group"><label>' + escapeHtml(t('iam.callbackUrl')) + '</label><input type="text" id="iamCallback" placeholder="http://127.0.0.1:xxx/?code=..." /></div>' +
      '</div>' +
      '<div class="modal-footer">' +
      '<button class="btn btn-secondary" data-modal-goto="add" type="button">' + escapeHtml(t('common.back')) + '</button>' +
      '<button class="btn btn-primary" id="iamBtn" type="button">' + escapeHtml(t('builderid.startLogin')) + '</button>' +
      '</div>';
    $('iamBtn').addEventListener('click', startIamSso);
  }
  function modalSso(title, body) {
    title.textContent = t('modal.ssoTitle');
    body.innerHTML =
      '<div class="help-block">' +
      '<b>' + escapeHtml(t('sso.howToGet')) + '</b>' +
      '<ol class="steps-list">' +
      '<li>' + escapeHtml(t('sso.step1')) + ' <code class="code-inline">view.awsapps.com/start</code></li>' +
      '<li>' + escapeHtml(t('sso.step2')) + '</li>' +
      '<li>' + escapeHtml(t('sso.step3')) + ' <code class="code-inline">x-amz-sso_authn</code></li>' +
      '</ol>' +
      '</div>' +
      '<div class="form-group"><label>' + escapeHtml(t('sso.tokenLabel')) + ' <small>' + escapeHtml(t('sso.tokenHint')) + '</small></label>' +
      '<textarea id="ssoToken" placeholder="' + escapeAttr(t('sso.tokenPlaceholder')) + '"></textarea></div>' +
      '<div class="form-group"><label>' + escapeHtml(t('detail.region')) + '</label><input type="text" id="ssoRegion" value="us-east-1" /></div>' +
      '<div class="modal-footer">' +
      '<button class="btn btn-secondary" data-modal-goto="add" type="button">' + escapeHtml(t('common.back')) + '</button>' +
      '<button class="btn btn-primary" id="importSsoBtn" type="button">' + escapeHtml(t('common.add')) + '</button>' +
      '</div>';
    $('importSsoBtn').addEventListener('click', importSsoToken);
  }

  function modalLocal(title, body) {
    title.textContent = t('modal.localTitle');
    body.innerHTML =
      '<p class="help-block">' + escapeHtml(t('modal.localDesc')) + '</p>' +
      '<div class="help-block">' +
      '<p><b>' + escapeHtml(t('local.fileLocation')) + '</b></p>' +
      '<p>' + escapeHtml(t('local.windows')) + ': <code class="code-inline">%USERPROFILE%\\.aws\\sso\\cache\\</code></p>' +
      '<p>' + escapeHtml(t('local.macosLinux')) + ': <code class="code-inline">~/.aws/sso/cache/</code></p>' +
      '</div>' +
      '<div class="form-group"><label>' + escapeHtml(t('local.loginChannel')) + '</label>' +
      '<select id="localProvider">' +
      '<option value="BuilderId">' + escapeHtml(t('local.providerBuilderId')) + '</option>' +
      '<option value="Enterprise">' + escapeHtml(t('local.providerEnterprise')) + '</option>' +
      '<option value="Google">' + escapeHtml(t('local.providerGoogle')) + '</option>' +
      '<option value="Github">' + escapeHtml(t('local.providerGithub')) + '</option>' +
      '</select>' +
      '</div>' +
      '<div class="form-group">' +
      '<label>' + escapeHtml(t('local.tokenFile')) + ' <small>' + escapeHtml(t('local.tokenRequired')) + '</small></label>' +
      '<div class="input-row">' +
      '<textarea id="localTokenJson" placeholder="' + escapeAttr(t('local.pasteOrUpload')) + '" class="font-mono"></textarea>' +
      '<label class="btn btn-outline btn-sm">' + escapeHtml(t('local.upload')) +
      '<input type="file" accept=".json" id="localTokenFile" class="file-input-hidden" />' +
      '</label>' +
      '</div>' +
      '</div>' +
      '<div id="localClientGroup" class="form-group">' +
      '<label>' + escapeHtml(t('local.clientFile')) + ' <small>' + escapeHtml(t('local.clientRequired')) + '</small></label>' +
      '<div class="input-row">' +
      '<textarea id="localClientJson" placeholder="' + escapeAttr(t('local.pasteOrUpload')) + '" class="font-mono"></textarea>' +
      '<label class="btn btn-outline btn-sm">' + escapeHtml(t('local.upload')) +
      '<input type="file" accept=".json" id="localClientFile" class="file-input-hidden" />' +
      '</label>' +
      '</div>' +
      '</div>' +
      '<div class="modal-footer">' +
      '<button class="btn btn-secondary" data-modal-goto="add" type="button">' + escapeHtml(t('common.back')) + '</button>' +
      '<button class="btn btn-primary" id="importLocalBtn" type="button">' + escapeHtml(t('common.add')) + '</button>' +
      '</div>';
    $('localProvider').addEventListener('change', updateLocalFields);
    $('localTokenFile').addEventListener('change', e => loadLocalFile(e.target, 'localTokenJson'));
    $('localClientFile').addEventListener('change', e => loadLocalFile(e.target, 'localClientJson'));
    $('importLocalBtn').addEventListener('click', importLocalKiro);
  }
  function modalCredentials(title, body) {
    title.textContent = t('modal.credentialsTitle');
    body.innerHTML =
      '<p class="help-block">' + escapeHtml(t('modal.credentialsDesc')) + '</p>' +
      '<p class="help-block">' + escapeHtml(t('credentials.batchHint')) + '</p>' +
      '<div class="form-group"><label>' + escapeHtml(t('credentials.label')) + '</label>' +
      '<textarea id="credJson" class="font-mono" placeholder=\'[{"refreshToken":"xxx","provider":"BuilderID"}]&#10;or&#10;email----password----refreshToken----clientId----clientSecret\'></textarea>' +
      '</div>' +
      '<div class="modal-footer">' +
      '<button class="btn btn-secondary" data-modal-goto="add" type="button">' + escapeHtml(t('common.back')) + '</button>' +
      '<button class="btn btn-primary" id="importCredBtn" type="button">' + escapeHtml(t('common.add')) + '</button>' +
      '</div>';
    $('importCredBtn').addEventListener('click', importCredentials);
  }
  function modalCookie(title, body) {
    title.textContent = t('modal.cookieTitle');
    body.innerHTML =
      '<div class="help-block">' +
      '<p><b>' + escapeHtml(t('cookie.howToGet')) + '</b></p>' +
      '<ol class="steps-list">' +
      '<li>' + escapeHtml(t('cookie.step1')) + ' <a href="' + escapeAttr(t('cookie.link')) + '" target="_blank">' + escapeHtml(t('cookie.link')) + '</a></li>' +
      '<li>' + escapeHtml(t('cookie.step2')) + '</li>' +
      '<li>' + escapeHtml(t('cookie.step3')) + '</li>' +
      '</ol>' +
      '</div>' +
      '<div class="form-group"><label>' + escapeHtml(t('cookie.provider')) + '</label>' +
      '<select id="cookieProvider">' +
      '<option value="Google">' + escapeHtml(t('cookie.google')) + '</option>' +
      '<option value="Github">' + escapeHtml(t('cookie.github')) + '</option>' +
      '</select>' +
      '</div>' +
      '<div class="form-group"><label>' + escapeHtml(t('cookie.refreshToken')) + '</label>' +
      '<textarea id="cookieRefreshToken" class="font-mono" placeholder="' + escapeAttr(t('cookie.refreshTokenPlaceholder')) + '"></textarea>' +
      '</div>' +
      '<div class="modal-footer">' +
      '<button class="btn btn-secondary" data-modal-goto="add" type="button">' + escapeHtml(t('common.back')) + '</button>' +
      '<button class="btn btn-primary" id="importCookieBtn" type="button">' + escapeHtml(t('common.add')) + '</button>' +
      '</div>';
    $('importCookieBtn').addEventListener('click', importFromCookie);
  }
  function updateLocalFields() {
    const p = $('localProvider').value;
    $('localClientGroup').classList.toggle('hidden', p === 'Google' || p === 'Github');
  }
  function loadLocalFile(input, targetId) {
    const file = input.files[0];
    if (!file) return;
    const r = new FileReader();
    r.onload = e => { $(targetId).value = e.target.result; };
    r.readAsText(file);
  }

  // Import handlers
  async function importLocalKiro() {
    const provider = $('localProvider').value;
    const tokenJson = $('localTokenJson').value.trim();
    const clientJson = $('localClientJson').value.trim();
    const isSocial = provider === 'Google' || provider === 'Github';
    if (!tokenJson) return toastWarning(t('local.tokenMissing'));
    let tokenData, clientData;
    try { tokenData = JSON.parse(tokenJson); } catch { return toastWarning(t('local.tokenInvalid')); }
    if (!tokenData.refreshToken) return toastWarning(t('local.refreshTokenMissing'));
    if (!isSocial) {
      if (!clientJson) return toastWarning(t('local.clientMissing'));
      try { clientData = JSON.parse(clientJson); } catch { return toastWarning(t('local.clientInvalid')); }
      if (!clientData.clientId || !clientData.clientSecret) return toastWarning(t('local.clientSecretMissing'));
    }
    const authMethod = clientData ? 'idc' : 'social';
    const payload = {
      refreshToken: tokenData.refreshToken,
      accessToken: tokenData.accessToken || '',
      clientId: clientData?.clientId || '',
      clientSecret: clientData?.clientSecret || '',
      region: tokenData.region || '',
      authMethod, provider
    };
    const res = await api('/auth/credentials', { method: 'POST', body: JSON.stringify(payload) });
    const d = await res.json();
    if (d.success) {
      closeModal(); loadAccounts(); loadStats();
      toastPrimary(t('local.importSuccess') + ': ' + (d.account?.email || d.account?.id));
      autoRefreshNewAccount(d.account?.id);
    } else toastError(t('common.failed') + ': ' + (d.error || ''));
  }
  async function importCredentials() {
    const raw = $('credJson').value.trim();
    if (!raw) { toastWarning(t('credentials.jsonError')); return; }
    let items;
    let skipped = 0;
    try {
      const json = JSON.parse(raw);
      if (json.accounts && Array.isArray(json.accounts)) {
        items = json.accounts.map(a => {
          const c = a.credentials || {};
          return {
            refreshToken: c.refreshToken || a.refreshToken,
            clientId: c.clientId || a.clientId,
            clientSecret: c.clientSecret || a.clientSecret,
            region: c.region || a.region,
            authMethod: c.authMethod || a.authMethod,
            provider: c.provider || a.provider || a.idp
          };
        });
      } else {
        items = Array.isArray(json) ? json : [json];
      }
    } catch {
      const parsed = parseLineCredentials(raw);
      items = parsed.items;
      skipped = parsed.skipped;
      if (items.length === 0 && skipped === 0) {
        toastWarning(t('credentials.jsonError'));
        return;
      }
      if (items.length === 0) {
        toastWarning(t('credentials.lineParseAllSkipped', skipped));
        return;
      }
    }
    let ok = 0, fail = 0, newIds = [];
    for (const item of items) {
      if (!item.refreshToken) { fail++; continue; }
      let authMethod = item.authMethod || '';
      if (item.clientId && item.clientSecret) authMethod = 'idc';
      else if (!authMethod || authMethod === 'social') authMethod = 'social';
      else authMethod = authMethod.toLowerCase() === 'idc' ? 'idc' : 'social';
      let provider = item.provider || '';
      if (!provider && authMethod === 'social') provider = 'Google';
      if (!provider && authMethod === 'idc') provider = 'BuilderId';
      const payload = {
        refreshToken: item.refreshToken,
        accessToken: item.accessToken || '',
        clientId: item.clientId || '',
        clientSecret: item.clientSecret || '',
        authMethod, provider,
        region: item.region || 'us-east-1'
      };
      try {
        const res = await api('/auth/credentials', { method: 'POST', body: JSON.stringify(payload) });
        const d = await res.json();
        if (d.success) { ok++; if (d.account?.id) newIds.push(d.account.id); }
        else fail++;
      } catch { fail++; }
    }
    closeModal(); loadAccounts(); loadStats();
    let msg = t('sso.importSuccess', ok);
    if (fail > 0) msg += t('sso.importPartial', fail);
    if (skipped > 0) msg += t('credentials.lineParseSkipped', skipped);
    toastPrimary(msg, { duration: 5200 });
    newIds.forEach(autoRefreshNewAccount);
  }
  function parseLineCredentials(text) {
    const items = [];
    let skipped = 0;
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      let parts;
      if (trimmed.includes('----')) {
        parts = trimmed.split('----').map(s => s.trim());
      } else if (trimmed.includes('\t')) {
        parts = trimmed.split(/\t+/).map(s => s.trim());
      } else {
        parts = trimmed.split(/\s+/).map(s => s.trim());
      }
      if (parts.length < 5) { skipped++; continue; }
      const refreshToken = parts[2];
      if (!refreshToken) { skipped++; continue; }
      items.push({
        refreshToken,
        clientId: parts[3],
        clientSecret: parts[4],
      });
    }
    return { items, skipped };
  }
  async function importFromCookie() {
    const refreshToken = $('cookieRefreshToken').value.trim();
    if (!refreshToken) return toastWarning(t('cookie.refreshTokenMissing'));
    const provider = $('cookieProvider').value;
    const payload = { refreshToken, accessToken: '', clientId: '', clientSecret: '', authMethod: 'social', provider };
    const res = await api('/auth/credentials', { method: 'POST', body: JSON.stringify(payload) });
    const d = await res.json();
    if (d.success) {
      closeModal(); loadAccounts(); loadStats();
      toastPrimary(t('cookie.importSuccess') + ': ' + (d.account?.email || d.account?.id));
      autoRefreshNewAccount(d.account?.id);
    } else toastError(t('common.failed') + ': ' + (d.error || ''));
  }
  async function importSsoToken() {
    const res = await api('/auth/sso-token', {
      method: 'POST', body: JSON.stringify({
        bearerToken: $('ssoToken').value,
        region: $('ssoRegion').value
      })
    });
    const d = await res.json();
    if (d.success) {
      closeModal(); loadAccounts(); loadStats();
      const count = d.accounts?.length || 0;
      const errs = d.errors?.length || 0;
      let msg = t('sso.importSuccess', count);
      if (errs > 0) msg += t('sso.importPartial', errs);
      toastPrimary(msg, { duration: 5200 });
      if (d.accounts) d.accounts.forEach(a => autoRefreshNewAccount(a.id));
    } else toastError(t('common.failed') + ': ' + (d.error || ''));
  }
  async function startBuilderIdLogin() {
    const region = $('builderIdRegion').value || 'us-east-1';
    const res = await api('/auth/builderid/start', { method: 'POST', body: JSON.stringify({ region }) });
    const d = await res.json();
    if (d.sessionId) {
      builderIdSession = d.sessionId;
      $('builderIdUserCode').textContent = d.userCode;
      $('builderIdVerifyUrl').textContent = d.verificationUri;
      $('builderIdStep1').classList.add('hidden');
      $('builderIdStep2').classList.remove('hidden');
      $('builderIdOpenBtn').addEventListener('click', () => window.open($('builderIdVerifyUrl').textContent, '_blank'));
      $('builderIdCopyBtn').addEventListener('click', async () => {
        await copyText($('builderIdVerifyUrl').textContent);
        toast(t('common.copied'), 'primary');
      });
      $('builderIdCancelBtn').addEventListener('click', cancelBuilderIdLogin);
      pollBuilderIdAuth(d.interval || 5);
    } else toastError(t('common.failed') + ': ' + (d.error || ''));
  }
  function pollBuilderIdAuth(interval) {
    builderIdPollTimer = setTimeout(async () => {
      const res = await api('/auth/builderid/poll', { method: 'POST', body: JSON.stringify({ sessionId: builderIdSession }) });
      const d = await res.json();
      if (d.completed) {
        closeModal(); loadAccounts(); loadStats();
        toastPrimary(t('builderid.success') + ': ' + (d.account?.email || d.account?.id));
        autoRefreshNewAccount(d.account?.id);
      } else if (d.success && !d.completed) {
        $('builderIdStatus').textContent = t('builderid.waiting');
        pollBuilderIdAuth(d.interval || interval);
      } else {
        toastError(t('common.failed') + ': ' + (d.error || ''));
        cancelBuilderIdLogin();
      }
    }, interval * 1000);
  }
  function cancelBuilderIdLogin() {
    if (builderIdPollTimer) { clearTimeout(builderIdPollTimer); builderIdPollTimer = null; }
    builderIdSession = '';
    showModal('add');
  }
  async function startIamSso() {
    if (iamSession) {
      const res = await api('/auth/iam-sso/complete', {
        method: 'POST', body: JSON.stringify({
          sessionId: iamSession, callbackUrl: $('iamCallback').value
        })
      });
      const d = await res.json();
      if (d.success) {
        closeModal(); loadAccounts(); loadStats();
        toastPrimary(t('builderid.success') + ': ' + (d.account?.email || d.account?.id));
        autoRefreshNewAccount(d.account?.id);
      } else toastError(t('common.failed') + ': ' + (d.error || ''));
    } else {
      const res = await api('/auth/iam-sso/start', {
        method: 'POST', body: JSON.stringify({
          startUrl: $('iamStartUrl').value, region: $('iamRegion').value
        })
      });
      const d = await res.json();
      if (d.authorizeUrl) {
        iamSession = d.sessionId;
        $('iamAuthUrl').textContent = d.authorizeUrl;
        $('iamStep2').classList.remove('hidden');
        $('iamBtn').textContent = t('iam.complete');
        $('iamOpenBtn').addEventListener('click', () => window.open($('iamAuthUrl').textContent, '_blank'));
        $('iamCopyBtn').addEventListener('click', async () => {
          await copyText($('iamAuthUrl').textContent);
          toast(t('common.copied'), 'primary');
        });
      } else toastError(t('common.failed') + ': ' + (d.error || ''));
    }
  }
  async function autoRefreshNewAccount(id) {
    if (!id) return;
    try { await api('/accounts/' + id + '/refresh', { method: 'POST' }); } catch (e) { }
    loadAccounts();
  }

  // Export modal
  function showExportModal() {
    if (!accountsData.length) return toastWarning(t('accounts.empty'));
    exportSelectedIds = new Set(accountsData.map(a => a.id));
    renderExportModal();
    openDialog('exportModal');
  }
  function closeExportModal() { closeDialog('exportModal'); }
  function renderExportModal() {
    const body = $('exportBody');
    const all = exportSelectedIds.size === accountsData.length;
    body.innerHTML =
      '<div class="flex items-center justify-between mb-3">' +
      '<span class="text-sm muted-text">' + escapeHtml(t('export.selected', exportSelectedIds.size)) + '</span>' +
      '<button class="btn btn-sm btn-outline" id="exportToggleAllBtn" type="button">' + escapeHtml(all ? t('export.deselectAll') : t('export.selectAll')) + '</button>' +
      '</div>' +
      '<div class="export-list">' +
      accountsData.map(a => {
        const checked = exportSelectedIds.has(a.id);
        return '<label class="export-row' + (checked ? ' selected' : '') + '">' +
          '<input type="checkbox" ' + (checked ? 'checked' : '') + ' data-export-toggle="' + escapeAttr(a.id) + '" />' +
          '<div class="export-row-text">' +
          '<div class="export-row-email">' + escapeHtml(getDisplayEmail(a.email, a.id)) + '</div>' +
          '<div class="export-row-meta">' + escapeHtml(formatAuthMethod(a.provider || a.authMethod)) + ' · ' + escapeHtml(formatSubscriptionLabel(a.subscriptionType)) + '</div>' +
          '</div>' +
          '</label>';
      }).join('') +
      '</div>' +
      '<div id="exportJsonPreview" class="hidden mb-3"><textarea id="exportJsonText" readonly class="font-mono"></textarea></div>' +
      '<div class="modal-footer">' +
      '<button class="btn btn-secondary" id="exportCloseBtn" type="button">' + escapeHtml(t('common.cancel')) + '</button>' +
      '<button class="btn btn-outline" id="exportShowJsonBtn" type="button">' + escapeHtml(t('export.showJson')) + '</button>' +
      '<button class="btn btn-outline" id="exportCopyJsonBtn" type="button">' + escapeHtml(t('export.copyJson')) + '</button>' +
      '<button class="btn btn-primary" id="exportDownloadBtn" type="button">' + escapeHtml(t('export.downloadJson')) + '</button>' +
      '</div>';
    $('exportToggleAllBtn').addEventListener('click', () => {
      if (exportSelectedIds.size === accountsData.length) exportSelectedIds.clear();
      else exportSelectedIds = new Set(accountsData.map(a => a.id));
      renderExportModal();
    });
    $('exportCloseBtn').addEventListener('click', closeExportModal);
    $('exportShowJsonBtn').addEventListener('click', exportShowJson);
    $('exportCopyJsonBtn').addEventListener('click', exportCopyJson);
    $('exportDownloadBtn').addEventListener('click', exportDownloadJson);
    qsa('[data-export-toggle]', body).forEach(cb => cb.addEventListener('change', e => {
      const id = e.target.dataset.exportToggle;
      if (exportSelectedIds.has(id)) exportSelectedIds.delete(id);
      else exportSelectedIds.add(id);
      renderExportModal();
    }));
  }
  async function getExportData() {
    if (exportSelectedIds.size === 0) { toastWarning(t('export.noSelection')); return null; }
    const res = await api('/export', { method: 'POST', body: JSON.stringify({ ids: Array.from(exportSelectedIds) }) });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      toastError(t('common.failed') + ': ' + (err.error || t('common.unknownError')));
      return null;
    }
    return res.json();
  }
  async function exportShowJson() {
    const data = await getExportData();
    if (!data) return;
    $('exportJsonPreview').classList.remove('hidden');
    $('exportJsonText').value = JSON.stringify(data, null, 2);
  }
  async function exportCopyJson() {
    if (exportSelectedIds.size === 0) { toastWarning(t('export.noSelection')); return; }
    const jsonPromise = getExportData().then(data => {
      if (!data) throw new Error('no-data');
      const filtered = (data.accounts || []).map(a => {
        const { clientId, clientSecret, accessToken, refreshToken } = a.credentials || {};
        return { clientId, clientSecret, accessToken, refreshToken };
      });
      return JSON.stringify(filtered, null, 2);
    });
    try {
      await copyText(jsonPromise);
      toast(t('export.copied'), 'primary');
    } catch (e) {
      if (e && e.message !== 'no-data') toastError(t('common.failed'));
    }
  }
  async function exportDownloadJson() {
    const data = await getExportData();
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'kiro-accounts-' + new Date().toISOString().slice(0, 10) + '.json';
    a.click();
    URL.revokeObjectURL(url);
  }

  // Version and update
  function renderVersionBadge() {
    const badge = $('versionBadge');
    if (badge && currentVersion) badge.textContent = currentVersion.replace(/^v/i, '');
  }
  async function loadVersion() {
    try {
      const res = await api('/version');
      const d = await res.json();
      currentVersion = d.version || '';
      renderVersionBadge();
    } catch (e) { }
  }
  function compareVersions(a, b) {
    const pa = a.split('.').map(Number);
    const pb = b.split('.').map(Number);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const na = pa[i] || 0, nb = pb[i] || 0;
      if (na > nb) return 1;
      if (na < nb) return -1;
    }
    return 0;
  }
  function setUpdateButtonLoading(loading) {
    const btn = $('checkUpdateBtn');
    if (!btn) return;
    btn.disabled = loading;
    if (loading) btn.setAttribute('aria-busy', 'true');
    else btn.removeAttribute('aria-busy');
    const label = btn.querySelector('[data-update-label]');
    const icon = btn.querySelector('i');
    if (label) label.textContent = t(loading ? 'update.checking' : 'update.check');
    if (icon) icon.classList.toggle('fa-spin', loading);
  }
  async function checkUpdate(manual) {
    if (manual) setUpdateButtonLoading(true);
    try {
      if (!currentVersion) await loadVersion();
      const current = currentVersion.replace(/^v/i, '');
      if (!current) throw new Error('Current version missing');
      const res = await fetch('https://raw.githubusercontent.com/Quorinex/Kiro-Go/main/version.json?t=' + Date.now());
      if (!res.ok) throw new Error('Fetch failed');
      const d = await res.json();
      const latest = (d.version || '').replace(/^v/i, '');
      if (!latest) throw new Error('Latest version missing');
      if (latest && latest !== current && compareVersions(latest, current) > 0) {
        if (manual) showUpdateModal(latest, d.download, d.changelog);
        else showUpdateToast('available', current, latest);
      } else if (manual) {
        showUpdateToast('current', current, latest || current);
      }
    } catch (e) {
      if (manual) showUpdateToast('error', '', '');
    } finally {
      if (manual) setUpdateButtonLoading(false);
    }
  }
  function showUpdateToast(status, current, latest) {
    if (status === 'available') {
      toast(t('update.availableToast') + (latest ? ': ' + latest : ''), 'warning', {
        icon: 'fa-solid fa-arrow-up',
        duration: 5200,
        onClick: function () { checkUpdate(true); }
      });
      return;
    }
    if (status === 'current') {
      toast(t('update.noUpdatesToast'), 'success', {
        icon: 'fa-solid fa-circle-check',
        duration: 3600
      });
      return;
    }
    toast(t('update.checkFailed'), 'error', {
      icon: 'fa-solid fa-triangle-exclamation',
      duration: 4200
    });
  }
  function showUpdateModal(version, url, changelog) {
    const current = currentVersion.replace(/^v/i, '');
    $('updateBody').innerHTML =
      '<div class="update-shell">' +
      '<div class="update-hero">' +
      '<div class="update-result-icon update-result-info"><i class="fa-solid fa-arrow-up"></i></div>' +
      '<div>' +
      '<h3 class="update-hero-title">' + escapeHtml(t('update.newVersion')) + '</h3>' +
      '<p class="update-hero-copy">' + escapeHtml(t('update.newVersionMessage')) + '</p>' +
      '</div>' +
      '</div>' +
      '<div class="update-version-grid">' +
      '<div class="update-version-card update-version-card-current"><p class="update-version-label">' + escapeHtml(t('update.current')) + '</p><p class="update-version-value update-version-value-current">' + escapeHtml(current) + '</p></div>' +
      '<div class="update-version-card update-version-card-latest"><p class="update-version-label">' + escapeHtml(t('update.latest')) + '</p><p class="update-version-value update-version-value-success">' + escapeHtml(version) + '</p></div>' +
      '</div>' +
      (changelog ? '<div class="update-notes"><p class="update-notes-title">' + escapeHtml(t('update.changelog')) + '</p><p class="update-notes-body">' + escapeHtml(changelog) + '</p></div>' : '') +
      '<div class="update-actions"><a href="' + escapeAttr(url) + '" target="_blank" rel="noopener" class="btn btn-primary">' + escapeHtml(t('update.goDownload')) + '</a></div>' +
      '</div>';
    openDialog('updateModal');
  }
  function showUpdateStatusModal(status, title, message, latest) {
    const current = currentVersion.replace(/^v/i, '');
    const isError = status === 'error';
    $('updateBody').innerHTML =
      '<div class="update-shell">' +
      '<div class="text-center mb-5">' +
      '<div class="update-result-icon update-status-icon update-result-' + (isError ? 'error' : 'success') + '">' +
      '<i class="fa-solid ' + (isError ? 'fa-triangle-exclamation' : 'fa-circle-check') + '"></i>' +
      '</div>' +
      '<p class="text-base font-semibold ' + (isError ? 'danger-text' : 'success-text') + '">' + escapeHtml(title) + '</p>' +
      '<p class="text-sm mt-2 muted-text">' + escapeHtml(message) + '</p>' +
      '</div>' +
      '<div class="update-version-grid">' +
      '<div class="update-version-card update-version-card-current"><p class="update-version-label">' + escapeHtml(t('update.current')) + '</p><p class="update-version-value update-version-value-current">' + escapeHtml(current || '-') + '</p></div>' +
      '<div class="update-version-card' + (!isError ? ' update-version-card-latest' : '') + '"><p class="update-version-label">' + escapeHtml(t('update.latest')) + '</p><p class="update-version-value' + (!isError ? ' update-version-value-success' : '') + '">' + escapeHtml(latest || '-') + '</p></div>' +
      '</div>' +
      '</div>';
    openDialog('updateModal');
  }
  function closeUpdateModal() { closeDialog('updateModal'); }

  // Tabs
  function switchTab(tab) {
    qsa('.tab').forEach(el => el.classList.toggle('active', el.dataset.tab === tab));
    qsa('.tab-content').forEach(c => c.classList.add('hidden'));
    $('tab' + tab.charAt(0).toUpperCase() + tab.slice(1)).classList.remove('hidden');
    if (tab === 'logs') loadLogs();
  }

  // Event wiring
  function bindLoginEvents() {
    $('loginBtn').addEventListener('click', login);
    $('pwdField').addEventListener('keypress', e => { if (e.key === 'Enter') login(); });

    const pwdToggle = $('pwdToggle');
    if (pwdToggle) {
      pwdToggle.addEventListener('click', () => {
        const f = $('pwdField');
        const willShow = f.type === 'password';
        f.type = willShow ? 'text' : 'password';
        pwdToggle.dataset.shown = String(willShow);
        pwdToggle.setAttribute('aria-label', willShow ? t('login.hidePassword') : t('login.showPassword'));
        pwdToggle.innerHTML = willShow
          ? '<i class="fa-solid fa-eye-slash"></i>'
          : '<i class="fa-solid fa-eye"></i>';
      });
    }
  }

  function bindShellEvents() {
    const checkUpdateBtn = $('checkUpdateBtn');
    if (checkUpdateBtn) checkUpdateBtn.addEventListener('click', () => checkUpdate(true));

    document.body.addEventListener('click', e => {
      if (!e.target.closest('.custom-select')) closeAllCustomSelects();
      const lb = e.target.closest('.lang-btn');
      if (lb) setLang(lb.dataset.lang);
      const lt = e.target.closest('.lang-toggle');
      if (lt) toggleLang();
    });
    window.addEventListener('resize', positionOpenCustomSelects);
    window.addEventListener('scroll', positionOpenCustomSelects, true);

    $('loginThemeToggle').addEventListener('click', toggleTheme);
    $('mainThemeToggle').addEventListener('click', toggleTheme);
    $('logoutBtn').addEventListener('click', logout);

    qsa('#tabBar .tab').forEach(tab => tab.addEventListener('click', () => switchTab(tab.dataset.tab)));

    qsa('[data-copy]').forEach(btn => btn.addEventListener('click', async () => {
      const id = btn.dataset.copy;
      const target = $(id);
      if (!target) return;
      try {
        await copyText(target.dataset.rawValue || target.textContent);
        toast(t('common.copied'), 'primary');
      } catch (e) {
        toast(t('common.failed'), 'error');
      }
    }));

    // API View buttons
    $('viewModelsBtn').addEventListener('click', showModelsView);
    $('viewStatsBtn').addEventListener('click', showStatsView);
    $('apiViewModalClose').addEventListener('click', closeApiViewModal);
    bindDialogBackdropClose('apiViewModal', closeApiViewModal);

    // Logs tab
    const logsRefreshBtn = $('logsRefreshBtn');
    if (logsRefreshBtn) logsRefreshBtn.addEventListener('click', loadLogs);
    const logsClearBtn = $('logsClearBtn');
    if (logsClearBtn) logsClearBtn.addEventListener('click', clearLogs);
    const logsAuto = $('logsAutoRefresh');
    if (logsAuto) logsAuto.addEventListener('change', toggleLogsAutoRefresh);
    const logsFilterSel = $('logsFilterSelect');
    if (logsFilterSel) logsFilterSel.addEventListener('change', e => {
      logsFilter = e.target.value;
      loadLogs();
    });
  }

  function bindAccountEvents() {
    $('privacyModeToggle').addEventListener('change', e => {
      privacyModeEnabled = e.target.checked;
      localStorage.setItem('privacyMode', privacyModeEnabled);
      renderAccounts();
    });

    $('exportBtn').addEventListener('click', showExportModal);
    $('refreshAllModelsBtn').addEventListener('click', refreshAllModels);
    $('addAccountBtn').addEventListener('click', () => showModal('add'));

    $('selectAllCheckbox').addEventListener('change', e => toggleSelectAll(e.target.checked));
    qsa('[data-batch]').forEach(b => b.addEventListener('click', () => {
      const a = b.dataset.batch;
      if (a === 'refreshModels') batchRefreshModels();
      else if (a === 'delete') batchDelete();
      else batchAction(a);
    }));

    $('filterSearch').addEventListener('input', onFilterChange);
    $('filterStatusSelect').addEventListener('change', onFilterChange);

    $('accountsList').addEventListener('click', e => {
      const cb = e.target.closest('.account-checkbox');
      if (cb) {
        toggleSelectAccount(cb.dataset.id);
        const card = cb.closest('.account-card');
        if (card) card.classList.toggle('selected', cb.checked);
        return;
      }
      const btn = e.target.closest('button[data-action]');
      if (!btn) return;
      const id = btn.dataset.id;
      const action = btn.dataset.action;
      if (action === 'refresh') refreshAccount(id, btn.closest('.account-card'));
      else if (action === 'detail') showDetail(id);
      else if (action === 'copyJSON') copyAccountJSON(id, btn);
      else if (action === 'toggle') toggleAccount(id, btn.dataset.enabled === 'true');
      else if (action === 'test') testAccount(id);
      else if (action === 'delete') deleteAccount(id);
    });
  }

  function bindSettingsEvents() {
    $('saveRequireApiKeyBtn').addEventListener('click', saveRequireApiKey);
    $('saveOverUsageBtn').addEventListener('click', saveOverUsageConfig);
    $('saveThinkingBtn').addEventListener('click', saveThinkingConfig);
    $('saveEndpointBtn').addEventListener('click', saveEndpointConfig);
    $('changePasswordBtn').addEventListener('click', changePassword);
    $('proxyType').addEventListener('change', onProxyTypeChange);
    $('saveProxyBtn').addEventListener('click', saveProxyConfig);
    $('resetStatsBtn').addEventListener('click', resetStats);
    bindApiKeyEvents();
  }

  function bindPromptFilterEvents() {
    $('savePromptFilterBtn').addEventListener('click', savePromptFilter);
    $('addRuleRegexBtn').addEventListener('click', () => addPromptRule('regex'));
    $('addRuleContainsBtn').addEventListener('click', () => addPromptRule('lines-containing'));

    $('promptFilterRules').addEventListener('input', e => {
      const idx = e.target.dataset.ruleIdx;
      const field = e.target.dataset.ruleField;
      if (idx != null && field) promptRules[idx][field] = e.target.value;
    });
    $('promptFilterRules').addEventListener('change', e => {
      if (e.target.dataset.ruleToggle != null) {
        promptRules[e.target.dataset.ruleToggle].enabled = e.target.checked;
        renderPromptRules();
      }
    });
    $('promptFilterRules').addEventListener('click', e => {
      const rm = e.target.closest('[data-rule-remove]');
      if (rm) { promptRules.splice(parseInt(rm.dataset.ruleRemove, 10), 1); renderPromptRules(); }
    });
  }

  function bindModalEvents() {
    $('addModalClose').addEventListener('click', closeModal);
    $('detailModalClose').addEventListener('click', closeDetailModal);
    $('exportModalClose').addEventListener('click', closeExportModal);
    $('testModalClose').addEventListener('click', closeTestModal);
    $('updateModalClose').addEventListener('click', closeUpdateModal);
    [
      ['addModal', closeModal],
      ['detailModal', closeDetailModal],
      ['exportModal', closeExportModal],
      ['testModal', closeTestModal],
      ['updateModal', closeUpdateModal],
      ['confirmModal', () => closeConfirm(false)],
    ].forEach(([id, fn]) => bindDialogBackdropClose(id, fn));

    $('modalBody').addEventListener('click', e => {
      const m = e.target.closest('[data-method]');
      if (m) { showModal(m.dataset.method); return; }
      const g = e.target.closest('[data-modal-goto]');
      if (g) { showModal(g.dataset.modalGoto); return; }
      if (e.target.dataset.closeAdd) closeModal();
    });
  }

  function bindDetailEvents() {
    $('detailBody').addEventListener('click', e => {
      if (e.target.id === 'generateMachineIdBtn') { generateMachineId(); return; }
      const b = e.target.closest('[data-detail-action]');
      if (!b) return;
      const id = b.dataset.id;
      const a = b.dataset.detailAction;
      if (a === 'saveMachineId') saveMachineId(id);
      else if (a === 'saveWeight') saveWeight(id);
      else if (a === 'toggleOverage') toggleOverageSwitch(id, b);
      else if (a === 'refreshOverage') refreshAccountOverage(id);
      else if (a === 'saveProxyURL') saveProxyURL(id);
      else if (a === 'loadModels') loadModels(id);
      else if (a === 'refreshModels') refreshAccountModels(id);
    });
  }

  function bindTestEvents() {
    $('testBody').addEventListener('click', e => {
      if (e.target.id === 'testLogClear') { clearTestLog(); return; }
      if (e.target.id === 'testModalCancelBtn') { closeTestModal(); return; }
      const run = e.target.closest('#testRunBtn');
      if (run) runTestAccount(run.dataset.id, getTestModelValue());
    });
    $('testBody').addEventListener('keydown', e => {
      if (e.key !== 'Enter') return;
      if (!e.target.closest('#testModelChoice')) return;
      const run = $('testRunBtn');
      if (!run || run.disabled) return;
      e.preventDefault();
      runTestAccount(run.dataset.id, getTestModelValue());
    });
  }

  // ── API View Modal ──
  function closeApiViewModal() {
    closeDialog('apiViewModal');
  }

  function formatUptime(seconds) {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    const parts = [];
    if (d > 0) parts.push(d + (currentLang === 'zh' ? '天' : 'd'));
    if (h > 0) parts.push(h + (currentLang === 'zh' ? '时' : 'h'));
    if (m > 0) parts.push(m + (currentLang === 'zh' ? '分' : 'm'));
    parts.push(s + (currentLang === 'zh' ? '秒' : 's'));
    return parts.join(' ');
  }

  async function showModelsView() {
    const title = $('apiViewTitle');
    const body = $('apiViewBody');
    title.textContent = t('api.viewModelsTitle');
    body.innerHTML = '<div class="api-view-loading"><i class="fa-solid fa-spinner fa-spin"></i> ' + escapeHtml(t('api.loading')) + '</div>';
    openDialog('apiViewModal');

    try {
      const res = await fetch(baseUrl + '/v1/models');
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      const models = data.data || [];
      renderModelsView(body, models);
    } catch (e) {
      body.innerHTML = '<div class="api-view-error"><i class="fa-solid fa-circle-exclamation"></i> ' + escapeHtml(t('api.fetchError') + ': ' + e.message) + '</div>';
    }
  }

  function renderModelsView(container, models) {
    const thinkingSuffix = '-thinking';
    let html = '<div class="api-view-toolbar">';
    html += '<span class="api-view-count">' + escapeHtml(t('api.totalModels').replace('{count}', models.length)) + '</span>';
    html += '<input type="text" class="api-view-search" id="modelsSearchInput" placeholder="' + escapeAttr(t('api.searchModels')) + '" />';
    html += '</div>';
    html += '<div id="modelsGridContainer">';
    html += buildModelsGroupedHtml(models, thinkingSuffix);
    html += '</div>';
    container.innerHTML = html;

    const searchInput = $('modelsSearchInput');
    if (searchInput) {
      searchInput.addEventListener('input', () => {
        const kw = searchInput.value.toLowerCase().trim();
        const filtered = kw ? models.filter(m => (m.id || '').toLowerCase().includes(kw) || (m.owned_by || '').toLowerCase().includes(kw)) : models;
        $('modelsGridContainer').innerHTML = buildModelsGroupedHtml(filtered, thinkingSuffix);
      });
    }
  }

  // SVG icons for model providers (inline style forces size over Tailwind preflight)
  const _svgStyle = 'style="width:1.375rem;height:1.375rem;max-width:1.375rem;max-height:1.375rem;flex:none;display:block"';
  const MODEL_SVGS = {
    claude: '<svg ' + _svgStyle + ' viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" d="M4.709 15.955l4.72-2.647.08-.23-.08-.128H9.2l-.79-.048-2.698-.073-2.339-.097-2.266-.122-.571-.121L0 11.784l.055-.352.48-.321.686.06 1.52.103 2.278.158 1.652.097 2.449.255h.389l.055-.157-.134-.098-.103-.097-2.358-1.596-2.552-1.688-1.336-.972-.724-.491-.364-.462-.158-1.008.656-.722.881.06.225.061.893.686 1.908 1.476 2.491 1.833.365.304.145-.103.019-.073-.164-.274-1.355-2.446-1.446-2.49-.644-1.032-.17-.619a2.97 2.97 0 01-.104-.729L6.283.134 6.696 0l.996.134.42.364.62 1.414 1.002 2.229 1.555 3.03.456.898.243.832.091.255h.158V9.01l.128-1.706.237-2.095.23-2.695.08-.76.376-.91.747-.492.584.28.48.685-.067.444-.286 1.851-.559 2.903-.364 1.942h.212l.243-.242.985-1.306 1.652-2.064.73-.82.85-.904.547-.431h1.033l.76 1.129-.34 1.166-1.064 1.347-.881 1.142-1.264 1.7-.79 1.36.073.11.188-.02 2.856-.606 1.543-.28 1.841-.315.833.388.091.395-.328.807-1.969.486-2.309.462-3.439.813-.042.03.049.061 1.549.146.662.036h1.622l3.02.225.79.522.474.638-.079.485-1.215.62-1.64-.389-3.829-.91-1.312-.329h-.182v.11l1.093 1.068 2.006 1.81 2.509 2.33.127.578-.322.455-.34-.049-2.205-1.657-.851-.747-1.926-1.62h-.128v.17l.444.649 2.345 3.521.122 1.08-.17.353-.608.213-.668-.122-1.374-1.925-1.415-2.167-1.143-1.943-.14.08-.674 7.254-.316.37-.729.28-.607-.461-.322-.747.322-1.476.389-1.924.315-1.53.286-1.9.17-.632-.012-.042-.14.018-1.434 1.967-2.18 2.945-1.726 1.845-.414.164-.717-.37.067-.662.401-.589 2.388-3.036 1.44-1.882.93-1.086-.006-.158h-.055L4.132 18.56l-1.13.146-.487-.456.061-.746.231-.243 1.908-1.312-.006.006z"/></svg>',
    openai: '<svg ' + _svgStyle + ' viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" d="M9.205 8.658v-2.26c0-.19.072-.333.238-.428l4.543-2.616c.619-.357 1.356-.523 2.117-.523 2.854 0 4.662 2.212 4.662 4.566 0 .167 0 .357-.024.547l-4.71-2.759a.797.797 0 00-.856 0l-5.97 3.473zm10.609 8.8V12.06c0-.333-.143-.57-.429-.737l-5.97-3.473 1.95-1.118a.433.433 0 01.476 0l4.543 2.617c1.309.76 2.189 2.378 2.189 3.948 0 1.808-1.07 3.473-2.76 4.163zM7.802 12.703l-1.95-1.142c-.167-.095-.239-.238-.239-.428V5.899c0-2.545 1.95-4.472 4.591-4.472 1 0 1.927.333 2.712.928L8.23 5.067c-.285.166-.428.404-.428.737v6.898zM12 15.128l-2.795-1.57v-3.33L12 8.658l2.795 1.57v3.33L12 15.128zm1.796 7.23c-1 0-1.927-.332-2.712-.927l4.686-2.712c.285-.166.428-.404.428-.737v-6.898l1.974 1.142c.167.095.238.238.238.428v5.233c0 2.545-1.974 4.472-4.614 4.472zm-5.637-5.303l-4.544-2.617c-1.308-.761-2.188-2.378-2.188-3.948A4.482 4.482 0 014.21 6.327v5.423c0 .333.143.571.428.738l5.947 3.449-1.95 1.118a.432.432 0 01-.476 0zm-.262 3.9c-2.688 0-4.662-2.021-4.662-4.519 0-.19.024-.38.047-.57l4.686 2.71c.286.167.571.167.856 0l5.97-3.448v2.26c0 .19-.07.333-.237.428l-4.543 2.616c-.619.357-1.356.523-2.117.523zm5.899 2.83a5.947 5.947 0 005.827-4.756C22.287 18.339 24 15.84 24 13.296c0-1.665-.713-3.282-1.998-4.448.119-.5.19-.999.19-1.498 0-3.401-2.759-5.947-5.946-5.947-.642 0-1.26.095-1.88.31A5.962 5.962 0 0010.205 0a5.947 5.947 0 00-5.827 4.757C1.713 5.447 0 7.945 0 10.49c0 1.666.713 3.283 1.998 4.448-.119.5-.19 1-.19 1.499 0 3.401 2.759 5.946 5.946 5.946.642 0 1.26-.095 1.88-.309a5.96 5.96 0 004.162 1.713z"/></svg>',
    deepseek: '<svg ' + _svgStyle + ' viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" d="M23.748 4.482c-.254-.124-.364.113-.512.234-.051.039-.094.09-.137.136-.372.397-.806.657-1.373.626-.829-.046-1.537.214-2.163.848-.133-.782-.575-1.248-1.247-1.548-.352-.156-.708-.311-.955-.65-.172-.241-.219-.51-.305-.774-.055-.16-.11-.323-.293-.35-.2-.031-.278.136-.356.276-.313.572-.434 1.202-.422 1.84.027 1.436.633 2.58 1.838 3.393.137.093.172.187.129.323-.082.28-.18.552-.266.833-.055.179-.137.217-.329.14a5.526 5.526 0 01-1.736-1.18c-.857-.828-1.631-1.742-2.597-2.458a11.365 11.365 0 00-.689-.471c-.985-.957.13-1.743.388-1.836.27-.098.093-.432-.779-.428-.872.004-1.67.295-2.687.684a3.055 3.055 0 01-.465.137 9.597 9.597 0 00-2.883-.102c-1.885.21-3.39 1.102-4.497 2.623C.082 8.606-.231 10.684.152 12.85c.403 2.284 1.569 4.175 3.36 5.653 1.858 1.533 3.997 2.284 6.438 2.14 1.482-.085 3.133-.284 4.994-1.86.47.234.962.327 1.78.397.63.059 1.236-.03 1.705-.128.735-.156.684-.837.419-.961-2.155-1.004-1.682-.595-2.113-.926 1.096-1.296 2.746-2.642 3.392-7.003.05-.347.007-.565 0-.845-.004-.17.035-.237.23-.256a4.173 4.173 0 001.545-.475c1.396-.763 1.96-2.015 2.093-3.517.02-.23-.004-.467-.247-.588zM11.581 18c-2.089-1.642-3.102-2.183-3.52-2.16-.392.024-.321.471-.235.763.09.288.207.486.371.739.114.167.192.416-.113.603-.673.416-1.842-.14-1.897-.167-1.361-.802-2.5-1.86-3.301-3.307-.774-1.393-1.224-2.887-1.298-4.482-.02-.386.093-.522.477-.592a4.696 4.696 0 011.529-.039c2.132.312 3.946 1.265 5.468 2.774.868.86 1.525 1.887 2.202 2.891.72 1.066 1.494 2.082 2.48 2.914.348.292.625.514.891.677-.802.09-2.14.11-3.054-.614zm1-6.44a.306.306 0 01.415-.287.302.302 0 01.2.288.306.306 0 01-.31.307.303.303 0 01-.304-.308zm3.11 1.596c-.2.081-.399.151-.59.16a1.245 1.245 0 01-.798-.254c-.274-.23-.47-.358-.552-.758a1.73 1.73 0 01.016-.588c.07-.327-.008-.537-.239-.727-.187-.156-.426-.199-.688-.199a.559.559 0 01-.254-.078c-.11-.054-.2-.19-.114-.358.028-.054.16-.186.192-.21.356-.202.767-.136 1.146.016.352.144.618.408 1.001.782.391.451.462.576.685.914.176.265.336.537.445.848.067.195-.019.354-.25.452z"/></svg>',
    qwen: '<svg ' + _svgStyle + ' viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" d="M12.604 1.34c.393.69.784 1.382 1.174 2.075a.18.18 0 00.157.091h5.552c.174 0 .322.11.446.327l1.454 2.57c.19.337.24.478.024.837-.26.43-.513.864-.76 1.3l-.367.658c-.106.196-.223.28-.04.512l2.652 4.637c.172.301.111.494-.043.77-.437.785-.882 1.564-1.335 2.34-.159.272-.352.375-.68.37-.777-.016-1.552-.01-2.327.016a.099.099 0 00-.081.05 575.097 575.097 0 01-2.705 4.74c-.169.293-.38.363-.725.364-.997.003-2.002.004-3.017.002a.537.537 0 01-.465-.271l-1.335-2.323a.09.09 0 00-.083-.049H4.982c-.285.03-.553-.001-.805-.092l-1.603-2.77a.543.543 0 01-.002-.54l1.207-2.12a.198.198 0 000-.197 550.951 550.951 0 01-1.875-3.272l-.79-1.395c-.16-.31-.173-.496.095-.965.465-.813.927-1.625 1.387-2.436.132-.234.304-.334.584-.335a338.3 338.3 0 012.589-.001.124.124 0 00.107-.063l2.806-4.895a.488.488 0 01.422-.246c.524-.001 1.053 0 1.583-.006L11.704 1c.341-.003.724.032.9.34zm-3.432.403a.06.06 0 00-.052.03L6.254 6.788a.157.157 0 01-.135.078H3.253c-.056 0-.07.025-.041.074l5.81 10.156c.025.042.013.062-.034.063l-2.795.015a.218.218 0 00-.2.116l-1.32 2.31c-.044.078-.021.118.068.118l5.716.008c.046 0 .08.02.104.061l1.403 2.454c.046.081.092.082.139 0l5.006-8.76.783-1.382a.055.055 0 01.096 0l1.424 2.53a.122.122 0 00.107.062l2.763-.02a.04.04 0 00.035-.02.041.041 0 000-.04l-2.9-5.086a.108.108 0 010-.113l.293-.507 1.12-1.977c.024-.041.012-.062-.035-.062H9.2c-.059 0-.073-.026-.043-.077l1.434-2.505a.107.107 0 000-.114L9.225 1.774a.06.06 0 00-.053-.031zm6.29 8.02c.046 0 .058.02.034.06l-.832 1.465-2.613 4.585a.056.056 0 01-.05.029.058.058 0 01-.05-.029L8.498 9.841c-.02-.034-.01-.052.028-.054l.216-.012 6.722-.012z"/></svg>',
    mistral: '<svg ' + _svgStyle + ' viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path clip-rule="evenodd" fill="currentColor" d="M3.428 3.4h3.429v3.428h3.429v3.429h-.002 3.431V6.828h3.427V3.4h3.43v13.714H24v3.429H13.714v-3.428h-3.428v-3.429h-3.43v3.428h3.43v3.429H0v-3.429h3.428V3.4zm10.286 13.715h3.428v-3.429h-3.427v3.429z"/></svg>',
    gemini: '<svg ' + _svgStyle + ' viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" d="M20.616 10.835a14.147 14.147 0 01-4.45-3.001 14.111 14.111 0 01-3.678-6.452.503.503 0 00-.975 0 14.134 14.134 0 01-3.679 6.452 14.155 14.155 0 01-4.45 3.001c-.65.28-1.318.505-2.002.678a.502.502 0 000 .975c.684.172 1.35.397 2.002.677a14.147 14.147 0 014.45 3.001 14.112 14.112 0 013.679 6.453.502.502 0 00.975 0c.172-.685.397-1.351.677-2.003a14.145 14.145 0 013.001-4.45 14.113 14.113 0 016.453-3.678.503.503 0 000-.975 13.245 13.245 0 01-2.003-.678z"/></svg>',
    meta: '<svg ' + _svgStyle + ' viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" d="M6.897 4c1.915 0 3.516.932 5.43 3.376l.282-.373c.19-.246.383-.484.58-.71l.313-.35C14.588 4.788 15.792 4 17.225 4c1.273 0 2.469.557 3.491 1.516l.218.213c1.73 1.765 2.917 4.71 3.053 8.026l.011.392.002.25c0 1.501-.28 2.759-.818 3.7l-.14.23-.108.153c-.301.42-.664.758-1.086 1.009l-.265.142-.087.04a3.493 3.493 0 01-.302.118 4.117 4.117 0 01-1.33.208c-.524 0-.996-.067-1.438-.215-.614-.204-1.163-.56-1.726-1.116l-.227-.235c-.753-.812-1.534-1.976-2.493-3.586l-1.43-2.41-.544-.895-1.766 3.13-.343.592C7.597 19.156 6.227 20 4.356 20c-1.21 0-2.205-.42-2.936-1.182l-.168-.184c-.484-.573-.837-1.311-1.043-2.189l-.067-.32a8.69 8.69 0 01-.136-1.288L0 14.468c.002-.745.06-1.49.174-2.23l.1-.573c.298-1.53.828-2.958 1.536-4.157l.209-.34c1.177-1.83 2.789-3.053 4.615-3.16L6.897 4zm-.033 2.615l-.201.01c-.83.083-1.606.673-2.252 1.577l-.138.199-.01.018c-.67 1.017-1.185 2.378-1.456 3.845l-.004.022a12.591 12.591 0 00-.207 2.254l.002.188c.004.18.017.36.04.54l.043.291c.092.503.257.908.486 1.208l.117.137c.303.323.698.492 1.17.492 1.1 0 1.796-.676 3.696-3.641l2.175-3.4.454-.701-.139-.198C9.11 7.3 8.084 6.616 6.864 6.616zm10.196-.552l-.176.007c-.635.048-1.223.359-1.82.933l-.196.198c-.439.462-.887 1.064-1.367 1.807l.266.398c.18.274.362.56.55.858l.293.475 1.396 2.335.695 1.114c.583.926 1.03 1.6 1.408 2.082l.213.262c.282.326.529.54.777.673l.102.05c.227.1.457.138.718.138.176.002.35-.023.518-.073.338-.104.61-.32.813-.637l.095-.163.077-.162c.194-.459.29-1.06.29-1.785l-.006-.449c-.08-2.871-.938-5.372-2.2-6.798l-.176-.189c-.67-.683-1.444-1.074-2.27-1.074z"/></svg>',
    zhipu: '<svg ' + _svgStyle + ' viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" d="M11.991 23.503a.24.24 0 00-.244.248.24.24 0 00.244.249.24.24 0 00.245-.249.24.24 0 00-.22-.247l-.025-.001zM9.671 5.365a1.697 1.697 0 011.099 2.132l-.071.172-.016.04-.018.054c-.07.16-.104.32-.104.498-.035.71.47 1.279 1.186 1.314h.366c1.309.053 2.338 1.173 2.286 2.523-.052 1.332-1.152 2.38-2.478 2.327h-.174c-.715.018-1.274.64-1.239 1.368 0 .124.018.23.053.337.209.373.54.658.96.8.75.23 1.517-.125 1.9-.782l.018-.035c.402-.64 1.17-.96 1.92-.711.854.284 1.378 1.226 1.099 2.167a1.661 1.661 0 01-2.077 1.102 1.711 1.711 0 01-.907-.711l-.017-.035c-.2-.323-.463-.58-.851-.711l-.056-.018a1.646 1.646 0 00-1.954.746 1.66 1.66 0 01-1.065.764 1.677 1.677 0 01-1.989-1.279c-.209-.906.332-1.83 1.257-2.043a1.51 1.51 0 01.296-.035h.018c.68-.071 1.151-.622 1.116-1.333a1.307 1.307 0 00-.227-.693 2.515 2.515 0 01-.366-1.403 2.39 2.39 0 01.366-1.208c.14-.195.21-.444.227-.693.018-.71-.506-1.261-1.186-1.332l-.07-.018a1.43 1.43 0 01-.299-.07l-.05-.019a1.7 1.7 0 01-1.047-2.114 1.68 1.68 0 012.094-1.101zm-5.575 10.11c.26-.264.639-.367.994-.27.355.096.633.379.728.74.095.362-.007.748-.267 1.013-.402.41-1.053.41-1.455 0a1.062 1.062 0 010-1.482zm14.845-.294c.359-.09.738.024.992.297.254.274.344.665.237 1.025-.107.36-.396.634-.756.718-.551.128-1.1-.22-1.23-.781a1.05 1.05 0 01.757-1.26zm-.064-4.39c.314.32.49.753.49 1.206 0 .452-.176.886-.49 1.206-.315.32-.74.5-1.185.5-.444 0-.87-.18-1.184-.5a1.727 1.727 0 010-2.412 1.654 1.654 0 012.369 0zm-11.243.163c.364.484.447 1.128.218 1.691a1.665 1.665 0 01-2.188.923c-.855-.36-1.26-1.358-.907-2.228a1.68 1.68 0 011.33-1.038c.593-.08 1.183.169 1.547.652zm11.545-4.221c.368 0 .708.2.892.524.184.324.184.724 0 1.048a1.026 1.026 0 01-.892.524c-.568 0-1.03-.47-1.03-1.048 0-.579.462-1.048 1.03-1.048zm-14.358 0c.368 0 .707.2.891.524.184.324.184.724 0 1.048a1.026 1.026 0 01-.891.524c-.569 0-1.03-.47-1.03-1.048 0-.579.461-1.048 1.03-1.048zm10.031-1.475c.925 0 1.675.764 1.675 1.706s-.75 1.705-1.675 1.705-1.674-.763-1.674-1.705c0-.942.75-1.706 1.674-1.706zm-2.626-.684c.362-.082.653-.356.761-.718a1.062 1.062 0 00-.238-1.028 1.017 1.017 0 00-.996-.294c-.547.14-.881.7-.752 1.257.13.558.675.907 1.225.783zm0 16.876c.359-.087.644-.36.75-.72a1.062 1.062 0 00-.237-1.019 1.018 1.018 0 00-.985-.301 1.037 1.037 0 00-.762.717c-.108.361-.017.754.239 1.028.245.263.606.377.953.305l.043-.01zM17.19 3.5a.631.631 0 00.628-.64c0-.355-.279-.64-.628-.64a.631.631 0 00-.628.64c0 .355.28.64.628.64zm-10.38 0a.631.631 0 00.628-.64c0-.355-.28-.64-.628-.64a.631.631 0 00-.628.64c0 .355.279.64.628.64zm-5.182 7.852a.631.631 0 00-.628.64c0 .354.28.639.628.639a.63.63 0 00.627-.606l.001-.034a.62.62 0 00-.628-.64zm5.182 9.13a.631.631 0 00-.628.64c0 .355.279.64.628.64a.631.631 0 00.628-.64c0-.355-.28-.64-.628-.64zm10.38.018a.631.631 0 00-.628.64c0 .355.28.64.628.64a.631.631 0 00.628-.64c0-.355-.279-.64-.628-.64zm5.182-9.148a.631.631 0 00-.628.64c0 .354.279.639.628.639a.631.631 0 00.628-.64c0-.355-.28-.64-.628-.64zm-.384-4.992a.24.24 0 00.244-.249.24.24 0 00-.244-.249.24.24 0 00-.244.249c0 .142.122.249.244.249zM11.991.497a.24.24 0 00.245-.248A.24.24 0 0011.99 0a.24.24 0 00-.244.249c0 .133.108.236.223.247l.021.001zM2.011 6.36a.24.24 0 00.245-.249.24.24 0 00-.244-.249.24.24 0 00-.244.249.24.24 0 00.244.249zm0 11.263a.24.24 0 00-.243.248.24.24 0 00.244.249.24.24 0 00.244-.249.252.252 0 00-.244-.248zm19.995-.018a.24.24 0 00-.245.248.24.24 0 00.245.25.24.24 0 00.244-.25.252.252 0 00-.244-.248z"/></svg>',
    minimax: '<svg ' + _svgStyle + ' viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" d="M16.278 2c1.156 0 2.093.927 2.093 2.07v12.501a.74.74 0 00.744.709.74.74 0 00.743-.709V9.099a2.06 2.06 0 012.071-2.049A2.06 2.06 0 0124 9.1v6.561a.649.649 0 01-.652.645.649.649 0 01-.653-.645V9.1a.762.762 0 00-.766-.758.762.762 0 00-.766.758v7.472a2.037 2.037 0 01-2.048 2.026 2.037 2.037 0 01-2.048-2.026v-12.5a.785.785 0 00-.788-.753.785.785 0 00-.789.752l-.001 15.904A2.037 2.037 0 0113.441 22a2.037 2.037 0 01-2.048-2.026V18.04c0-.356.292-.645.652-.645.36 0 .652.289.652.645v1.934c0 .263.142.506.372.638.23.131.514.131.744 0a.734.734 0 00.372-.638V4.07c0-1.143.937-2.07 2.093-2.07zm-5.674 0c1.156 0 2.093.927 2.093 2.07v11.523a.648.648 0 01-.652.645.648.648 0 01-.652-.645V4.07a.785.785 0 00-.789-.78.785.785 0 00-.789.78v14.013a2.06 2.06 0 01-2.07 2.048 2.06 2.06 0 01-2.071-2.048V9.1a.762.762 0 00-.766-.758.762.762 0 00-.766.758v3.8a2.06 2.06 0 01-2.071 2.049A2.06 2.06 0 010 12.9v-1.378c0-.357.292-.646.652-.646.36 0 .653.29.653.646V12.9c0 .418.343.757.766.757s.766-.339.766-.757V9.099a2.06 2.06 0 012.07-2.048 2.06 2.06 0 012.071 2.048v8.984c0 .419.343.758.767.758.423 0 .766-.339.766-.758V4.07c0-1.143.937-2.07 2.093-2.07z"/></svg>',
    proxy: '<svg ' + _svgStyle + ' viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>'
  };

  function getModelFamily(id) {
    const lower = id.toLowerCase();
    if (lower.startsWith('claude-') || lower.startsWith('anthropic')) return 'claude';
    if (lower.startsWith('gpt-') || lower === 'o1' || lower.startsWith('o1-') || lower.startsWith('o3-') || lower.startsWith('o4-')) return 'openai';
    if (lower.startsWith('deepseek')) return 'deepseek';
    if (lower.startsWith('qwen') || lower.startsWith('qwq') || lower.startsWith('qvq')) return 'qwen';
    if (lower.startsWith('glm') || lower.startsWith('chatglm') || lower.startsWith('zhipu') || lower.startsWith('codegeex')) return 'zhipu';
    if (lower.startsWith('minimax') || lower.startsWith('abab')) return 'minimax';
    if (lower.startsWith('mistral') || lower.startsWith('mixtral') || lower.startsWith('codestral')) return 'mistral';
    if (lower.startsWith('gemini') || lower.startsWith('gemma')) return 'gemini';
    if (lower.startsWith('llama') || lower.startsWith('meta-') || lower.startsWith('codellama')) return 'meta';
    if (lower === 'auto' || lower.startsWith('auto')) return 'proxy';
    return 'other';
  }

  function getModelFamilyLabel(family) {
    const labels = {
      claude: 'Claude (Anthropic)',
      openai: 'OpenAI',
      deepseek: 'DeepSeek',
      qwen: 'Qwen (Alibaba)',
      zhipu: 'GLM (Zhipu)',
      minimax: 'MiniMax',
      mistral: 'Mistral AI',
      gemini: 'Gemini (Google)',
      meta: 'LLaMA (Meta)',
      proxy: 'Proxy Aliases',
      other: currentLang === 'zh' ? '其他模型' : 'Other'
    };
    return labels[family] || family;
  }

  function getModelFamilyColor(family) {
    const colors = {
      claude: '#d97757',
      openai: '#10a37f',
      deepseek: '#4d6bfe',
      qwen: '#615ced',
      zhipu: '#3859ff',
      minimax: '#e1474f',
      mistral: '#ff7000',
      gemini: '#4285f4',
      meta: '#0668e1',
      proxy: '#888888',
      other: '#6b7280'
    };
    return colors[family] || '#6b7280';
  }

  function buildModelsGroupedHtml(models, thinkingSuffix) {
    if (models.length === 0) {
      return '<div class="api-view-loading">' + escapeHtml(t('api.noModels')) + '</div>';
    }

    // Group models by family
    const groups = {};
    const familyOrder = ['claude', 'openai', 'deepseek', 'qwen', 'zhipu', 'minimax', 'mistral', 'gemini', 'meta', 'proxy', 'other'];
    for (const m of models) {
      const family = getModelFamily(m.id || '');
      if (!groups[family]) groups[family] = [];
      groups[family].push(m);
    }

    let html = '';
    for (const family of familyOrder) {
      if (!groups[family] || groups[family].length === 0) continue;
      const familyModels = groups[family];
      const color = getModelFamilyColor(family);
      const svg = MODEL_SVGS[family] || MODEL_SVGS.proxy;
      const label = getModelFamilyLabel(family);

      html += '<div class="model-group">';
      html += '<div class="model-group-header">';
      html += '<span class="model-group-icon" style="color:' + color + '">' + svg + '</span>';
      html += '<span class="model-group-title">' + escapeHtml(label) + '</span>';
      html += '<span class="model-group-count">' + familyModels.length + '</span>';
      html += '</div>';
      html += '<div class="model-group-grid">';

      for (const m of familyModels) {
        const id = m.id || '';
        const isThinking = id.endsWith(thinkingSuffix);
        const supportsImage = m.supports_image || false;

        html += '<div class="model-item">';
        html += '<div class="model-info">';
        html += '<div class="model-name">' + escapeHtml(id) + '</div>';
        html += '<div class="model-badges">';
        if (isThinking) html += '<span class="model-badge model-badge--thinking"><i class="fa-solid fa-brain"></i> thinking</span>';
        if (supportsImage) html += '<span class="model-badge model-badge--image"><i class="fa-solid fa-image"></i> vision</span>';
        html += '</div>';
        html += '</div>';
        html += '</div>';
      }

      html += '</div></div>';
    }
    return html;
  }

  async function showStatsView() {
    const title = $('apiViewTitle');
    const body = $('apiViewBody');
    title.textContent = t('api.viewStatsTitle');
    body.innerHTML = '<div class="api-view-loading"><i class="fa-solid fa-spinner fa-spin"></i> ' + escapeHtml(t('api.loading')) + '</div>';
    openDialog('apiViewModal');

    try {
      const res = await api('/status');
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const d = await res.json();
      renderStatsView(body, d);
    } catch (e) {
      body.innerHTML = '<div class="api-view-error"><i class="fa-solid fa-circle-exclamation"></i> ' + escapeHtml(t('api.fetchError') + ': ' + e.message) + '</div>';
    }
  }

  function renderStatsView(container, d) {
    const version = String(d.version || currentVersion || '-').replace(/^v/i, '');
    let html = '<div class="stats-view-grid">';
    html += statsCard(t('api.statsVersion'), version, '');
    html += statsCard(t('api.statsAccounts'), d.accounts || 0, '');
    html += statsCard(t('api.statsAvailable'), d.available || 0, 'success');
    html += statsCard(t('api.statsTotalReqs'), formatNum(d.totalRequests || 0), 'info');
    html += statsCard(t('api.statsSuccessReqs'), formatNum(d.successRequests || 0), 'success');
    html += statsCard(t('api.statsFailedReqs'), formatNum(d.failedRequests || 0), 'danger');
    html += statsCard(t('api.statsTotalTokens'), formatNum(d.totalTokens || 0), '');
    html += statsCard(t('api.statsTotalCredits'), (d.totalCredits || 0).toFixed(2), 'info');
    html += '</div>';
    if (d.uptime !== undefined) {
      html += '<div class="stats-view-uptime"><i class="fa-solid fa-clock"></i> ' + escapeHtml(t('api.statsUptime')) + ': <strong>' + escapeHtml(formatUptime(d.uptime)) + '</strong></div>';
    }
    container.innerHTML = html;
  }

  function statsCard(label, value, variant) {
    const cls = variant ? ' stats-view-item--' + variant : '';
    return '<div class="stats-view-item' + cls + '"><div class="stats-view-value">' + escapeHtml(String(value)) + '</div><div class="stats-view-label">' + escapeHtml(label) + '</div></div>';
  }

  function wireEvents() {
    bindLoginEvents();
    bindShellEvents();
    bindAccountEvents();
    bindSettingsEvents();
    bindPromptFilterEvents();
    bindModalEvents();
    bindDetailEvents();
    bindTestEvents();
  }

  // Init
  async function init() {
    initTheme();
    await loadLocale(currentLang);
    if (currentLang !== 'zh') await loadLocale('zh');
    applyTranslations();
    initCustomSelectObserver();
    initPrivacyMode();
    initRememberMe();
    const yr = $('footerYear');
    if (yr) yr.textContent = new Date().getFullYear();
    wireEvents();
    if (password) tryAutoLogin();
    setInterval(() => {
      if (!$('mainPage').classList.contains('hidden')) loadStats();
    }, 10000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
