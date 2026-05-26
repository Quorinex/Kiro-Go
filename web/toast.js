/*
 * Toast notification module.
 * Public API: window.toast(message, variant, opts), variant helpers, dismissAll().
 */
(function (global) {
  'use strict';

  if (global.__kt_loaded__) return;
  global.__kt_loaded__ = true;

  var MAX_STACK = 5;
  var DEFAULT_DURATION = 4000;
  var MIN_DURATION = 2000;
  var ENTER_DELAY_MS = 20;
  var EXIT_DURATION_MS = 240;

  var ROOT_ID = 'kt-root';
  var SVG_NS = 'http://www.w3.org/2000/svg';

  function svgEl(name, attrs) {
    var el = document.createElementNS(SVG_NS, name);
    if (attrs) for (var k in attrs) if (Object.prototype.hasOwnProperty.call(attrs, k)) el.setAttribute(k, attrs[k]);
    return el;
  }

  function baseSvg() {
    return svgEl('svg', {
      viewBox: '0 0 24 24',
      width: '18',
      height: '18',
      fill: 'none',
      stroke: 'currentColor',
      'stroke-width': '2.4',
      'stroke-linecap': 'round',
      'stroke-linejoin': 'round',
      'aria-hidden': 'true'
    });
  }

  function svgInfo() {
    var s = baseSvg();
    s.appendChild(svgEl('circle', { cx: '12', cy: '12', r: '10' }));
    s.appendChild(svgEl('path', { d: 'M12 16v-4' }));
    s.appendChild(svgEl('path', { d: 'M12 8h.01' }));
    return s;
  }
  function svgSuccess() {
    var s = baseSvg();
    s.appendChild(svgEl('circle', { cx: '12', cy: '12', r: '10' }));
    s.appendChild(svgEl('path', { d: 'm9 12 2 2 4-4' }));
    return s;
  }
  function svgError() {
    var s = baseSvg();
    s.appendChild(svgEl('circle', { cx: '12', cy: '12', r: '10' }));
    s.appendChild(svgEl('path', { d: 'M12 8v4' }));
    s.appendChild(svgEl('path', { d: 'M12 16h.01' }));
    return s;
  }
  function svgWarning() {
    var s = baseSvg();
    s.appendChild(svgEl('path', { d: 'M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z' }));
    s.appendChild(svgEl('path', { d: 'M12 9v4' }));
    s.appendChild(svgEl('path', { d: 'M12 17h.01' }));
    return s;
  }

  var SVG_BUILDERS = {
    success: svgSuccess,
    error: svgError,
    warning: svgWarning,
    info: svgInfo,
    danger: svgError,
    primary: svgInfo,
    secondary: svgInfo,
    ghost: svgInfo
  };

  var FA = {
    success: 'fa-solid fa-circle-check',
    error: 'fa-solid fa-circle-exclamation',
    warning: 'fa-solid fa-triangle-exclamation',
    info: 'fa-solid fa-circle-info',
    danger: 'fa-solid fa-trash',
    primary: 'fa-solid fa-circle-info',
    secondary: 'fa-solid fa-circle-info',
    ghost: 'fa-solid fa-circle-info'
  };

  var VARIANTS = ['success', 'error', 'warning', 'info', 'danger', 'primary', 'secondary', 'ghost'];

  function ensureRoot() {
    var root = document.getElementById(ROOT_ID);
    if (root && root.parentNode === document.body) return root;
    if (root && root.parentNode) root.parentNode.removeChild(root);
    root = document.createElement('div');
    root.id = ROOT_ID;
    root.className = 'kt-root';
    root.setAttribute('role', 'region');
    root.setAttribute('aria-label', 'Notifications');
    document.body.appendChild(root);
    return root;
  }

  var _faCheckDone = false;
  var _faAvailable = false;
  function faAvailable() {
    if (_faCheckDone) return _faAvailable;
    _faCheckDone = true;
    try {
      var probe = document.createElement('i');
      probe.className = 'fa-solid fa-check';
      probe.style.position = 'absolute';
      probe.style.left = '-9999px';
      probe.style.fontSize = '14px';
      document.body.appendChild(probe);
      var cs = window.getComputedStyle(probe);
      var family = (cs.fontFamily || '').toLowerCase();
      _faAvailable = family.indexOf('font awesome') !== -1 || family.indexOf('fontawesome') !== -1;
      document.body.removeChild(probe);
    } catch (_) {
      _faAvailable = false;
    }
    return _faAvailable;
  }

  function buildIcon(variant, customFa) {
    if (customFa) {
      var el = document.createElement('i');
      el.className = customFa + ' kt-icon';
      el.setAttribute('aria-hidden', 'true');
      return el;
    }
    if (faAvailable()) {
      var i = document.createElement('i');
      i.className = (FA[variant] || FA.info) + ' kt-icon';
      i.setAttribute('aria-hidden', 'true');
      return i;
    }
    var wrap = document.createElement('span');
    wrap.className = 'kt-icon';
    wrap.setAttribute('aria-hidden', 'true');
    var builder = SVG_BUILDERS[variant] || svgInfo;
    wrap.appendChild(builder());
    return wrap;
  }

  function dismiss(node) {
    if (!node || node.__kt_closing) return;
    node.__kt_closing = true;
    if (node.__kt_timer) {
      clearTimeout(node.__kt_timer);
      node.__kt_timer = null;
    }
    node.classList.remove('kt-in');
    node.classList.add('kt-out');
    setTimeout(function () {
      if (node.parentNode) node.parentNode.removeChild(node);
    }, EXIT_DURATION_MS);
  }

  function dismissAll() {
    var root = document.getElementById(ROOT_ID);
    if (!root) return;
    var nodes = Array.prototype.slice.call(root.children);
    for (var i = 0; i < nodes.length; i++) dismiss(nodes[i]);
  }

  function trimStack(root) {
    var live = [];
    for (var i = 0; i < root.children.length; i++) {
      var c = root.children[i];
      if (!c.__kt_closing) live.push(c);
    }
    while (live.length >= MAX_STACK) {
      var oldest = live.shift();
      dismiss(oldest);
    }
  }

  function show(message, variant, opts) {
    if (typeof document === 'undefined') return function () {};
    variant = VARIANTS.indexOf(variant) !== -1 ? variant : 'info';
    opts = opts || {};

    var raw = opts.duration != null ? Number(opts.duration) : DEFAULT_DURATION;
    var sticky = !(raw > 0);
    var duration = sticky ? 0 : Math.max(raw, MIN_DURATION);

    var root = ensureRoot();
    trimStack(root);

    var node = document.createElement('div');
    node.className = 'kt-toast kt-' + variant;
    node.setAttribute('role', variant === 'error' || variant === 'danger' ? 'alert' : 'status');
    node.setAttribute('aria-live', variant === 'error' || variant === 'danger' ? 'assertive' : 'polite');

    node.appendChild(buildIcon(variant, opts.icon));

    var msg = document.createElement('span');
    msg.className = 'kt-msg';
    msg.textContent = message == null ? '' : String(message);
    node.appendChild(msg);

    var close = function () { dismiss(node); };

    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'kt-close';
    btn.setAttribute('aria-label', 'Dismiss');
    btn.textContent = '×';
    node.appendChild(btn);

    btn.addEventListener('click', close);

    root.appendChild(node);

    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        node.classList.add('kt-in');
      });
    });

    setTimeout(function () {
      if (!node.__kt_closing) node.classList.add('kt-in');
    }, ENTER_DELAY_MS + 60);

    if (!sticky) {
      node.__kt_timer = setTimeout(close, duration);
      node.addEventListener('mouseenter', function () {
        if (node.__kt_timer) {
          clearTimeout(node.__kt_timer);
          node.__kt_timer = null;
        }
      });
      node.addEventListener('mouseleave', function () {
        if (node.__kt_closing || node.__kt_timer) return;
        node.__kt_timer = setTimeout(close, 1500);
      });
    }

    return close;
  }

  function toast(message, variant, opts) {
    return show(message, variant, opts);
  }
  for (var i = 0; i < VARIANTS.length; i++) {
    (function (v) {
      toast[v] = function (message, opts) { return show(message, v, opts); };
    })(VARIANTS[i]);
  }
  toast.dismissAll = dismissAll;
  toast.show = show;

  global.toast = toast;
})(window);
