/**
 * Modus Design System — JavaScript Component Library v2.0
 *
 * API surface:
 *   Modus.toast.success(msg, opts)   Modus.toast.error(msg, opts)
 *   Modus.toast.warning(msg, opts)   Modus.toast.info(msg, opts)
 *   Modus.modal.open(id)             Modus.modal.close(id)
 *   Modus.modal.confirm(opts) → Promise<boolean>
 *   Modus.tabs.init(container)
 *   Modus.dropdown.init()
 *   Modus.form.validate(formEl) → boolean
 *   Modus.skeleton.show(container)   Modus.skeleton.hide(container)
 *   Modus.table.init(tableEl, opts)
 *   Modus.theme.set(theme)           Modus.theme.toggle()
 *   Modus.btn.load(btnEl)            Modus.btn.done(btnEl)
 *   Modus.tag.init(containerEl)
 *   Modus.drawer.open(id)            Modus.drawer.close(id)
 *
 * Auto-init on DOMContentLoaded:
 *   - Tabs (.tabs containers)
 *   - Dropdowns (.dropdown)
 *   - Modals (data-modal-open, data-modal-close, data-modal-confirm)
 *   - Drawers (data-drawer-open, data-drawer-close)
 *   - Tag inputs (.tag-input-wrap)
 *   - Sortable tables (.table[data-sort-table])
 *   - Alerts with close buttons
 *   - Character counters (data-maxlength)
 */

(function (global) {
  'use strict';

  /* ────────────────────────────────────────────────────────────────────
     INTERNAL HELPERS
  ──────────────────────────────────────────────────────────────────── */

  function qs(sel, ctx) { return (ctx || document).querySelector(sel); }
  function qsa(sel, ctx) { return Array.from((ctx || document).querySelectorAll(sel)); }

  function esc(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /* Focus trap — keeps keyboard focus inside a container */
  function trapFocus(el) {
    const focusable = 'button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
    const nodes = () => Array.from(el.querySelectorAll(focusable)).filter(n => !n.closest('[hidden]'));
    function handler(e) {
      if (e.key !== 'Tab') return;
      const list = nodes();
      if (!list.length) return e.preventDefault();
      const first = list[0], last = list[list.length - 1];
      if (e.shiftKey ? document.activeElement === first : document.activeElement === last) {
        e.preventDefault();
        (e.shiftKey ? last : first).focus();
      }
    }
    el.addEventListener('keydown', handler);
    const firstFocusable = nodes()[0];
    if (firstFocusable) firstFocusable.focus();
    return () => el.removeEventListener('keydown', handler);
  }

  /* ────────────────────────────────────────────────────────────────────
     TOAST
  ──────────────────────────────────────────────────────────────────── */

  const toastIcons = {
    success: '✓',
    error:   '✕',
    warning: '⚠',
    info:    'ℹ',
  };

  function ensureToastRegion() {
    let region = document.getElementById('mds-toast-region');
    if (!region) {
      region = document.createElement('div');
      region.id = 'mds-toast-region';
      region.setAttribute('aria-live', 'polite');
      region.setAttribute('aria-atomic', 'false');
      document.body.appendChild(region);
    }
    return region;
  }

  /**
   * opts: { title, message, duration=4000, action: { label, fn }, persistent }
   */
  function showToast(type, msgOrOpts, opts) {
    const options = typeof msgOrOpts === 'string'
      ? Object.assign({ message: msgOrOpts }, opts)
      : msgOrOpts;

    const {
      title,
      message,
      duration = 4000,
      action,
      persistent = false,
    } = options;

    const region = ensureToastRegion();
    const toast  = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.setAttribute('role', 'alert');

    const displayTitle   = title   || (type.charAt(0).toUpperCase() + type.slice(1));
    const displayMessage = message || '';
    const actionHtml     = action
      ? `<button class="toast-action" type="button">${esc(action.label)}</button>`
      : '';
    const progressHtml   = !persistent
      ? `<div class="toast-progress" style="animation-duration:${duration}ms"></div>`
      : '';

    toast.innerHTML = `
      <span class="toast-icon">${toastIcons[type] || 'ℹ'}</span>
      <div class="toast-body">
        <div class="toast-title">${esc(displayTitle)}</div>
        ${displayMessage ? `<div class="toast-msg">${esc(displayMessage)}</div>` : ''}
        ${actionHtml}
      </div>
      <button class="toast-close" type="button" aria-label="Dismiss">✕</button>
      ${progressHtml}
    `;

    region.appendChild(toast);

    const dismiss = () => {
      if (!toast.parentNode) return;
      toast.classList.add('toast-leaving');
      toast.addEventListener('animationend', () => toast.remove(), { once: true });
    };

    qs('.toast-close', toast).addEventListener('click', dismiss);

    if (action && action.fn) {
      qs('.toast-action', toast).addEventListener('click', () => {
        action.fn();
        dismiss();
      });
    }

    if (!persistent) {
      const timer = setTimeout(dismiss, duration);
      toast.addEventListener('mouseenter', () => clearTimeout(timer));
      toast.addEventListener('mouseleave', () => setTimeout(dismiss, 800));
    }

    return { dismiss };
  }

  const toast = {
    success: (m, o) => showToast('success', m, o),
    error:   (m, o) => showToast('error',   m, o),
    warning: (m, o) => showToast('warning', m, o),
    info:    (m, o) => showToast('info',    m, o),
  };

  /* ────────────────────────────────────────────────────────────────────
     MODAL
  ──────────────────────────────────────────────────────────────────── */

  const modalStack  = [];
  let   removeTrap  = null;

  function openModal(idOrEl) {
    const el = typeof idOrEl === 'string' ? document.getElementById(idOrEl) : idOrEl;
    if (!el) return;

    el.classList.add('open');
    el.removeAttribute('hidden');
    el.setAttribute('aria-modal', 'true');
    el.setAttribute('role', 'dialog');
    document.body.style.overflow = 'hidden';

    modalStack.push({ el, prevFocus: document.activeElement });
    if (removeTrap) removeTrap();
    removeTrap = trapFocus(el);

    el.addEventListener('click', overlayClickClose);
    document.addEventListener('keydown', escClose);
  }

  function closeModal(idOrEl) {
    const el = typeof idOrEl === 'string' ? document.getElementById(idOrEl) : idOrEl;
    if (!el) return;

    el.classList.remove('open');
    el.setAttribute('hidden', '');
    el.removeEventListener('click', overlayClickClose);

    const entry = modalStack.pop();
    if (entry && entry.prevFocus) entry.prevFocus.focus();

    if (!modalStack.length) {
      document.body.style.overflow = '';
      document.removeEventListener('keydown', escClose);
      if (removeTrap) { removeTrap(); removeTrap = null; }
    } else {
      if (removeTrap) removeTrap();
      removeTrap = trapFocus(modalStack[modalStack.length - 1].el);
    }
  }

  function overlayClickClose(e) {
    if (e.target === e.currentTarget) closeModal(e.currentTarget);
  }

  function escClose(e) {
    if (e.key === 'Escape' && modalStack.length) closeModal(modalStack[modalStack.length - 1].el);
  }

  /**
   * Programmatic confirm dialog.
   * opts: { title, message, confirmLabel='Confirm', cancelLabel='Cancel', danger=false }
   * Returns Promise<boolean>
   */
  function confirmDialog(opts = {}) {
    const {
      title        = 'Are you sure?',
      message      = '',
      confirmLabel = 'Confirm',
      cancelLabel  = 'Cancel',
      danger       = false,
    } = opts;

    return new Promise(resolve => {
      const id = `mds-confirm-${Date.now()}`;
      const overlay = document.createElement('div');
      overlay.id = id;
      overlay.className = 'modal-overlay';
      overlay.style.display = 'flex';
      overlay.innerHTML = `
        <div class="modal modal-sm" role="alertdialog" aria-modal="true" aria-labelledby="${id}-title">
          <div class="modal-header">
            <span class="modal-title" id="${id}-title">${esc(title)}</span>
          </div>
          ${message ? `<div class="modal-body"><p style="margin:0;font-size:13px;color:var(--text-2);line-height:1.5">${esc(message)}</p></div>` : ''}
          <div class="modal-footer">
            <button class="btn btn-outline" data-action="cancel">${esc(cancelLabel)}</button>
            <button class="btn ${danger ? 'btn-danger' : 'btn-primary'}" data-action="confirm">${esc(confirmLabel)}</button>
          </div>
        </div>
      `;
      document.body.appendChild(overlay);
      document.body.style.overflow = 'hidden';

      const cleanup = (result) => {
        document.body.style.overflow = '';
        overlay.remove();
        resolve(result);
      };

      overlay.addEventListener('click', e => {
        const action = e.target.closest('[data-action]');
        if (action) cleanup(action.dataset.action === 'confirm');
        else if (e.target === overlay) cleanup(false);
      });

      const trap = trapFocus(overlay);
      const keydown = e => {
        if (e.key === 'Escape') { trap(); document.removeEventListener('keydown', keydown); cleanup(false); }
      };
      document.addEventListener('keydown', keydown);
      overlay.addEventListener('click', () => { trap(); document.removeEventListener('keydown', keydown); }, { once: true });
    });
  }

  const modal = {
    open:    openModal,
    close:   closeModal,
    confirm: confirmDialog,
  };

  /* ────────────────────────────────────────────────────────────────────
     DRAWER
  ──────────────────────────────────────────────────────────────────── */

  function openDrawer(id) {
    const overlay = document.getElementById(id);
    if (!overlay) return;
    overlay.classList.add('open');
    document.body.style.overflow = 'hidden';
    overlay.addEventListener('click', e => { if (e.target === overlay) closeDrawer(id); }, { once: true });
    document.addEventListener('keydown', function escDrawer(e) {
      if (e.key === 'Escape') { closeDrawer(id); document.removeEventListener('keydown', escDrawer); }
    });
    const drawer = overlay.querySelector('.drawer');
    if (drawer) trapFocus(drawer);
  }

  function closeDrawer(id) {
    const overlay = document.getElementById(id);
    if (!overlay) return;
    overlay.classList.remove('open');
    document.body.style.overflow = '';
  }

  const drawer = { open: openDrawer, close: closeDrawer };

  /* ────────────────────────────────────────────────────────────────────
     TABS
  ──────────────────────────────────────────────────────────────────── */

  function initTabs(container) {
    const tabs   = qsa('.tab', container);
    const panels = qsa('.tab-panel', container.closest('[data-tabs-root]') || container.parentElement || document);

    function activate(tab) {
      const target = tab.dataset.tab || tab.getAttribute('href')?.replace('#', '');
      tabs.forEach(t => {
        t.classList.toggle('active', t === tab);
        t.setAttribute('aria-selected', t === tab ? 'true' : 'false');
      });
      panels.forEach(p => {
        const isTarget = p.id === target || p.dataset.panel === target;
        p.classList.toggle('active', isTarget);
        p.hidden = !isTarget;
      });
      // Persist to sessionStorage if tab has an id
      if (container.id && target) {
        try { sessionStorage.setItem(`mds-tab-${container.id}`, target); } catch (_) {}
      }
    }

    tabs.forEach((tab, i) => {
      tab.setAttribute('role', 'tab');
      tab.setAttribute('aria-selected', tab.classList.contains('active') ? 'true' : 'false');
      tab.setAttribute('tabindex', tab.classList.contains('active') ? '0' : '-1');
      tab.addEventListener('click', e => { e.preventDefault(); activate(tab); });
      tab.addEventListener('keydown', e => {
        let next = null;
        if (e.key === 'ArrowRight') next = tabs[i + 1] || tabs[0];
        if (e.key === 'ArrowLeft')  next = tabs[i - 1] || tabs[tabs.length - 1];
        if (next) { next.focus(); activate(next); }
      });
    });

    // Restore from sessionStorage
    if (container.id) {
      try {
        const saved = sessionStorage.getItem(`mds-tab-${container.id}`);
        if (saved) {
          const match = tabs.find(t => (t.dataset.tab || t.getAttribute('href')?.replace('#','')) === saved);
          if (match) activate(match);
        }
      } catch (_) {}
    }

    // Activate first tab if none are active
    if (!tabs.some(t => t.classList.contains('active')) && tabs[0]) activate(tabs[0]);
  }

  const tabs = { init: initTabs };

  /* ────────────────────────────────────────────────────────────────────
     DROPDOWN
  ──────────────────────────────────────────────────────────────────── */

  let activeDropdown = null;

  function closeDropdowns() {
    if (activeDropdown) {
      activeDropdown.classList.remove('open');
      activeDropdown = null;
    }
  }

  function initDropdown(el) {
    const trigger = qs('[data-dropdown-trigger]', el) || qs('button', el);
    const menu    = qs('.dropdown-menu', el);
    if (!trigger || !menu) return;

    trigger.setAttribute('aria-haspopup', 'true');
    trigger.setAttribute('aria-expanded', 'false');

    trigger.addEventListener('click', e => {
      e.stopPropagation();
      const isOpen = menu.classList.contains('open');
      closeDropdowns();
      if (!isOpen) {
        menu.classList.add('open');
        activeDropdown = menu;
        trigger.setAttribute('aria-expanded', 'true');

        // Keyboard nav inside menu
        const items = qsa('.dropdown-item:not([disabled]):not([aria-disabled])', menu);
        menu.addEventListener('keydown', function menuKey(e) {
          const i = items.indexOf(document.activeElement);
          if (e.key === 'ArrowDown') { items[i + 1]?.focus(); e.preventDefault(); }
          if (e.key === 'ArrowUp')   { items[i - 1]?.focus(); e.preventDefault(); }
          if (e.key === 'Escape')    { closeDropdowns(); trigger.focus(); menu.removeEventListener('keydown', menuKey); }
        });
        items[0]?.focus();
      } else {
        trigger.setAttribute('aria-expanded', 'false');
      }
    });

    menu.addEventListener('click', e => {
      if (e.target.closest('.dropdown-item')) closeDropdowns();
    });
  }

  function initAllDropdowns(root) {
    qsa('.dropdown', root || document).forEach(initDropdown);
  }

  document.addEventListener('click', e => {
    if (activeDropdown && !e.target.closest('.dropdown')) closeDropdowns();
  });

  const dropdown = { init: initAllDropdowns };

  /* ────────────────────────────────────────────────────────────────────
     FORM VALIDATION
  ──────────────────────────────────────────────────────────────────── */

  const validators = {
    required:    v => v.trim() !== '' || 'This field is required',
    email:       v => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) || 'Enter a valid email address',
    minlength:   (v, min) => v.length >= parseInt(min) || `Minimum ${min} characters`,
    maxlength:   (v, max) => v.length <= parseInt(max) || `Maximum ${max} characters`,
    min:         (v, min) => parseFloat(v) >= parseFloat(min) || `Minimum value is ${min}`,
    max:         (v, max) => parseFloat(v) <= parseFloat(max) || `Maximum value is ${max}`,
    pattern:     (v, p)   => new RegExp(p).test(v) || 'Invalid format',
    phone:       v => /^[\d\s\+\-\(\)]{7,15}$/.test(v.replace(/\s/g,'')) || 'Enter a valid phone number',
    url:         v => { try { new URL(v); return true; } catch { return 'Enter a valid URL'; } },
    match:       (v, targetId) => v === (document.getElementById(targetId)?.value || '') || 'Fields do not match',
  };

  function getFieldError(input) {
    const v = input.value;
    for (const [rule, arg] of Object.entries(input.dataset)) {
      if (rule.startsWith('validate')) {
        const ruleName = rule.replace('validate', '').toLowerCase();
        const fn = validators[ruleName];
        if (fn) {
          const result = arg === '' ? fn(v) : fn(v, arg);
          if (result !== true) return result;
        }
      }
    }
    // Native HTML5 constraints
    if (!input.checkValidity()) return input.validationMessage;
    return null;
  }

  function showFieldError(input, msg) {
    clearFieldError(input);
    input.classList.add('input-error');
    input.setAttribute('aria-invalid', 'true');
    const err = document.createElement('div');
    err.className = 'field-error';
    err.id = `err-${input.id || Math.random().toString(36).slice(2)}`;
    err.textContent = `⚠ ${msg}`;
    input.setAttribute('aria-describedby', err.id);
    input.insertAdjacentElement('afterend', err);
  }

  function clearFieldError(input) {
    input.classList.remove('input-error');
    input.removeAttribute('aria-invalid');
    input.removeAttribute('aria-describedby');
    const next = input.nextElementSibling;
    if (next && next.classList.contains('field-error')) next.remove();
  }

  function validateForm(formEl) {
    const inputs = qsa('[data-validate], [required], [pattern], [min], [max]', formEl)
      .filter(el => el.tagName !== 'BUTTON' && !el.disabled);

    let valid = true;
    let firstError = null;

    inputs.forEach(input => {
      clearFieldError(input);
      const err = getFieldError(input);
      if (err) {
        showFieldError(input, err);
        valid = false;
        if (!firstError) firstError = input;
      }
    });

    if (firstError) firstError.focus();
    return valid;
  }

  function initFormLiveValidation(formEl) {
    qsa('input, select, textarea', formEl).forEach(input => {
      input.addEventListener('blur', () => {
        const err = getFieldError(input);
        if (err) showFieldError(input, err);
        else clearFieldError(input);
      });
      input.addEventListener('input', () => {
        if (input.classList.contains('input-error')) {
          const err = getFieldError(input);
          if (!err) clearFieldError(input);
        }
      });
    });
  }

  const form = {
    validate:        validateForm,
    initLive:        initFormLiveValidation,
    addValidator:    (name, fn) => { validators[name] = fn; },
    showError:       showFieldError,
    clearError:      clearFieldError,
  };

  /* ────────────────────────────────────────────────────────────────────
     SKELETON
  ──────────────────────────────────────────────────────────────────── */

  function showSkeleton(container) {
    const content = qsa('[data-skeleton-hide]', container);
    const skels   = qsa('[data-skeleton-show]', container);
    content.forEach(el => { el.dataset.wasHidden = el.hidden; el.hidden = true; });
    skels.forEach(el => { el.hidden = false; });
  }

  function hideSkeleton(container) {
    const content = qsa('[data-skeleton-hide]', container);
    const skels   = qsa('[data-skeleton-show]', container);
    content.forEach(el => { el.hidden = el.dataset.wasHidden === 'true'; delete el.dataset.wasHidden; });
    skels.forEach(el => { el.hidden = true; });
  }

  /**
   * Build skeleton rows for a table body.
   * Usage: Modus.skeleton.tableRows(tbody, 5, 4)
   */
  function skeletonTableRows(tbody, rows = 5, cols = 4) {
    const colWidths = Array.from({ length: cols }, (_, i) => `${Math.random() * 40 + 40}%`);
    tbody.innerHTML = Array.from({ length: rows }, () => `
      <tr>
        ${colWidths.map(w => `<td><span class="skeleton skeleton-text" style="width:${w}"></span></td>`).join('')}
      </tr>
    `).join('');
  }

  const skeleton = {
    show:      showSkeleton,
    hide:      hideSkeleton,
    tableRows: skeletonTableRows,
  };

  /* ────────────────────────────────────────────────────────────────────
     TABLE — sort, filter, paginate
  ──────────────────────────────────────────────────────────────────── */

  /**
   * opts: { pageSize=20, searchSelector='', onSort, onFilter, onPage }
   */
  function initTable(tableEl, opts = {}) {
    const { pageSize = 20, searchSelector = '' } = opts;

    const tbody    = tableEl.querySelector('tbody');
    const headers  = qsa('th[data-sort]', tableEl);
    let allRows    = Array.from(tbody.querySelectorAll('tr'));
    let filtered   = [...allRows];
    let sortCol    = null;
    let sortDir    = 'asc';
    let page       = 1;
    let totalPages = 1;

    // ── Search / filter ──────────────────────────────────────────────
    function applyFilter(query) {
      const q = (query || '').toLowerCase().trim();
      filtered = q
        ? allRows.filter(row => row.textContent.toLowerCase().includes(q))
        : [...allRows];
      page = 1;
      render();
    }

    if (searchSelector) {
      const searchEl = document.querySelector(searchSelector);
      if (searchEl) {
        let debounce;
        searchEl.addEventListener('input', () => {
          clearTimeout(debounce);
          debounce = setTimeout(() => applyFilter(searchEl.value), 200);
        });
      }
    }

    // ── Sort ─────────────────────────────────────────────────────────
    headers.forEach(th => {
      th.addEventListener('click', () => {
        const col = th.cellIndex;
        if (sortCol === col) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
        else { sortCol = col; sortDir = 'asc'; }

        headers.forEach(h => h.removeAttribute('data-sort'));
        headers.forEach(h => h.setAttribute('data-sort', ''));
        th.setAttribute('data-sort', sortDir);

        const type = th.dataset.type || 'string';
        filtered.sort((a, b) => {
          const av = a.cells[col]?.textContent.trim() || '';
          const bv = b.cells[col]?.textContent.trim() || '';
          let cmp;
          if (type === 'number') cmp = parseFloat(av) - parseFloat(bv);
          else if (type === 'date') cmp = new Date(av) - new Date(bv);
          else cmp = av.localeCompare(bv, undefined, { sensitivity: 'base' });
          return sortDir === 'asc' ? cmp : -cmp;
        });
        page = 1;
        render();
      });
    });

    // ── Pagination ───────────────────────────────────────────────────
    let paginationEl = tableEl.parentElement.querySelector('.pagination');

    function renderPagination() {
      if (!paginationEl) return;
      totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
      const start = (page - 1) * pageSize + 1;
      const end   = Math.min(page * pageSize, filtered.length);

      const pages = [];
      const delta = 2;
      for (let i = 1; i <= totalPages; i++) {
        if (i === 1 || i === totalPages || (i >= page - delta && i <= page + delta)) pages.push(i);
        else if (pages[pages.length - 1] !== '…') pages.push('…');
      }

      paginationEl.innerHTML = `
        <button class="page-btn" data-page="${page - 1}" ${page === 1 ? 'aria-disabled="true"' : ''} aria-label="Previous">←</button>
        ${pages.map(p => p === '…'
          ? `<span class="page-btn page-btn-dots">…</span>`
          : `<button class="page-btn ${p === page ? 'active' : ''}" data-page="${p}" aria-label="Page ${p}" ${p === page ? 'aria-current="page"' : ''}>${p}</button>`
        ).join('')}
        <button class="page-btn" data-page="${page + 1}" ${page === totalPages ? 'aria-disabled="true"' : ''} aria-label="Next">→</button>
        <span class="pagination-info">${filtered.length ? `${start}–${end} of ${filtered.length}` : '0 results'}</span>
      `;

      paginationEl.querySelectorAll('[data-page]').forEach(btn => {
        btn.addEventListener('click', () => {
          const p = parseInt(btn.dataset.page);
          if (p >= 1 && p <= totalPages && p !== page) { page = p; render(); }
        });
      });
    }

    // ── Render ───────────────────────────────────────────────────────
    function render() {
      tbody.innerHTML = '';
      const start = (page - 1) * pageSize;
      const slice = filtered.slice(start, start + pageSize);

      if (!slice.length) {
        const empty = document.createElement('tr');
        empty.innerHTML = `<td colspan="${tableEl.querySelector('thead tr')?.children.length || 4}" style="text-align:center;padding:32px;color:var(--muted);font-size:13px">No results found</td>`;
        tbody.appendChild(empty);
      } else {
        slice.forEach(row => tbody.appendChild(row));
      }
      renderPagination();
    }

    render();

    return {
      refresh: () => { allRows = Array.from(tbody.querySelectorAll('tr')); filtered = [...allRows]; page = 1; render(); },
      filter:  applyFilter,
      getPage: () => page,
      setPage: (p) => { page = p; render(); },
    };
  }

  const table = { init: initTable };

  /* ────────────────────────────────────────────────────────────────────
     THEME MANAGER
  ──────────────────────────────────────────────────────────────────── */

  function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    try { localStorage.setItem('mds-theme', theme); } catch (_) {}
  }

  function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || 'light';
    setTheme(current === 'dark' ? 'light' : 'dark');
  }

  function initTheme() {
    try {
      const saved = localStorage.getItem('mds-theme');
      if (saved) { setTheme(saved); return; }
    } catch (_) {}
    if (window.matchMedia?.('(prefers-color-scheme: dark)').matches) setTheme('dark');
  }

  const theme = { set: setTheme, toggle: toggleTheme, init: initTheme };

  /* ────────────────────────────────────────────────────────────────────
     BUTTON LOADING STATE
  ──────────────────────────────────────────────────────────────────── */

  function btnLoad(btnEl, label) {
    btnEl.dataset.originalText = btnEl.innerHTML;
    if (label) btnEl.textContent = label;
    btnEl.dataset.loading = 'true';
    btnEl.disabled = true;
  }

  function btnDone(btnEl, label, tempLabel) {
    btnEl.dataset.loading = 'false';
    btnEl.disabled = false;
    if (tempLabel) {
      btnEl.textContent = tempLabel;
      setTimeout(() => { btnEl.innerHTML = label || btnEl.dataset.originalText || btnEl.textContent; }, 2000);
    } else {
      btnEl.innerHTML = label || btnEl.dataset.originalText || btnEl.textContent;
    }
  }

  const btn = { load: btnLoad, done: btnDone };

  /* ────────────────────────────────────────────────────────────────────
     TAG INPUT
  ──────────────────────────────────────────────────────────────────── */

  function initTagInput(wrap) {
    const input   = qs('input', wrap);
    const hiddenInput = wrap.dataset.hiddenInput ? document.getElementById(wrap.dataset.hiddenInput) : null;
    const tags    = new Set(Array.from(qsa('.tag', wrap)).map(t => t.textContent.trim().replace('✕', '').trim()));

    function syncHidden() {
      if (hiddenInput) hiddenInput.value = [...tags].join(',');
    }

    function addTag(value) {
      const val = value.trim();
      if (!val || tags.has(val)) return;
      tags.add(val);
      const tag = document.createElement('span');
      tag.className = 'tag';
      tag.innerHTML = `${esc(val)}<button class="tag-close" type="button" aria-label="Remove ${esc(val)}">✕</button>`;
      tag.querySelector('.tag-close').addEventListener('click', () => { tag.remove(); tags.delete(val); syncHidden(); });
      wrap.insertBefore(tag, input);
      syncHidden();
    }

    input.addEventListener('keydown', e => {
      if ((e.key === 'Enter' || e.key === ',') && input.value.trim()) {
        e.preventDefault();
        addTag(input.value.replace(',', ''));
        input.value = '';
      }
      if (e.key === 'Backspace' && !input.value) {
        const lastTag = Array.from(qsa('.tag', wrap)).pop();
        if (lastTag) { tags.delete(lastTag.textContent.trim().replace('✕','').trim()); lastTag.remove(); syncHidden(); }
      }
    });

    input.addEventListener('blur', () => {
      if (input.value.trim()) { addTag(input.value); input.value = ''; }
    });

    wrap.addEventListener('click', () => input.focus());

    return {
      getTags: () => [...tags],
      addTag,
      clear: () => { qsa('.tag', wrap).forEach(t => t.remove()); tags.clear(); syncHidden(); },
    };
  }

  const tag = { init: initTagInput };

  /* ────────────────────────────────────────────────────────────────────
     CHARACTER COUNTER
  ──────────────────────────────────────────────────────────────────── */

  function initCharCounter(input) {
    const max     = parseInt(input.dataset.maxlength || input.maxLength);
    if (!max) return;
    const counter = document.createElement('div');
    counter.className = 'input-counter';
    counter.textContent = `${input.value.length} / ${max}`;
    input.insertAdjacentElement('afterend', counter);

    input.setAttribute('maxlength', max);
    input.addEventListener('input', () => {
      const len = input.value.length;
      counter.textContent = `${len} / ${max}`;
      counter.classList.toggle('near-limit', len >= max * 0.85 && len < max);
      counter.classList.toggle('at-limit', len >= max);
    });
  }

  /* ────────────────────────────────────────────────────────────────────
     AUTO-INIT
  ──────────────────────────────────────────────────────────────────── */

  function autoInit() {
    // Theme
    initTheme();

    // Tabs
    qsa('.tabs').forEach(el => initTabs(el));

    // Dropdowns
    initAllDropdowns();

    // Modal triggers
    document.addEventListener('click', e => {
      // Open
      const opener = e.target.closest('[data-modal-open]');
      if (opener) { e.preventDefault(); openModal(opener.dataset.modalOpen); return; }

      // Close
      const closer = e.target.closest('[data-modal-close]');
      if (closer) { e.preventDefault(); closeModal(closer.dataset.modalClose || closer.closest('.modal-overlay')?.id); return; }

      // Drawer open
      const drawerOpen = e.target.closest('[data-drawer-open]');
      if (drawerOpen) { e.preventDefault(); openDrawer(drawerOpen.dataset.drawerOpen); return; }

      // Drawer close
      const drawerClose = e.target.closest('[data-drawer-close]');
      if (drawerClose) { e.preventDefault(); closeDrawer(drawerClose.dataset.drawerClose || drawerClose.closest('.drawer-overlay')?.id); return; }
    });

    // Dismiss alerts
    document.addEventListener('click', e => {
      const btn = e.target.closest('.alert-close');
      if (btn) { const alert = btn.closest('.alert'); if (alert) alert.remove(); }
    });

    // Tag inputs
    qsa('.tag-input-wrap').forEach(el => initTagInput(el));

    // Character counters
    qsa('[data-maxlength]').forEach(el => initCharCounter(el));

    // Sortable tables
    qsa('[data-sort-table]').forEach(el => initTable(el, {
      pageSize:       parseInt(el.dataset.pageSize) || 20,
      searchSelector: el.dataset.searchFor || '',
    }));

    // Form live validation
    qsa('[data-validate-live]').forEach(el => initFormLiveValidation(el));

    // Close modal when clicking outside
    qsa('.modal-overlay').forEach(overlay => {
      if (overlay.getAttribute('data-no-dismiss') !== 'true') {
        overlay.addEventListener('click', e => {
          if (e.target === overlay) closeModal(overlay);
        });
      }
    });
  }

  /* ────────────────────────────────────────────────────────────────────
     PUBLIC API
  ──────────────────────────────────────────────────────────────────── */

  const Modus = {
    toast,
    modal,
    drawer,
    tabs,
    dropdown,
    form,
    skeleton,
    table,
    theme,
    btn,
    tag,
    version: '2.0.0',
  };

  // Expose globally
  global.Modus = Modus;

  // Auto-init on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', autoInit);
  } else {
    autoInit();
  }

}(typeof window !== 'undefined' ? window : global));

/* ═══════════════════════════════════════════════════════════════════════
   USAGE REFERENCE
   ───────────────────────────────────────────────────────────────────
   TOAST
     Modus.toast.success('Saved!')
     Modus.toast.error('Something went wrong', { title: 'Error', duration: 6000 })
     Modus.toast.info({ title: 'Update', message: 'v2 is live', action: { label: 'View', fn: () => location.reload() } })

   MODAL
     HTML:  <div id="my-modal" class="modal-overlay" hidden> <div class="modal"> ... </div> </div>
     Trigger: <button data-modal-open="my-modal">Open</button>
     Dismiss: <button data-modal-close="my-modal">Close</button>
     JS:    Modus.modal.open('my-modal')   /   Modus.modal.close('my-modal')
     Confirm: const ok = await Modus.modal.confirm({ title: 'Delete?', danger: true })

   DRAWER
     HTML:  <div id="my-drawer" class="drawer-overlay"> <div class="drawer"> ... </div> </div>
     Trigger: <button data-drawer-open="my-drawer">Open</button>

   TABS
     HTML:
       <div class="tabs" id="my-tabs">
         <button class="tab active" data-tab="overview">Overview</button>
         <button class="tab" data-tab="settings">Settings</button>
       </div>
       <div data-panel="overview" class="tab-panel active">...</div>
       <div data-panel="settings" class="tab-panel" hidden>...</div>

   FORM VALIDATION
     <input required data-validate-required data-validate-email placeholder="Email">
     <input data-validate-minlength="8" placeholder="Password">
     Modus.form.validate(document.getElementById('my-form'))

   SKELETON (manual show/hide)
     <div data-skeleton-show hidden class="skeleton-card"></div>
     <div data-skeleton-hide>Real content</div>
     Modus.skeleton.show(container)  /  Modus.skeleton.hide(container)
     Modus.skeleton.tableRows(tbody, 6, 4)

   TABLE
     <table data-sort-table data-page-size="25" data-search-for="#my-search">
       <thead><tr><th data-sort data-type="string">Name</th>...</tr></thead>
       <tbody>...</tbody>
     </table>
     <div class="pagination"></div>  <!-- must be sibling of table's parent -->
     Or via JS: const ctrl = Modus.table.init(tableEl, { pageSize: 25, searchSelector: '#my-search' })

   BTN LOADING
     Modus.btn.load(btn, 'Saving…')
     await save()
     Modus.btn.done(btn, 'Save', 'Saved ✓')

   THEME
     <button onclick="Modus.theme.toggle()">Toggle dark mode</button>

   TAG INPUT
     <div class="tag-input-wrap" data-hidden-input="tags-field">
       <input placeholder="Add tag…">
       <input type="hidden" id="tags-field" name="tags">
     </div>
     const ctrl = Modus.tag.init(wrap)
     ctrl.getTags()  //=> ['react', 'node']
════════════════════════════════════════════════════════════════════════ */
