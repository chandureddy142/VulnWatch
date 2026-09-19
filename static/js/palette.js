/* =========================================================
   WebGuard — Command Palette
   Ctrl+K / Cmd+K opens quick-navigation overlay.
   ========================================================= */

(function () {
    'use strict';

    const overlay = document.getElementById('palette-overlay');
    const input = document.getElementById('palette-input');
    const resultsEl = document.getElementById('palette-results');

    if (!overlay || !input || !resultsEl) return;

    let selectedIndex = -1;
    let currentItems = [];

    // ---- Static navigation items ----
    const NAV_ITEMS = [
        {
            name: 'Dashboard',
            hint: 'Overview',
            href: '/',
            icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/></svg>',
        },
        {
            name: 'New Audit',
            hint: 'Launch scan',
            href: '/scanner',
            icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polygon points="10 8 16 12 10 16 10 8"/></svg>',
        },
        {
            name: 'API Docs',
            hint: 'JSON endpoint',
            href: '/api/scans',
            icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
        },
        {
            name: 'Settings',
            hint: 'Enterprise config',
            href: '/settings',
            icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
        },
    ];

    let recentScans = [];
    let scansFetched = false;

    function fetchRecentScans() {
        if (scansFetched) return;
        scansFetched = true;
        const apiKey = sessionStorage.getItem('webguard_api_key') || '';
        fetch('/api/scans', {
            headers: apiKey ? { 'X-API-Key': apiKey } : {}
        })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                recentScans = (data || []).slice(0, 10).map(function (s) {
                    return {
                        name: s.target_url,
                        hint: 'Scan #' + s.id,
                        href: '/reports/' + s.id,
                        icon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
                    };
                });
                if (input.value.trim() === '') renderResults('');
            })
            .catch(function () { /* graceful no-op */ });
    }

    // ---- Open / close ----
    function open() {
        overlay.classList.add('is-open');
        input.value = '';
        selectedIndex = -1;
        renderResults('');
        fetchRecentScans();
        setTimeout(function () { input.focus(); }, 30);
    }

    function close() {
        overlay.classList.remove('is-open');
        input.blur();
    }

    // ---- Keyboard shortcut ----
    document.addEventListener('keydown', function (e) {
        const isMac = navigator.platform.toUpperCase().includes('MAC');
        if ((isMac ? e.metaKey : e.ctrlKey) && e.key === 'k') {
            e.preventDefault();
            overlay.classList.contains('is-open') ? close() : open();
        }
        if (e.key === 'Escape' && overlay.classList.contains('is-open')) {
            close();
        }
    });

    // ---- Palette trigger button ----
    document.querySelectorAll('[data-palette-open]').forEach(function (btn) {
        btn.addEventListener('click', open);
    });

    // ---- Close on backdrop click ----
    overlay.addEventListener('click', function (e) {
        if (e.target === overlay) close();
    });

    // ---- Input handler ----
    input.addEventListener('input', function () {
        selectedIndex = -1;
        renderResults(this.value.trim().toLowerCase());
    });

    input.addEventListener('keydown', function (e) {
        const items = resultsEl.querySelectorAll('.palette-item');
        if (e.key === 'ArrowDown') {
            e.preventDefault();
            selectedIndex = Math.min(selectedIndex + 1, items.length - 1);
            _updateSelection(items);
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            selectedIndex = Math.max(selectedIndex - 1, -1);
            _updateSelection(items);
        } else if (e.key === 'Enter') {
            e.preventDefault();
            const sel = resultsEl.querySelector('.palette-item.is-selected');
            if (sel) { close(); window.location.href = sel.getAttribute('href'); }
        }
    });

    function _updateSelection(items) {
        items.forEach(function (item, i) {
            item.classList.toggle('is-selected', i === selectedIndex);
        });
    }

    // ---- Render ----
    function renderResults(query) {
        resultsEl.innerHTML = '';

        const navMatches = NAV_ITEMS.filter(function (item) {
            return !query || item.name.toLowerCase().includes(query);
        });

        const scanMatches = recentScans.filter(function (item) {
            return !query || item.name.toLowerCase().includes(query) || item.hint.toLowerCase().includes(query);
        });

        if (navMatches.length === 0 && scanMatches.length === 0) {
            resultsEl.innerHTML = '<div class="palette-empty">No results for "' + _escapeHtml(query) + '"</div>';
            return;
        }

        if (navMatches.length > 0) {
            const label = document.createElement('div');
            label.className = 'palette-group-label';
            label.textContent = 'Navigation';
            resultsEl.appendChild(label);
            navMatches.forEach(function (item) { resultsEl.appendChild(_makeItem(item)); });
        }

        if (scanMatches.length > 0) {
            const label = document.createElement('div');
            label.className = 'palette-group-label';
            label.textContent = 'Recent Scans';
            resultsEl.appendChild(label);
            scanMatches.slice(0, 6).forEach(function (item) { resultsEl.appendChild(_makeItem(item)); });
        }
    }

    function _makeItem(item) {
        const a = document.createElement('a');
        a.className = 'palette-item';
        a.href = item.href;
        a.innerHTML =
            '<span class="palette-item-icon">' + item.icon + '</span>' +
            '<span class="palette-item-name">' + _escapeHtml(item.name) + '</span>' +
            '<span class="palette-item-hint">' + _escapeHtml(item.hint || '') + '</span>';
        a.addEventListener('click', function () { close(); });
        return a;
    }

    function _escapeHtml(str) {
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }
})();
