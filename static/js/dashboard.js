/* =========================================================
   WebGuard — Dashboard JS
   Table search, filter, sort, pagination + sparkline render
   ========================================================= */

document.addEventListener('DOMContentLoaded', function () {
    'use strict';

    // ---- Sparkline ----
    renderSparkline();

    // ---- Table state ----
    const tbody = document.getElementById('scans-tbody');
    if (!tbody) return;

    const rows = Array.from(tbody.querySelectorAll('tr[data-scan-id]'));
    const tableCount = document.getElementById('table-count');
    const paginationInfo = document.getElementById('pagination-info');
    const paginationControls = document.getElementById('pagination-controls');
    const searchInput = document.getElementById('table-search');
    const severityFilter = document.getElementById('severity-filter');

    const PAGE_SIZE = 10;
    let currentPage = 1;
    let sortKey = 'id';
    let sortDir = 'desc';
    let filtered = rows.slice();

    // ---- Sorting ----
    document.querySelectorAll('.data-table th[data-sort]').forEach(function (th) {
        th.addEventListener('click', function () {
            var key = this.getAttribute('data-sort');
            if (sortKey === key) {
                sortDir = sortDir === 'asc' ? 'desc' : 'asc';
            } else {
                sortKey = key;
                sortDir = 'asc';
            }
            _updateSortHeaders();
            currentPage = 1;
            _applyAll();
        });
    });

    function _updateSortHeaders() {
        document.querySelectorAll('.data-table th[data-sort]').forEach(function (th) {
            th.classList.remove('sort-asc', 'sort-desc');
            if (th.getAttribute('data-sort') === sortKey) {
                th.classList.add(sortDir === 'asc' ? 'sort-asc' : 'sort-desc');
            }
        });
    }

    // ---- Search ----
    if (searchInput) {
        searchInput.addEventListener('input', function () {
            currentPage = 1;
            _applyAll();
        });
    }

    // ---- Severity filter ----
    if (severityFilter) {
        severityFilter.addEventListener('change', function () {
            currentPage = 1;
            _applyAll();
        });
    }

    function _applyAll() {
        var query = searchInput ? searchInput.value.toLowerCase().trim() : '';
        var sev = severityFilter ? severityFilter.value : '';

        // Filter
        filtered = rows.filter(function (row) {
            var target = (row.getAttribute('data-target') || '').toLowerCase();
            var id = (row.getAttribute('data-scan-id') || '').toLowerCase();
            var status = row.getAttribute('data-status') || '';
            var matchesSearch = !query || target.includes(query) || id.includes(query);
            var matchesSev = !sev ||
                (sev === 'critical' && parseInt(row.getAttribute('data-critical') || '0') > 0) ||
                (sev === 'high' && parseInt(row.getAttribute('data-high') || '0') > 0) ||
                (sev === 'medium' && parseInt(row.getAttribute('data-medium') || '0') > 0) ||
                (sev === 'completed' && status === 'completed') ||
                (sev === 'failed' && status === 'failed');
            return matchesSearch && matchesSev;
        });

        // Sort
        filtered.sort(function (a, b) {
            var av = _sortVal(a, sortKey);
            var bv = _sortVal(b, sortKey);
            if (av < bv) return sortDir === 'asc' ? -1 : 1;
            if (av > bv) return sortDir === 'asc' ? 1 : -1;
            return 0;
        });

        _renderPage();
    }

    function _sortVal(row, key) {
        switch (key) {
            case 'id':       return parseInt(row.getAttribute('data-scan-id') || '0');
            case 'target':   return (row.getAttribute('data-target') || '').toLowerCase();
            case 'status':   return row.getAttribute('data-status') || '';
            case 'findings': return parseInt(row.getAttribute('data-findings') || '0');
            case 'date':     return row.getAttribute('data-date') || '';
            default:         return '';
        }
    }

    function _renderPage() {
        var total = filtered.length;
        var totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
        currentPage = Math.min(currentPage, totalPages);

        var start = (currentPage - 1) * PAGE_SIZE;
        var end = Math.min(start + PAGE_SIZE, total);

        // Hide all, show current page subset
        rows.forEach(function (row) { row.style.display = 'none'; });
        filtered.slice(start, end).forEach(function (row) {
            row.style.display = '';
            tbody.appendChild(row); // reorder in DOM
        });

        // Show/hide empty row
        var emptyRow = document.getElementById('empty-row');
        if (emptyRow) emptyRow.style.display = total === 0 ? '' : 'none';

        // Update count
        if (tableCount) tableCount.textContent = total + ' scan' + (total !== 1 ? 's' : '');
        if (paginationInfo) {
            paginationInfo.textContent = total === 0
                ? 'No results'
                : 'Showing ' + (start + 1) + '–' + end + ' of ' + total;
        }

        // Pagination buttons
        if (paginationControls) {
            paginationControls.innerHTML = '';

            var prevBtn = _makePageBtn('‹ Prev', currentPage === 1);
            prevBtn.addEventListener('click', function () {
                if (currentPage > 1) { currentPage--; _renderPage(); }
            });
            paginationControls.appendChild(prevBtn);

            // Page number buttons (max 5 visible)
            var startPage = Math.max(1, currentPage - 2);
            var endPage = Math.min(totalPages, startPage + 4);
            startPage = Math.max(1, endPage - 4);

            for (var p = startPage; p <= endPage; p++) {
                var btn = _makePageBtn(String(p), false);
                if (p === currentPage) btn.classList.add('is-active');
                (function (pg) {
                    btn.addEventListener('click', function () { currentPage = pg; _renderPage(); });
                })(p);
                paginationControls.appendChild(btn);
            }

            var nextBtn = _makePageBtn('Next ›', currentPage === totalPages);
            nextBtn.addEventListener('click', function () {
                if (currentPage < totalPages) { currentPage++; _renderPage(); }
            });
            paginationControls.appendChild(nextBtn);
        }
    }

    function _makePageBtn(label, disabled) {
        var btn = document.createElement('button');
        btn.className = 'page-btn';
        btn.textContent = label;
        btn.disabled = disabled;
        return btn;
    }

    // Initial render
    _updateSortHeaders();
    _applyAll();

    // ---- Sparkline render ----
    function renderSparkline() {
        var svgEl = document.getElementById('sparkline-svg');
        if (!svgEl || typeof SPARKLINE_DATA === 'undefined') return;

        var data = SPARKLINE_DATA;
        if (!data || data.length === 0) return;

        var max = Math.max.apply(null, data) || 1;
        var w = 300;
        var h = 44;
        var pad = 4;

        var pts = data.map(function (v, i) {
            var x = pad + (i / (data.length - 1)) * (w - pad * 2);
            var y = h - pad - ((v / max) * (h - pad * 2));
            return [x, y];
        });

        var linePath = pts.map(function (p, i) {
            return (i === 0 ? 'M' : 'L') + p[0].toFixed(1) + ',' + p[1].toFixed(1);
        }).join(' ');

        var areaPath = linePath +
            ' L' + pts[pts.length - 1][0].toFixed(1) + ',' + h +
            ' L' + pts[0][0].toFixed(1) + ',' + h + ' Z';

        var brand = getComputedStyle(document.documentElement).getPropertyValue('--brand').trim() || '#4338ca';

        svgEl.innerHTML =
            '<defs>' +
            '<linearGradient id="spark-grad" x1="0" y1="0" x2="0" y2="1">' +
            '<stop offset="0%" stop-color="' + brand + '" stop-opacity="0.4"/>' +
            '<stop offset="100%" stop-color="' + brand + '" stop-opacity="0"/>' +
            '</linearGradient>' +
            '</defs>' +
            '<path class="sparkline-area" d="' + areaPath + '" fill="url(#spark-grad)"/>' +
            '<path class="sparkline-line" d="' + linePath + '" stroke="' + brand + '"/>';
    }
});
