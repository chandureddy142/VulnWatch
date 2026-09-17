document.addEventListener('DOMContentLoaded', function () {
    const filterButtons = document.querySelectorAll('.filter-btn');
    const findingItems = document.querySelectorAll('.finding-item');
    const searchInput = document.getElementById('finding-search');
    const noResultsState = document.getElementById('no-results-state');

    let activeSeverity = 'ALL';
    let activeDiff = null;
    let searchQuery = '';

    // ---------- Severity and Diff filter buttons ----------
    filterButtons.forEach(function (btn) {
        btn.addEventListener('click', function () {
            filterButtons.forEach(function (b) { b.classList.remove('is-active'); });
            this.classList.add('is-active');

            const sev = this.getAttribute('data-severity');
            const diff = this.getAttribute('data-diff');

            if (sev) {
                activeSeverity = sev;
                activeDiff = null;
            } else if (diff) {
                activeSeverity = 'ALL';
                activeDiff = diff;
            }

            applyFilters();
        });
    });

    // ---------- Live keyword search ----------
    if (searchInput) {
        searchInput.addEventListener('input', function () {
            searchQuery = this.value.toLowerCase().trim();
            applyFilters();
        });
    }

    function applyFilters() {
        let visibleCount = 0;
        const severityCounts = { ALL: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };

        findingItems.forEach(function (item) {
            const itemSeverity = item.getAttribute('data-severity');
            const itemDiff = item.getAttribute('data-diff');
            const itemText = item.textContent.toLowerCase();
            const matchesSearch = !searchQuery || itemText.includes(searchQuery);

            if (matchesSearch) {
                severityCounts.ALL += 1;
                if (severityCounts.hasOwnProperty(itemSeverity)) {
                    severityCounts[itemSeverity] += 1;
                }
            }

            let matchesFilter = true;
            if (activeDiff) {
                matchesFilter = (itemDiff === activeDiff);
            } else if (activeSeverity !== 'ALL') {
                matchesFilter = (itemSeverity === activeSeverity);
            }

            const isVisible = matchesFilter && matchesSearch;

            item.classList.toggle('is-hidden', !isVisible);
            if (isVisible) visibleCount += 1;
        });

        filterButtons.forEach(function (btn) {
            const badge = btn.querySelector('.count-badge');
            const sev = btn.getAttribute('data-severity');
            if (badge && severityCounts.hasOwnProperty(sev)) {
                badge.textContent = severityCounts[sev];
            }
        });

        if (noResultsState) {
            noResultsState.classList.toggle('hidden', visibleCount !== 0 || findingItems.length === 0);
        }
    }

    // ---------- Collapsible finding cards ----------
    document.querySelectorAll('.finding-header').forEach(function (header) {
        header.addEventListener('click', function () {
            const item = this.closest('.finding-item');
            const isOpen = item.classList.toggle('is-open');
            this.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
        });
    });

    // ---------- Triage async save ----------
    document.querySelectorAll('.btn-save-triage').forEach(function (btn) {
        btn.addEventListener('click', function (e) {
            e.stopPropagation();
            const scanId = this.getAttribute('data-scan-id');
            const findingId = this.getAttribute('data-finding-id');
            const statusSelect = document.getElementById(`triage-status-${findingId}`);
            const notesInput = document.getElementById(`triage-notes-${findingId}`);

            const triageStatus = statusSelect ? statusSelect.value : 'active';
            const triageNotes = notesInput ? notesInput.value : '';

            const originalBtnText = this.textContent;
            this.disabled = true;
            this.textContent = 'Saving...';

            fetch(`/reports/${scanId}/findings/${findingId}/triage`, {
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    triage_status: triageStatus,
                    triage_notes: triageNotes
                })
            })
                .then(function (response) {
                    return response.json().then(function (data) {
                        if (!response.ok) {
                            throw new Error(data.error || 'Failed to update triage.');
                        }
                        return data;
                    });
                })
                .then(function (data) {
                    if (window.showToast) {
                        window.showToast(`Finding #${findingId} triage status updated to "${triageStatus}"`, 'success');
                    }
                    const item = document.querySelector(`.finding-item[data-triage]`);
                    if (item) item.setAttribute('data-triage', triageStatus);
                })
                .catch(function (err) {
                    if (window.showToast) {
                        window.showToast(`Triage update failed: ${err.message}`, 'error');
                    }
                })
                .finally(() => {
                    this.disabled = false;
                    this.textContent = originalBtnText;
                });
        });
    });

    // ---------- Copy evidence to clipboard ----------
    document.querySelectorAll('.copy-btn').forEach(function (btn) {
        btn.addEventListener('click', function (e) {
            e.stopPropagation();
            const targetId = this.getAttribute('data-copy-target');
            const block = document.getElementById(targetId);
            if (!block) return;

            const text = block.textContent;
            const label = this.querySelector('span:last-child');
            const originalLabel = label ? label.textContent : '';

            const onCopied = function (btnEl, labelEl) {
                btnEl.classList.add('is-copied');
                if (labelEl) labelEl.textContent = 'Copied!';
                setTimeout(function () {
                    btnEl.classList.remove('is-copied');
                    if (labelEl) labelEl.textContent = originalLabel;
                }, 1500);
            };

            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text)
                    .then(function () { onCopied(btn, label); })
                    .catch(function () { fallbackCopy(text, btn, label, onCopied); });
            } else {
                fallbackCopy(text, btn, label, onCopied);
            }
        });
    });

    function fallbackCopy(text, btn, label, onCopied) {
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        document.body.appendChild(textarea);
        textarea.select();
        try {
            document.execCommand('copy');
            onCopied(btn, label);
        } catch (err) {
            /* Clipboard unavailable; silently ignore */
        }
        document.body.removeChild(textarea);
    }

    // Initialize counts on load
    applyFilters();

    // ---------- Remediation Snippet Tab Handler ----------
    document.querySelectorAll('.snippet-tab').forEach(function (tab) {
        tab.addEventListener('click', function (e) {
            e.stopPropagation();
            const container = this.closest('.snippets-container');
            if (!container) return;

            const targetId = this.getAttribute('data-target');

            container.querySelectorAll('.snippet-tab').forEach(function (t) { t.classList.remove('active'); });
            container.querySelectorAll('.snippet-pane').forEach(function (p) { p.classList.add('hidden'); p.classList.remove('active'); });

            this.classList.add('active');
            const targetPane = document.getElementById(targetId);
            if (targetPane) {
                targetPane.classList.remove('hidden');
                targetPane.classList.add('active');
            }
        });
    });


    // ---------- CVSS v3.1 Base Score Calculator ----------

    // CVSS v3.1 metric numeric values per FIRST specification
    const CVSS_WEIGHTS = {
        AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.20 },
        AC: { L: 0.77, H: 0.44 },
        PR: {
            U: { N: 0.85, L: 0.62, H: 0.27 },
            C: { N: 0.85, L: 0.68, H: 0.50 },
        },
        UI: { N: 0.85, R: 0.62 },
        S:  { U: 0, C: 0 },   // handled in score logic
        C:  { N: 0.00, L: 0.22, H: 0.56 },
        I:  { N: 0.00, L: 0.22, H: 0.56 },
        A:  { N: 0.00, L: 0.22, H: 0.56 },
    };

    // Per-finding CVSS state map
    const cvssState = {};

    function computeCvssScore(fid) {
        const state = cvssState[fid] || {};
        const metrics = ['AV','AC','PR','UI','S','C','I','A'];
        if (!metrics.every(function(m) { return state[m]; })) return null;

        const scope = state['S'];
        const AV_w  = CVSS_WEIGHTS.AV[state['AV']];
        const AC_w  = CVSS_WEIGHTS.AC[state['AC']];
        const PR_w  = CVSS_WEIGHTS.PR[scope][state['PR']];
        const UI_w  = CVSS_WEIGHTS.UI[state['UI']];
        const C_w   = CVSS_WEIGHTS.C[state['C']];
        const I_w   = CVSS_WEIGHTS.I[state['I']];
        const A_w   = CVSS_WEIGHTS.A[state['A']];

        // Exploitability Sub-score
        const ISCBase = 1 - ((1 - C_w) * (1 - I_w) * (1 - A_w));
        let ISC, f_scope;
        if (scope === 'U') {
            ISC = 6.42 * ISCBase;
            f_scope = 1;
        } else {
            ISC = 7.52 * (ISCBase - 0.029) - 3.25 * Math.pow(ISCBase - 0.02, 15);
            f_scope = 1.08;
        }

        if (ISC <= 0) return 0.0;

        const ESC = 8.22 * AV_w * AC_w * PR_w * UI_w;
        const rawScore = Math.min(10.0, f_scope * (ISC + ESC));

        // Roundup to 1 decimal
        const score = Math.ceil(rawScore * 10) / 10;
        return score;
    }

    function cvssRating(score) {
        if (score === null) return null;
        if (score === 0.0) return 'None';
        if (score < 4.0)  return 'Low';
        if (score < 7.0)  return 'Medium';
        if (score < 9.0)  return 'High';
        return 'Critical';
    }

    function buildCvssVector(fid) {
        const state = cvssState[fid] || {};
        const order = ['AV','AC','PR','UI','S','C','I','A'];
        const abbrev = { C: 'C', I: 'I', A: 'A', AV: 'AV', AC: 'AC', PR: 'PR', UI: 'UI', S: 'S' };
        return 'CVSS:3.1/' + order.filter(function(m) { return state[m]; }).map(function(m) { return m + ':' + state[m]; }).join('/');
    }

    function updateCvssDisplay(fid) {
        const score = computeCvssScore(fid);
        const displayEl = document.getElementById('cvss-display-' + fid);
        const resultEl  = document.getElementById('cvss-result-' + fid);
        const vectorEl  = document.getElementById('cvss-vector-' + fid);
        const ratingEl  = document.getElementById('cvss-rating-' + fid);

        if (score !== null) {
            const rating = cvssRating(score);
            if (displayEl) displayEl.textContent = 'Score: ' + score.toFixed(1) + ' (' + rating + ')';
            if (vectorEl) vectorEl.textContent = buildCvssVector(fid);
            if (ratingEl) {
                ratingEl.textContent = rating;
                ratingEl.className = 'cvss-rating ' + rating.toLowerCase();
            }
            if (resultEl) resultEl.style.display = 'flex';
        } else {
            const filled = Object.keys(cvssState[fid] || {}).length;
            if (displayEl) displayEl.textContent = 'Score: — (' + filled + '/8 metrics)';
            if (resultEl) resultEl.style.display = 'none';
        }
    }

    // Attach click handlers to all CVSS metric buttons
    document.querySelectorAll('.cvss-btn-group').forEach(function (group) {
        const metric  = group.getAttribute('data-metric');
        const findingId = group.getAttribute('data-finding');

        group.querySelectorAll('.cvss-btn').forEach(function (btn) {
            btn.addEventListener('click', function (e) {
                e.stopPropagation();

                // Deselect siblings
                group.querySelectorAll('.cvss-btn').forEach(function (b) { b.classList.remove('active'); });
                this.classList.add('active');

                if (!cvssState[findingId]) cvssState[findingId] = {};
                cvssState[findingId][metric] = this.getAttribute('data-value');

                updateCvssDisplay(findingId);
            });
        });
    });
});



