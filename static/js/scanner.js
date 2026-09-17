document.addEventListener('DOMContentLoaded', function () {
    const authCheckbox = document.getElementById('auth_confirm');
    const submitBtn = document.getElementById('btn-submit');
    const submitBtnText = document.getElementById('btn-submit-text');
    const scanForm = document.getElementById('scan-form');
    const targetUrlInput = document.getElementById('target_url');
    const batchTargetsInput = document.getElementById('batch_targets');
    const scanModeInput = document.getElementById('scan_mode');
    const protocolTag = document.getElementById('protocol-tag');
    const formError = document.getElementById('form-error');
    const progressCard = document.getElementById('audit-progress');
    const terminalLogs = document.getElementById('terminal-logs');
    const moduleCheckboxes = document.querySelectorAll('.module-check input[type="checkbox"]');

    // Tabs
    const tabSingle = document.getElementById('tab-single');
    const tabBatch = document.getElementById('tab-batch');
    const groupSingle = document.getElementById('group-single-target');
    const groupBatch = document.getElementById('group-batch-targets');

    // Interceptor modal elements
    const interceptorOverlay = document.getElementById('interceptor-overlay');
    const interceptorTargetUrl = document.getElementById('interceptor-target-url');
    const interceptorCancel = document.getElementById('interceptor-cancel');
    const interceptorConfirm = document.getElementById('interceptor-confirm');

    // Queue modal elements
    const btnViewQueue = document.getElementById('btn-view-queue');
    const queueOverlay = document.getElementById('queue-overlay');
    const queueClose = document.getElementById('queue-close');
    const queueListContainer = document.getElementById('queue-list-container');
    let queuePollInterval = null;

    let isSubmitting = false;

    // Enable the submit button only once authorization is confirmed
    if (authCheckbox && submitBtn) {
        authCheckbox.addEventListener('change', function () {
            submitBtn.disabled = !this.checked;
        });
    }

    // Tab Switching Logic
    if (tabSingle && tabBatch) {
        tabSingle.addEventListener('click', function () {
            switchMode('single');
        });
        tabBatch.addEventListener('click', function () {
            switchMode('batch');
        });
    }

    function switchMode(mode) {
        if (scanModeInput) scanModeInput.value = mode;
        if (mode === 'single') {
            tabSingle.classList.add('active');
            tabSingle.setAttribute('aria-selected', 'true');
            tabBatch.classList.remove('active');
            tabBatch.setAttribute('aria-selected', 'false');
            groupSingle.classList.remove('hidden');
            groupBatch.classList.add('hidden');
            if (submitBtnText) submitBtnText.textContent = 'Start Security Assessment';
        } else {
            tabBatch.classList.add('active');
            tabBatch.setAttribute('aria-selected', 'true');
            tabSingle.classList.remove('active');
            tabSingle.setAttribute('aria-selected', 'false');
            groupBatch.classList.remove('hidden');
            groupSingle.classList.add('hidden');
            if (submitBtnText) submitBtnText.textContent = 'Start Multi-Target Batch Audit';
        }
    }

    // Automatic protocol prefixing
    if (targetUrlInput && protocolTag) {
        targetUrlInput.addEventListener('input', function () {
            const value = this.value.trim();
            if (/^https?:\/\//i.test(value)) {
                protocolTag.classList.add('hidden');
            } else {
                protocolTag.classList.remove('hidden');
            }
        });
    }

    function resolveTargetUrl(raw) {
        const value = (raw || '').trim();
        if (!value) return '';
        if (/^https?:\/\//i.test(value)) return value;
        return 'https://' + value;
    }

    function isExternalTarget(urlStr) {
        try {
            const parsed = new URL(urlStr);
            const host = parsed.hostname.toLowerCase();
            return !(
                host === 'localhost' ||
                host === '127.0.0.1' ||
                host === '::1' ||
                host.endsWith('.local')
            );
        } catch (e) {
            return false;
        }
    }

    if (scanForm) {
        scanForm.addEventListener('submit', function (e) {
            e.preventDefault();
            if (isSubmitting) return;

            formError.classList.add('hidden');
            formError.textContent = '';

            if (!authCheckbox.checked) {
                showError('You must explicitly confirm target authorization.');
                return;
            }

            const currentMode = scanModeInput ? scanModeInput.value : 'single';

            if (currentMode === 'batch') {
                const rawText = batchTargetsInput ? batchTargetsInput.value : '';
                const lines = rawText.split('\n').map(l => l.trim()).filter(Boolean);
                if (lines.length === 0) {
                    showError('Please enter at least one target URL for batch auditing.');
                    return;
                }
                const targets = lines.map(resolveTargetUrl);

                // Check external targets
                const hasExternal = targets.some(isExternalTarget);
                if (hasExternal && interceptorOverlay && interceptorTargetUrl) {
                    interceptorTargetUrl.textContent = `${targets.length} target(s) (including external network hosts)`;
                    interceptorOverlay.classList.add('active');
                    return;
                }

                startBatchScan(targets);
            } else {
                const targetUrl = resolveTargetUrl(targetUrlInput ? targetUrlInput.value : '');
                if (!targetUrl) {
                    showError('Please enter a valid target URL or hostname.');
                    return;
                }

                if (isExternalTarget(targetUrl) && interceptorOverlay && interceptorTargetUrl) {
                    interceptorTargetUrl.textContent = targetUrl;
                    interceptorOverlay.classList.add('active');
                    return;
                }

                startScan(targetUrl);
            }
        });
    }

    // Interceptor modal handlers
    if (interceptorCancel) {
        interceptorCancel.addEventListener('click', function () {
            if (interceptorOverlay) interceptorOverlay.classList.remove('active');
        });
    }

    if (interceptorConfirm) {
        interceptorConfirm.addEventListener('click', function () {
            if (interceptorOverlay) interceptorOverlay.classList.remove('active');
            const currentMode = scanModeInput ? scanModeInput.value : 'single';
            if (currentMode === 'batch') {
                const rawText = batchTargetsInput ? batchTargetsInput.value : '';
                const lines = rawText.split('\n').map(l => l.trim()).filter(Boolean);
                const targets = lines.map(resolveTargetUrl);
                startBatchScan(targets);
            } else {
                const targetUrl = resolveTargetUrl(targetUrlInput ? targetUrlInput.value : '');
                startScan(targetUrl);
            }
        });
    }

    // Queue Modal Handlers
    if (btnViewQueue && queueOverlay) {
        btnViewQueue.addEventListener('click', function () {
            queueOverlay.classList.add('active');
            fetchQueueStatus();
            if (queuePollInterval) clearInterval(queuePollInterval);
            queuePollInterval = setInterval(fetchQueueStatus, 3000);
        });
    }

    if (queueClose && queueOverlay) {
        queueClose.addEventListener('click', function () {
            queueOverlay.classList.remove('active');
            if (queuePollInterval) clearInterval(queuePollInterval);
        });
    }

    function fetchQueueStatus() {
        if (!queueListContainer) return;
        fetch('/queue')
            .then(res => res.json())
            .then(scans => {
                if (!scans || scans.length === 0) {
                    queueListContainer.innerHTML = '<div class="text-dim text-center py-3" style="padding:16px;">No running or pending scans in background queue.</div>';
                    return;
                }
                let html = '';
                scans.forEach(s => {
                    html += `
                        <div class="queue-item">
                            <div class="queue-item-url" title="${s.target_url}">${s.target_url}</div>
                            <span class="queue-item-status ${s.status.toLowerCase()}">${s.status}</span>
                        </div>
                    `;
                });
                queueListContainer.innerHTML = html;
            })
            .catch(err => {
                queueListContainer.innerHTML = `<div class="text-dim text-center py-3" style="color:var(--sev-critical); padding:16px;">Failed to fetch queue: ${err.message}</div>`;
            });
    }

    function startScan(targetUrl) {
        if (isSubmitting) return;
        isSubmitting = true;

        submitBtn.disabled = true;
        submitBtn.classList.add('is-scanning');
        if (targetUrlInput) targetUrlInput.disabled = true;
        authCheckbox.disabled = true;
        moduleCheckboxes.forEach(function (cb) { cb.disabled = true; });
        progressCard.classList.remove('hidden');
        progressCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

        appendLog(`[+] Dispatching posture audit request for: ${targetUrl}`);

        fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                target_url: targetUrl,
                authorized: true
            })
        })
            .then(function (response) {
                return response.json().then(function (data) {
                    if (!response.ok) {
                        throw new Error(data.message || data.error || 'Scan request failed.');
                    }
                    return data;
                });
            })
            .then(function (data) {
                appendLog('[+] Audit complete. Processing security findings...', 'success');
                appendLog(`[+] Discovered ${data.scan.findings_count} finding(s). Posture Score: ${data.posture_score}/100`, 'success');

                if (window.showToast) {
                    window.showToast(`Audit completed! Posture Score: ${data.posture_score}/100 (${data.scan.findings_count} findings)`, 'success', 5000);
                }

                setTimeout(function () {
                    window.location.href = `/reports/${data.scan.id}`;
                }, 1000);
            })
            .catch(function (err) {
                appendLog(`[-] ERROR: ${err.message}`, 'error');
                showError(err.message);

                if (window.showToast) {
                    window.showToast(`Scan execution failed: ${err.message}`, 'error', 6000);
                }

                isSubmitting = false;
                submitBtn.disabled = false;
                submitBtn.classList.remove('is-scanning');
                if (targetUrlInput) targetUrlInput.disabled = false;
                authCheckbox.disabled = false;
                moduleCheckboxes.forEach(function (cb) { cb.disabled = false; });
            });
    }

    function startBatchScan(targets) {
        if (isSubmitting) return;
        isSubmitting = true;

        submitBtn.disabled = true;
        submitBtn.classList.add('is-scanning');
        if (batchTargetsInput) batchTargetsInput.disabled = true;
        authCheckbox.disabled = true;
        moduleCheckboxes.forEach(function (cb) { cb.disabled = true; });
        progressCard.classList.remove('hidden');
        progressCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

        appendLog(`[+] Initializing Multi-Target Batch Audit for ${targets.length} target(s)...`);

        fetch('/scan/batch', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                targets: targets,
                authorized: true
            })
        })
            .then(function (response) {
                return response.json().then(function (data) {
                    if (!response.ok) {
                        throw new Error(data.message || data.error || 'Batch scan request failed.');
                    }
                    return data;
                });
            })
            .then(function (data) {
                appendLog(`[+] Batch audit complete! Executed ${data.results.length} scan(s).`, 'success');
                if (data.errors && data.errors.length > 0) {
                    appendLog(`[-] ${data.errors.length} target(s) returned errors.`, 'error');
                }

                if (window.showToast) {
                    window.showToast(`Batch Assessment completed! ${data.results.length} target(s) audited.`, 'success', 5000);
                }

                const ids = (data.results || []).map(r => r.scan_id).filter(Boolean).join(',');
                setTimeout(function () {
                    if (ids) {
                        window.location.href = `/scanner/batch/results?ids=${ids}`;
                    } else {
                        window.location.href = '/dashboard';
                    }
                }, 1200);
            })
            .catch(function (err) {
                appendLog(`[-] ERROR: ${err.message}`, 'error');
                showError(err.message);

                if (window.showToast) {
                    window.showToast(`Batch scan failed: ${err.message}`, 'error', 6000);
                }

                isSubmitting = false;
                submitBtn.disabled = false;
                submitBtn.classList.remove('is-scanning');
                if (batchTargetsInput) batchTargetsInput.disabled = false;
                authCheckbox.disabled = false;
                moduleCheckboxes.forEach(function (cb) { cb.disabled = false; });
            });
    }

    function appendLog(message, tone) {
        if (!terminalLogs) return;
        const line = document.createElement('div');
        line.className = 'log-line' + (tone === 'error' ? ' log-error' : tone === 'success' ? ' log-success' : '');
        line.textContent = `${new Date().toLocaleTimeString()} ${message}`;
        terminalLogs.appendChild(line);
        terminalLogs.scrollTop = terminalLogs.scrollHeight;
    }

    function showError(msg) {
        if (!formError) return;
        formError.textContent = msg;
        formError.classList.remove('hidden');
    }
});

