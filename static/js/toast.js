/* =========================================================
   WebGuard — Toast notification dispatcher
   Stacks multiple toasts, auto-dismisses, slide-in animation.
   ========================================================= */

(function () {
    'use strict';

    let container = null;

    function getContainer() {
        if (!container) {
            container = document.getElementById('toast-container');
        }
        return container;
    }

    /**
     * Show a toast notification.
     * @param {string} message  - Text to display
     * @param {string} type     - 'success' | 'error' | 'info' (default: 'info')
     * @param {number} duration - Auto-dismiss after ms (default: 4000). 0 = no auto-dismiss.
     */
    window.showToast = function (message, type, duration) {
        type = type || 'info';
        duration = (duration === undefined) ? 4000 : duration;

        const c = getContainer();
        if (!c) return;

        const iconSVG = _iconForType(type);

        const toast = document.createElement('div');
        toast.className = 'toast toast--' + type;
        toast.setAttribute('role', 'alert');
        toast.setAttribute('aria-live', 'polite');
        toast.innerHTML =
            '<span class="toast-icon">' + iconSVG + '</span>' +
            '<span class="toast-message">' + _escapeHtml(message) + '</span>' +
            '<button class="toast-close" aria-label="Dismiss">' +
            '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round">' +
            '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>' +
            '</svg></button>';

        c.appendChild(toast);

        // Wire close button
        toast.querySelector('.toast-close').addEventListener('click', function () {
            _dismiss(toast);
        });

        // Auto-dismiss
        if (duration > 0) {
            setTimeout(function () { _dismiss(toast); }, duration);
        }

        return toast;
    };

    function _dismiss(toast) {
        if (!toast || toast._dismissing) return;
        toast._dismissing = true;
        toast.classList.add('is-hiding');
        setTimeout(function () {
            if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, 250);
    }

    function _iconForType(type) {
        if (type === 'success') {
            return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>';
        }
        if (type === 'error') {
            return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
        }
        // info
        return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>';
    }

    function _escapeHtml(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }
})();
