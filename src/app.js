import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { Dashboard } from './components/Dashboard';
import { ScanProgress } from './components/ScanProgress';
import { ReportViewer } from './components/ReportViewer';
import { RuleManager } from './components/RuleManager';
import { Settings } from './components/Settings';
const NAV_ITEMS = [
    { name: 'dashboard', label: 'Dashboard', icon: '⊞' },
    { name: 'progress', label: 'Scan Progress', icon: '◉' },
    { name: 'reports', label: 'Reports', icon: '≡' },
    { name: 'rules', label: 'Rules', icon: '◈' },
    { name: 'settings', label: 'Settings', icon: '⚙' },
];
const PROTECTED_VIEWS = new Set(['rules', 'settings']);
export class App {
    constructor(mountEl) {
        Object.defineProperty(this, "mountEl", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "unlisteners", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: []
        });
        Object.defineProperty(this, "dashboard", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "scanProgress", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "reportViewer", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "ruleManager", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "settings", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: void 0
        });
        Object.defineProperty(this, "viewContainers", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: new Map()
        });
        // Auth gate — unlocked once per session after a successful password verification.
        Object.defineProperty(this, "sessionUnlocked", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: false
        });
        Object.defineProperty(this, "pendingView", {
            enumerable: true,
            configurable: true,
            writable: true,
            value: null
        });
        this.mountEl = mountEl;
        this.dashboard = new Dashboard();
        this.scanProgress = new ScanProgress();
        this.reportViewer = new ReportViewer();
        this.ruleManager = new RuleManager();
        this.settings = new Settings();
        this.buildShell();
        this.mountComponents();
        this.registerTauriEvents();
        this.registerCustomEvents();
        this.refreshRuleCount();
        this.switchView('dashboard');
    }
    buildShell() {
        this.mountEl.innerHTML = `
      <div class="flex flex-col h-full overflow-hidden bg-surface-900">

        <!-- Top bar -->
        <header class="flex items-center justify-between px-6 py-3.5 bg-surface-800 border-b border-surface-600 flex-shrink-0">
          <div class="flex items-center gap-3">
            <div class="w-7 h-7 rounded-lg flex items-center justify-center" style="background: linear-gradient(135deg, #009efd 0%, #2af598 100%);">
              <span class="text-black text-xs font-bold">Y</span>
            </div>
            <span class="font-bold text-sm tracking-wide">
              <span class="bg-yarax-gradient bg-clip-text text-transparent">YARA-X</span>
              <span class="text-white"> KIOSK</span>
            </span>
          </div>
          <div class="flex items-center gap-2 text-xs">
            <span id="rule-status-dot" class="inline-block w-2 h-2 bg-surface-500 rounded-full transition-colors"></span>
            <span class="text-surface-500">RULES</span>
            <span id="rule-count" class="text-white font-semibold tabular-nums">—</span>
          </div>
        </header>

        <div class="flex flex-1 overflow-hidden">

          <!-- Sidebar nav -->
          <nav class="w-48 flex-shrink-0 bg-surface-800 border-r border-surface-600 flex flex-col py-4 gap-0.5">
            ${NAV_ITEMS.map(item => `
              <button
                data-view="${item.name}"
                class="nav-btn text-left flex items-center gap-3 px-4 py-2.5 mx-2 rounded-xl text-sm font-medium transition-colors text-surface-500 hover:text-white hover:bg-surface-700"
              >
                <span class="text-base leading-none opacity-70">${item.icon}</span>
                <span>${item.label}</span>
                ${PROTECTED_VIEWS.has(item.name) ? '<span data-auth-badge class="ml-auto text-surface-600 text-xs">🔒</span>' : ''}
              </button>
            `).join('')}
          </nav>

          <!-- Main content area -->
          <main id="content-area" class="flex-1 overflow-hidden bg-surface-900 relative">
            ${NAV_ITEMS.map(item => `
              <div
                id="view-${item.name}"
                class="view-panel absolute inset-0 overflow-hidden hidden"
              ></div>
            `).join('')}
          </main>

        </div>
      </div>

      <!-- Password gate modal -->
      <div id="auth-modal" class="hidden fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-sm">
        <div class="bg-surface-800 border border-surface-600 rounded-2xl p-7 w-full max-w-sm flex flex-col gap-5 shadow-2xl">
          <div class="flex items-center gap-3">
            <div class="w-9 h-9 rounded-xl bg-surface-700 flex items-center justify-center text-lg shrink-0">🔒</div>
            <div>
              <h2 class="text-white font-semibold text-base">Authentication Required</h2>
              <p id="auth-modal-desc" class="text-surface-400 text-xs mt-0.5">Enter your system password to continue.</p>
            </div>
          </div>
          <div class="flex flex-col gap-2">
            <input
              id="auth-password"
              type="password"
              placeholder="System password…"
              autocomplete="current-password"
              class="w-full bg-surface-700 border border-surface-600 rounded-xl px-4 py-2.5 text-sm text-white placeholder-surface-500 focus:outline-none focus:border-primary transition-colors"
            />
            <p id="auth-error" class="text-danger text-xs hidden">Incorrect password. Please try again.</p>
          </div>
          <div class="flex gap-3 justify-end">
            <button id="auth-cancel" class="rounded-full px-5 py-2 border border-surface-600 text-surface-400 hover:text-white text-sm font-semibold transition-colors">CANCEL</button>
            <button id="auth-submit" class="rounded-full px-5 py-2 bg-primary hover:bg-primary-hover text-black text-sm font-semibold transition-colors">UNLOCK</button>
          </div>
        </div>
      </div>
    `;
        for (const item of NAV_ITEMS) {
            const el = this.mountEl.querySelector(`#view-${item.name}`);
            if (el)
                this.viewContainers.set(item.name, el);
        }
        this.mountEl.querySelectorAll('.nav-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const view = btn.dataset['view'];
                if (!view)
                    return;
                if (PROTECTED_VIEWS.has(view) && !this.sessionUnlocked) {
                    this.showAuthModal(view);
                }
                else {
                    this.switchView(view);
                }
            });
        });
        // Auth modal wiring
        this.mountEl.querySelector('#auth-cancel')?.addEventListener('click', () => this.closeAuthModal());
        this.mountEl.querySelector('#auth-submit')?.addEventListener('click', () => this.submitAuth());
        this.mountEl.querySelector('#auth-modal')?.addEventListener('click', (e) => {
            if (e.target === e.currentTarget)
                this.closeAuthModal();
        });
        this.mountEl.querySelector('#auth-password')?.addEventListener('keydown', (e) => {
            if (e.key === 'Enter')
                this.submitAuth();
        });
    }
    mountComponents() {
        const dashContainer = this.viewContainers.get('dashboard');
        if (dashContainer)
            this.dashboard.mount(dashContainer);
        const progressContainer = this.viewContainers.get('progress');
        if (progressContainer)
            this.scanProgress.mount(progressContainer);
        const reportsContainer = this.viewContainers.get('reports');
        if (reportsContainer)
            this.reportViewer.mount(reportsContainer);
        const rulesContainer = this.viewContainers.get('rules');
        if (rulesContainer)
            this.ruleManager.mount(rulesContainer);
        const settingsContainer = this.viewContainers.get('settings');
        if (settingsContainer)
            this.settings.mount(settingsContainer);
    }
    switchView(name) {
        // Hide all panels
        for (const [, el] of this.viewContainers) {
            el.classList.add('hidden');
        }
        // Show target panel
        const target = this.viewContainers.get(name);
        if (target)
            target.classList.remove('hidden');
        // Update nav active state
        this.mountEl.querySelectorAll('.nav-btn').forEach(btn => {
            const isActive = btn.dataset['view'] === name;
            btn.classList.toggle('text-white', isActive);
            btn.classList.toggle('bg-surface-700', isActive);
            btn.classList.toggle('text-surface-500', !isActive);
        });
        // Refresh data on view switch
        if (name === 'reports') {
            this.reportViewer.refresh();
        }
        else if (name === 'rules') {
            this.ruleManager.refresh();
        }
        else if (name === 'dashboard') {
            this.dashboard.refresh();
            this.refreshRuleCount();
        }
    }
    async refreshRuleCount() {
        try {
            const stats = await invoke('get_rule_stats');
            const countEl = this.mountEl.querySelector('#rule-count');
            const dotEl = this.mountEl.querySelector('#rule-status-dot');
            if (countEl)
                countEl.textContent = stats.totalRules.toLocaleString();
            if (dotEl) {
                dotEl.classList.remove('bg-surface-500', 'bg-success', 'bg-warning');
                dotEl.classList.add(stats.totalRules > 0 ? 'bg-success' : 'bg-warning');
            }
        }
        catch (_err) {
            // Non-fatal; keep displaying dash
        }
    }
    async registerTauriEvents() {
        const unlistenUsbDetected = await listen('usb-detected', (event) => {
            const device = event.payload;
            this.dashboard.onUsbDetected(device);
            if (this.settings.getAutoStartScans()) {
                invoke('scan_usb', { mountPoint: device.mountPoint })
                    .then(scanId => {
                    this.scanProgress.startScan(scanId, device.mountPoint);
                    this.switchView('progress');
                })
                    .catch(() => { });
            }
        });
        this.unlisteners.push(unlistenUsbDetected);
        const unlistenUsbRemoved = await listen('usb-removed', (event) => {
            this.dashboard.onUsbRemoved(event.payload.mountPoint);
        });
        this.unlisteners.push(unlistenUsbRemoved);
        const unlistenScanProgress = await listen('scan-progress', (event) => {
            this.scanProgress.onProgress(event.payload);
        });
        this.unlisteners.push(unlistenScanProgress);
        const unlistenScanComplete = await listen('scan-complete', (event) => {
            this.scanProgress.onComplete(event.payload);
            this.refreshRuleCount();
        });
        this.unlisteners.push(unlistenScanComplete);
        const unlistenScanError = await listen('scan-error', (event) => {
            this.scanProgress.onError(event.payload.scanId, event.payload.error);
        });
        this.unlisteners.push(unlistenScanError);
        const unlistenFetchProgress = await listen('rule-fetch-progress', (event) => {
            this.ruleManager.onFetchProgress(event.payload);
        });
        this.unlisteners.push(unlistenFetchProgress);
        const unlistenFetchComplete = await listen('rule-fetch-complete', (event) => {
            this.ruleManager.onFetchComplete(event.payload.source, event.payload.totalRules);
            this.refreshRuleCount();
        });
        this.unlisteners.push(unlistenFetchComplete);
        const unlistenFetchError = await listen('rule-fetch-error', (event) => {
            this.ruleManager.onFetchError(event.payload.source, event.payload.error);
        });
        this.unlisteners.push(unlistenFetchError);
    }
    registerCustomEvents() {
        document.addEventListener('scan-started', (e) => {
            const detail = e.detail;
            this.scanProgress.startScan(detail.scanId, detail.targetPath);
            this.switchView('progress');
        });
        document.addEventListener('nav-switch', (e) => {
            const detail = e.detail;
            this.switchView(detail.view);
        });
        document.addEventListener('rule-stats-changed', () => {
            this.refreshRuleCount();
        });
    }
    // ── Auth gate ─────────────────────────────────────────────────────────────
    showAuthModal(targetView) {
        this.pendingView = targetView;
        const label = NAV_ITEMS.find(n => n.name === targetView)?.label ?? targetView;
        const desc = this.mountEl.querySelector('#auth-modal-desc');
        if (desc)
            desc.textContent = `Enter your system password to access ${label}.`;
        const pwd = this.mountEl.querySelector('#auth-password');
        if (pwd)
            pwd.value = '';
        const err = this.mountEl.querySelector('#auth-error');
        if (err)
            err.classList.add('hidden');
        this.mountEl.querySelector('#auth-modal')?.classList.remove('hidden');
        // Focus after the modal becomes visible
        requestAnimationFrame(() => pwd?.focus());
    }
    closeAuthModal() {
        this.mountEl.querySelector('#auth-modal')?.classList.add('hidden');
        this.pendingView = null;
    }
    async submitAuth() {
        const pwd = this.mountEl.querySelector('#auth-password');
        const password = pwd?.value ?? '';
        const submitBtn = this.mountEl.querySelector('#auth-submit');
        const err = this.mountEl.querySelector('#auth-error');
        if (!password) {
            if (pwd)
                pwd.focus();
            return;
        }
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.textContent = 'VERIFYING…';
        }
        if (err)
            err.classList.add('hidden');
        try {
            const ok = await invoke('verify_password', { password });
            if (ok) {
                this.sessionUnlocked = true;
                this.updateLockIcons();
                this.closeAuthModal();
                if (this.pendingView)
                    this.switchView(this.pendingView);
            }
            else {
                if (err)
                    err.classList.remove('hidden');
                if (pwd) {
                    pwd.value = '';
                    pwd.focus();
                }
            }
        }
        catch (e) {
            if (err) {
                err.textContent = `Auth error: ${e}`;
                err.classList.remove('hidden');
            }
        }
        finally {
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.textContent = 'UNLOCK';
            }
        }
    }
    /** Update the 🔒 badges on nav items to reflect unlock state. */
    updateLockIcons() {
        this.mountEl.querySelectorAll('.nav-btn').forEach(btn => {
            const view = btn.dataset['view'];
            if (!view || !PROTECTED_VIEWS.has(view))
                return;
            const badge = btn.querySelector('[data-auth-badge]');
            if (badge)
                badge.textContent = this.sessionUnlocked ? '🔓' : '🔒';
        });
    }
    // ── Lifecycle ─────────────────────────────────────────────────────────────
    destroy() {
        for (const fn of this.unlisteners) {
            fn();
        }
        this.unlisteners = [];
    }
}
//# sourceMappingURL=app.js.map