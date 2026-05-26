import { invoke } from '@tauri-apps/api/core';
import type { AppSettings, AppInfo } from '../types/index';
import { showToast } from '../utils/toast';

export class Settings {
  private el: HTMLElement | null = null;
  private currentSettings: AppSettings | null = null;

  mount(container: HTMLElement): void {
    this.el = document.createElement('div');
    this.el.className = 'flex flex-col gap-8 h-full overflow-y-auto p-8';
    this.el.innerHTML = this.buildShellHTML();
    container.appendChild(this.el);
    this.bindEvents();
    this.loadSettings();
    this.loadAboutInfo();
  }

  private buildShellHTML(): string {
    return `
      <div>
        <h1 class="text-xl font-bold text-white tracking-tight">Configuration</h1>
        <p class="text-surface-500 text-sm mt-0.5">System settings for YARA-X Kiosk</p>
      </div>

      <div class="bg-surface-800 border border-surface-600 rounded-2xl divide-y divide-surface-600">

        <!-- Auto-start scans -->
        <div class="flex items-center justify-between px-6 py-5">
          <div class="flex flex-col gap-1">
            <label for="auto-start-toggle" class="text-white font-semibold text-sm cursor-pointer">
              Auto-start scan when USB inserted
            </label>
            <p class="text-surface-500 text-xs">Automatically begin scanning a USB drive when it is detected.</p>
          </div>
          <label class="relative inline-flex items-center cursor-pointer">
            <input id="auto-start-toggle" type="checkbox" class="sr-only peer" />
            <div class="w-10 h-6 bg-surface-600 rounded-full transition-colors peer-checked:bg-primary
                        after:content-[''] after:absolute after:top-0.5 after:left-0.5
                        after:w-5 after:h-5 after:bg-white after:rounded-full
                        after:transition-transform peer-checked:after:translate-x-4 relative"></div>
          </label>
        </div>

        <!-- Auto-navigate to Dashboard after scan -->
        <div class="flex items-center justify-between px-6 py-5">
          <div class="flex flex-col gap-1">
            <label for="auto-navigate-toggle" class="text-white font-semibold text-sm cursor-pointer">
              Auto-navigate to Dashboard after scan
            </label>
            <p class="text-surface-500 text-xs">Automatically return to the Dashboard 10 seconds after a scan completes.</p>
          </div>
          <label class="relative inline-flex items-center cursor-pointer">
            <input id="auto-navigate-toggle" type="checkbox" class="sr-only peer" />
            <div class="w-10 h-6 bg-surface-600 rounded-full transition-colors peer-checked:bg-primary
                        after:content-[''] after:absolute after:top-0.5 after:left-0.5
                        after:w-5 after:h-5 after:bg-white after:rounded-full
                        after:transition-transform peer-checked:after:translate-x-4 relative"></div>
          </label>
        </div>

        <!-- Max file size -->
        <div class="flex items-center justify-between px-6 py-5 gap-6">
          <div class="flex flex-col gap-1">
            <label for="max-file-size-input" class="text-white font-semibold text-sm cursor-pointer">
              Max file size (MB)
            </label>
            <p class="text-surface-500 text-xs">Files larger than this limit will be skipped during scans.</p>
          </div>
          <div class="flex items-center gap-2 flex-shrink-0">
            <input
              id="max-file-size-input"
              type="number"
              min="1"
              max="10240"
              value="100"
              class="w-24 bg-surface-700 border border-surface-600 rounded-xl px-3 py-2 text-sm text-white text-right focus:outline-none focus:border-primary transition-colors"
            />
            <span class="text-surface-500 text-xs">MB</span>
          </div>
        </div>

        <!-- Report retention -->
        <div class="flex items-center justify-between px-6 py-5 gap-6">
          <div class="flex flex-col gap-1">
            <label for="retention-days-input" class="text-white font-semibold text-sm cursor-pointer">
              Report retention (days)
            </label>
            <p class="text-surface-500 text-xs">Delete reports older than this many days on startup. Set to 0 to keep all reports.</p>
          </div>
          <div class="flex items-center gap-2 flex-shrink-0">
            <input
              id="retention-days-input"
              type="number"
              min="0"
              max="3650"
              value="0"
              class="w-24 bg-surface-700 border border-surface-600 rounded-xl px-3 py-2 text-sm text-white text-right focus:outline-none focus:border-primary transition-colors"
            />
            <span class="text-surface-500 text-xs">days</span>
          </div>
        </div>

        <!-- Rule refresh interval -->
        <div class="flex items-center justify-between px-6 py-5 gap-6">
          <div class="flex flex-col gap-1">
            <label for="refresh-interval-input" class="text-white font-semibold text-sm cursor-pointer">
              Rule auto-refresh interval (days)
            </label>
            <p class="text-surface-500 text-xs">Auto-fetch rule sources older than this many days on startup. Set to 0 to disable.</p>
          </div>
          <div class="flex items-center gap-2 flex-shrink-0">
            <input
              id="refresh-interval-input"
              type="number"
              min="0"
              max="365"
              value="0"
              class="w-24 bg-surface-700 border border-surface-600 rounded-xl px-3 py-2 text-sm text-white text-right focus:outline-none focus:border-primary transition-colors"
            />
            <span class="text-surface-500 text-xs">days</span>
          </div>
        </div>

        <!-- GTI API key -->
        <div class="flex items-start justify-between px-6 py-5 gap-6">
          <div class="flex flex-col gap-1">
            <label for="settings-gti-key" class="text-white font-semibold text-sm cursor-pointer">
              Google Threat Intelligence (GTI) API Key
            </label>
            <p class="text-surface-500 text-xs">Required to fetch GTI YARA rules. Leave blank to skip GTI integration.</p>
          </div>
          <input
            id="settings-gti-key"
            type="password"
            placeholder="API key…"
            autocomplete="off"
            class="w-72 flex-shrink-0 bg-surface-700 border border-surface-600 rounded-xl px-4 py-2.5 text-sm text-white placeholder-surface-500 focus:outline-none focus:border-primary transition-colors"
          />
        </div>

        <!-- GTI filter -->
        <div class="flex items-start justify-between px-6 py-5 gap-6">
          <div class="flex flex-col gap-1">
            <label for="settings-gti-filter" class="text-white font-semibold text-sm cursor-pointer">
              GTI Rule Filter
            </label>
            <p class="text-surface-500 text-xs">Optional filter expression applied when fetching GTI rules. Leave blank for all rules.</p>
          </div>
          <input
            id="settings-gti-filter"
            type="text"
            placeholder="e.g. tag:malware"
            autocomplete="off"
            class="w-72 flex-shrink-0 bg-surface-700 border border-surface-600 rounded-xl px-4 py-2.5 text-sm text-white placeholder-surface-500 focus:outline-none focus:border-primary transition-colors"
          />
        </div>

      </div>

      <!-- Actions -->
      <div class="flex items-center gap-4 flex-wrap">
        <button
          id="save-settings-btn"
          class="rounded-full px-6 py-2 bg-primary hover:bg-primary-hover text-black font-semibold text-sm transition-colors"
        >
          SAVE SETTINGS
        </button>
        <button
          id="reset-settings-btn"
          class="rounded-full px-6 py-2 border border-primary text-primary hover:bg-primary/10 font-semibold text-sm transition-colors"
        >
          RESET TO DEFAULTS
        </button>
        <span id="settings-status" class="text-xs text-surface-500"></span>
      </div>

      <!-- About -->
      <div class="bg-surface-800 border border-surface-600 rounded-2xl p-6">
        <h2 class="text-xs font-semibold tracking-widest text-surface-500 uppercase mb-4">About</h2>
        <div class="flex flex-col gap-2 text-sm">
          <div class="flex gap-4">
            <span class="text-surface-500 w-36">Application</span>
            <span class="text-white">YARA-X Kiosk</span>
          </div>
          <div class="flex gap-4">
            <span class="text-surface-500 w-36">Version</span>
            <span id="about-version" class="text-white">—</span>
          </div>
          <div class="flex gap-4">
            <span class="text-surface-500 w-36">Scan Engine</span>
            <span id="about-engine" class="text-white">YARA-X</span>
          </div>
          <div class="flex gap-4">
            <span class="text-surface-500 w-36">Platform</span>
            <span class="text-white">Tauri v2</span>
          </div>
          <div class="flex gap-4">
            <span class="text-surface-500 w-36">Data Directory</span>
            <span id="about-data-dir" class="text-surface-400 text-xs font-mono break-all">—</span>
          </div>
        </div>
      </div>
    `;
  }

  private bindEvents(): void {
    if (!this.el) return;

    this.el.querySelector<HTMLButtonElement>('#save-settings-btn')
      ?.addEventListener('click', () => this.saveSettings());

    this.el.querySelector<HTMLButtonElement>('#reset-settings-btn')
      ?.addEventListener('click', () => this.resetToDefaults());
  }

  private async loadSettings(): Promise<void> {
    try {
      const settings = await invoke<AppSettings>('get_settings');
      this.currentSettings = settings;
      this.applyToForm(settings);

      // Load GTI filter separately (stored per-source, not in settings).
      const gtiFilter = await invoke<string | null>('get_gti_filter').catch(() => null);
      const filterInput = this.el?.querySelector<HTMLInputElement>('#settings-gti-filter');
      if (filterInput) filterInput.value = gtiFilter ?? '';
    } catch (err) {
      showToast(`Failed to load settings: ${err}`, 'error');
    }
  }

  private async loadAboutInfo(): Promise<void> {
    try {
      const [info, dataDir] = await Promise.all([
        invoke<AppInfo>('get_app_info'),
        invoke<string>('get_data_dir'),
      ]);

      const versionEl = this.el?.querySelector<HTMLElement>('#about-version');
      if (versionEl) versionEl.textContent = info.version;

      const engineEl = this.el?.querySelector<HTMLElement>('#about-engine');
      if (engineEl) engineEl.textContent = `YARA-X ${info.yaraXVersion}`;

      const dirEl = this.el?.querySelector<HTMLElement>('#about-data-dir');
      if (dirEl) dirEl.textContent = dataDir;
    } catch {
      // Non-fatal; fields stay as "—".
    }
  }

  private applyToForm(settings: AppSettings): void {
    if (!this.el) return;

    const toggle = this.el.querySelector<HTMLInputElement>('#auto-start-toggle');
    if (toggle) toggle.checked = settings.autoStartScans;

    const navToggle = this.el.querySelector<HTMLInputElement>('#auto-navigate-toggle');
    if (navToggle) navToggle.checked = settings.autoNavigateDashboard;

    const maxSize = this.el.querySelector<HTMLInputElement>('#max-file-size-input');
    if (maxSize) maxSize.value = String(settings.maxFileSizeMb);

    const retention = this.el.querySelector<HTMLInputElement>('#retention-days-input');
    if (retention) retention.value = String(settings.reportRetentionDays);

    const refreshInterval = this.el.querySelector<HTMLInputElement>('#refresh-interval-input');
    if (refreshInterval) refreshInterval.value = String(settings.ruleRefreshIntervalDays);

    const gtiKey = this.el.querySelector<HTMLInputElement>('#settings-gti-key');
    if (gtiKey) gtiKey.value = settings.gtiApiKey ?? '';
  }

  private readFromForm(): AppSettings {
    if (!this.el) {
      return {
        autoStartScans: false,
        gtiApiKey: null,
        maxFileSizeMb: 100,
        autoNavigateDashboard: false,
        reportRetentionDays: 0,
        ruleRefreshIntervalDays: 0,
      };
    }

    const toggle = this.el.querySelector<HTMLInputElement>('#auto-start-toggle');
    const navToggle = this.el.querySelector<HTMLInputElement>('#auto-navigate-toggle');
    const maxSizeInput = this.el.querySelector<HTMLInputElement>('#max-file-size-input');
    const retentionInput = this.el.querySelector<HTMLInputElement>('#retention-days-input');
    const refreshInput = this.el.querySelector<HTMLInputElement>('#refresh-interval-input');
    const gtiKeyInput = this.el.querySelector<HTMLInputElement>('#settings-gti-key');

    const maxSize = parseInt(maxSizeInput?.value ?? '100', 10);
    const retention = parseInt(retentionInput?.value ?? '0', 10);
    const refreshInterval = parseInt(refreshInput?.value ?? '0', 10);
    const gtiKey = gtiKeyInput?.value.trim() || null;

    return {
      autoStartScans: toggle?.checked ?? false,
      gtiApiKey: gtiKey,
      maxFileSizeMb: isNaN(maxSize) || maxSize < 1 ? 100 : maxSize,
      autoNavigateDashboard: navToggle?.checked ?? false,
      reportRetentionDays: isNaN(retention) || retention < 0 ? 0 : retention,
      ruleRefreshIntervalDays: isNaN(refreshInterval) || refreshInterval < 0 ? 0 : refreshInterval,
    };
  }

  private async saveSettings(): Promise<void> {
    if (!this.el) return;

    const saveBtn = this.el.querySelector<HTMLButtonElement>('#save-settings-btn');
    const statusEl = this.el.querySelector<HTMLElement>('#settings-status');

    if (saveBtn) {
      saveBtn.disabled = true;
      saveBtn.textContent = 'SAVING…';
      saveBtn.classList.add('opacity-50', 'cursor-not-allowed');
    }
    if (statusEl) statusEl.textContent = '';

    try {
      const settings = this.readFromForm();
      const gtiFilterInput = this.el.querySelector<HTMLInputElement>('#settings-gti-filter');
      const gtiFilter = gtiFilterInput?.value.trim() || null;

      await Promise.all([
        invoke('save_settings', { settings }),
        invoke('update_gti_filter', { filter: gtiFilter }),
      ]);

      this.currentSettings = settings;

      if (statusEl) {
        statusEl.textContent = 'Saved successfully.';
        statusEl.className = 'text-xs text-success';
      }
      showToast('Settings saved.', 'success');

      setTimeout(() => {
        if (statusEl) {
          statusEl.textContent = '';
          statusEl.className = 'text-xs text-surface-500';
        }
      }, 3000);
    } catch (err) {
      if (statusEl) {
        statusEl.textContent = `Error: ${err}`;
        statusEl.className = 'text-xs text-danger';
      }
      showToast(`Failed to save settings: ${err}`, 'error');
    } finally {
      if (saveBtn) {
        saveBtn.disabled = false;
        saveBtn.textContent = 'SAVE SETTINGS';
        saveBtn.classList.remove('opacity-50', 'cursor-not-allowed');
      }
    }
  }

  private resetToDefaults(): void {
    const defaults: AppSettings = {
      autoStartScans: false,
      gtiApiKey: null,
      maxFileSizeMb: 100,
      autoNavigateDashboard: false,
      reportRetentionDays: 0,
      ruleRefreshIntervalDays: 0,
    };
    this.applyToForm(defaults);
    const filterInput = this.el?.querySelector<HTMLInputElement>('#settings-gti-filter');
    if (filterInput) filterInput.value = '';
    showToast('Form reset to defaults. Click SAVE to apply.', 'info');
  }

  getAutoStartScans(): boolean {
    return this.currentSettings?.autoStartScans ?? false;
  }
}
