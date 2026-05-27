import { invoke } from '@tauri-apps/api/core';
import { save } from '@tauri-apps/plugin-dialog';
import type { ScanProgress as ScanProgressEvent, ScanComplete, AppSettings } from '../types/index';
import { showToast } from '../utils/toast';
import { escapeHtml } from '../utils/escape';
import { reportModal } from './ReportModal';

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  const mins = Math.floor(ms / 60000);
  const secs = Math.floor((ms % 60000) / 1000);
  return `${mins}m ${secs}s`;
}

interface FeedEntry {
  filePath: string;
  /** Joined rule names that fired on this file, or null if the file scanned clean. */
  rules: string | null;
}

export class ScanProgress {
  private el: HTMLElement | null = null;
  private currentScanId: string | null = null;
  private matchFeedEntries: FeedEntry[] = [];
  private countdownTimer: ReturnType<typeof setInterval> | null = null;
  private static readonly MAX_FEED_ENTRIES = 50;
  private static readonly AUTO_NAV_SECONDS = 10;

  mount(container: HTMLElement): void {
    this.el = document.createElement('div');
    this.el.className = 'flex flex-col gap-8 h-full overflow-y-auto p-8';
    this.el.innerHTML = this.buildIdleHTML();
    container.appendChild(this.el);
  }

  private buildIdleHTML(): string {
    return `
      <div class="flex flex-col items-center justify-center h-64 text-surface-500 gap-4">
        <div class="w-16 h-16 rounded-full border-2 border-surface-600 flex items-center justify-center">
          <span class="text-2xl opacity-40">◈</span>
        </div>
        <p class="text-sm">No scan running. Start a scan from the Dashboard.</p>
      </div>
    `;
  }

  private buildScanHTML(targetPath: string): string {
    return `
      <div class="flex flex-col gap-2">
        <div class="flex items-center gap-2">
          <span class="inline-block w-2.5 h-2.5 bg-primary rounded-full animate-pulse"></span>
          <h2 class="text-xs font-semibold tracking-widest text-primary uppercase">Scan in Progress</h2>
        </div>
        <div class="bg-surface-800 border border-surface-600 rounded-2xl p-6 flex flex-col gap-5">
          <div class="flex flex-col gap-1">
            <div class="text-xs text-surface-500 uppercase tracking-wider font-medium">Target</div>
            <div id="scan-target" class="text-white text-sm font-mono break-all">${targetPath}</div>
          </div>

          <div class="flex flex-col gap-2">
            <div class="flex justify-between items-center text-xs">
              <span class="text-surface-500">Progress</span>
              <span id="scan-pct" class="text-primary font-semibold">0%</span>
            </div>
            <div class="w-full bg-surface-700 rounded-full h-1.5 overflow-hidden">
              <div
                id="scan-progress-bar"
                class="h-1.5 rounded-full transition-all duration-300"
                style="width: 0%; background: linear-gradient(90deg, #009efd 0%, #2af598 100%)"
              ></div>
            </div>
          </div>

          <div class="grid grid-cols-2 gap-6">
            <div class="flex flex-col gap-1">
              <div class="text-xs text-surface-500 uppercase tracking-wider font-medium">Files Scanned</div>
              <div id="scan-file-count" class="text-white font-semibold text-lg">0 / 0</div>
            </div>
            <div class="flex flex-col gap-1">
              <div class="text-xs text-surface-500 uppercase tracking-wider font-medium">Matches</div>
              <div id="scan-match-count" class="text-danger font-semibold text-lg">0</div>
            </div>
          </div>

          <div class="flex flex-col gap-1">
            <div class="text-xs text-surface-500 uppercase tracking-wider font-medium">Current File</div>
            <div id="scan-current-file" class="text-surface-500 text-xs truncate font-mono">—</div>
          </div>

          <div>
            <button
              id="cancel-scan-btn"
              class="rounded-full px-6 py-2 bg-danger hover:bg-pink-600 text-white font-semibold text-sm transition-colors"
            >
              CANCEL SCAN
            </button>
          </div>
        </div>
      </div>

      <div class="flex flex-col gap-3">
        <h2 class="text-xs font-semibold tracking-widest text-surface-500 uppercase">Live Match Feed</h2>
        <div class="bg-surface-800 border border-surface-600 rounded-2xl overflow-hidden">
          <div id="match-feed-empty" class="p-5 text-surface-500 text-xs italic">No matches yet…</div>
          <div
            id="match-feed"
            class="hidden flex-col divide-y divide-surface-600 max-h-64 overflow-y-auto"
          ></div>
        </div>
      </div>
    `;
  }

  private buildCompleteHTML(targetPath: string, complete: ScanComplete): string {
    const hasThreats = complete.matchCount > 0;
    const borderColour = hasThreats ? 'border-danger' : 'border-success';
    const statusColour = hasThreats ? 'text-danger' : 'text-success';
    const dotColour = hasThreats ? 'bg-danger' : 'bg-success';
    const statusLabel = hasThreats ? 'THREATS DETECTED' : 'SCAN CLEAN';

    const matchBadge = hasThreats
      ? `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-semibold bg-danger/20 text-danger">${complete.matchCount.toLocaleString()} threat${complete.matchCount !== 1 ? 's' : ''}</span>`
      : `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-semibold bg-success/20 text-success">Clean</span>`;

    const skippedBadge = complete.skippedFiles > 0
      ? `<div class="flex flex-col gap-1">
           <div class="text-xs text-surface-500 uppercase tracking-wider font-medium">Skipped</div>
           <div class="text-warning font-semibold text-lg">${complete.skippedFiles.toLocaleString()}</div>
         </div>`
      : '';

    const erroredBadge = complete.erroredFiles > 0
      ? `<div class="flex flex-col gap-1">
           <div class="text-xs text-surface-500 uppercase tracking-wider font-medium">Errors</div>
           <div class="text-danger font-semibold text-lg">${complete.erroredFiles.toLocaleString()}</div>
         </div>`
      : '';

    return `
      <div class="flex flex-col gap-2">
        <div class="flex items-center gap-2">
          <span class="inline-block w-2.5 h-2.5 ${dotColour} rounded-full"></span>
          <h2 class="text-xs font-semibold tracking-widest ${statusColour} uppercase">Scan Complete — ${statusLabel}</h2>
        </div>
        <div class="bg-surface-800 border ${borderColour} rounded-2xl p-6 flex flex-col gap-5">
          <div class="flex flex-col gap-1">
            <div class="text-xs text-surface-500 uppercase tracking-wider font-medium">Target</div>
            <div class="text-white text-sm font-mono break-all">${targetPath}</div>
          </div>

          <div class="grid grid-cols-3 gap-6">
            <div class="flex flex-col gap-1">
              <div class="text-xs text-surface-500 uppercase tracking-wider font-medium">Files Scanned</div>
              <div class="text-white font-semibold text-lg">${complete.filesScanned.toLocaleString()}</div>
            </div>
            <div class="flex flex-col gap-1">
              <div class="text-xs text-surface-500 uppercase tracking-wider font-medium">Matches</div>
              <div class="text-lg font-semibold">${matchBadge}</div>
            </div>
            <div class="flex flex-col gap-1">
              <div class="text-xs text-surface-500 uppercase tracking-wider font-medium">Duration</div>
              <div class="text-white font-semibold text-lg">${formatDuration(complete.durationMs)}</div>
            </div>
            ${skippedBadge}
            ${erroredBadge}
          </div>

          <div class="flex gap-3 flex-wrap">
            ${complete.reportPath ? `
              <button
                id="open-report-btn"
                class="rounded-full px-6 py-2 bg-primary hover:bg-primary-hover text-black font-semibold text-sm transition-colors"
                data-path="${escapeHtml(complete.reportPath)}"
              >
                OPEN REPORT
              </button>
              <button
                id="save-report-btn"
                class="rounded-full px-6 py-2 border border-primary text-primary hover:bg-primary/10 font-semibold text-sm transition-colors"
                data-path="${escapeHtml(complete.reportPath)}"
              >
                SAVE REPORT…
              </button>
            ` : ''}
            <button
              id="back-to-dashboard-btn"
              class="rounded-full px-6 py-2 border border-surface-600 text-surface-400 hover:text-white hover:border-primary font-semibold text-sm transition-colors"
            >
              BACK TO DASHBOARD
            </button>
          </div>

          <div id="auto-nav-countdown" class="hidden text-xs text-surface-500"></div>
        </div>
      </div>

      <div class="flex flex-col gap-3">
        <h2 class="text-xs font-semibold tracking-widest text-surface-500 uppercase">Match Feed</h2>
        <div class="bg-surface-800 border border-surface-600 rounded-2xl overflow-hidden">
          <div id="match-feed-empty" class="p-5 text-surface-500 text-xs italic ${complete.matchCount === 0 ? '' : 'hidden'}">No matches found.</div>
          <div
            id="match-feed"
            class="flex-col divide-y divide-surface-600 max-h-64 overflow-y-auto ${complete.matchCount === 0 ? 'hidden' : 'flex'}"
          ></div>
        </div>
      </div>
    `;
  }

  startScan(scanId: string, targetPath: string): void {
    this.clearCountdown();
    this.currentScanId = scanId;
    this.matchFeedEntries = [];
    if (!this.el) return;
    this.el.innerHTML = this.buildScanHTML(targetPath);
    this.bindScanEvents();
  }

  private bindScanEvents(): void {
    if (!this.el) return;

    const cancelBtn = this.el.querySelector<HTMLButtonElement>('#cancel-scan-btn');
    cancelBtn?.addEventListener('click', async () => {
      if (!this.currentScanId) return;
      try {
        await invoke('cancel_scan', { scanId: this.currentScanId });
        cancelBtn.disabled = true;
        cancelBtn.textContent = 'CANCELLING…';
        cancelBtn.classList.add('opacity-50', 'cursor-not-allowed');
      } catch (err) {
        showToast(`Could not cancel scan: ${err}`, 'error');
      }
    });
  }

  onProgress(p: ScanProgressEvent): void {
    if (!this.el || p.scanId !== this.currentScanId) return;

    const pct = p.totalFiles > 0 ? Math.round((p.filesScanned / p.totalFiles) * 100) : 0;

    const bar = this.el.querySelector<HTMLElement>('#scan-progress-bar');
    if (bar) bar.style.width = `${pct}%`;

    const pctEl = this.el.querySelector<HTMLElement>('#scan-pct');
    if (pctEl) pctEl.textContent = `${pct}%`;

    const fileCount = this.el.querySelector<HTMLElement>('#scan-file-count');
    if (fileCount) fileCount.textContent = `${p.filesScanned.toLocaleString()} / ${p.totalFiles.toLocaleString()}`;

    const matchCount = this.el.querySelector<HTMLElement>('#scan-match-count');
    if (matchCount) matchCount.textContent = p.matchCount.toLocaleString();

    const currentFile = this.el.querySelector<HTMLElement>('#scan-current-file');
    if (currentFile) {
      const truncated = p.currentFile.length > 80
        ? '…' + p.currentFile.slice(-79)
        : p.currentFile;
      currentFile.textContent = truncated || '—';
    }

    if (p.matchedRules.length > 0) {
      this.appendMatchFeedEntry(p.currentFile, p.matchedRules);
    }
  }

  private appendMatchFeedEntry(filePath: string, rules: string[]): void {
    if (!this.el) return;

    const rulesLabel = rules.length > 0 ? rules.join(', ') : null;
    this.matchFeedEntries.unshift({ filePath, rules: rulesLabel });
    if (this.matchFeedEntries.length > ScanProgress.MAX_FEED_ENTRIES) {
      this.matchFeedEntries = this.matchFeedEntries.slice(0, ScanProgress.MAX_FEED_ENTRIES);
    }

    const feedEmpty = this.el.querySelector<HTMLElement>('#match-feed-empty');
    const feed = this.el.querySelector<HTMLElement>('#match-feed');
    if (!feed || !feedEmpty) return;

    feedEmpty.classList.add('hidden');
    feed.classList.remove('hidden');
    feed.classList.add('flex');

    const entry = document.createElement('div');
    entry.className = 'px-5 py-2.5 text-xs flex items-center gap-3 hover:bg-surface-700 transition-colors';
    entry.innerHTML = `
      <span class="text-danger flex-shrink-0 text-base leading-none">▶</span>
      <div class="flex flex-col gap-0.5 min-w-0">
        <span class="text-surface-400 truncate font-mono">${escapeHtml(filePath)}</span>
        ${rulesLabel ? `<span class="text-danger/80 text-xs truncate">${escapeHtml(rulesLabel)}</span>` : ''}
      </div>
    `;

    feed.insertBefore(entry, feed.firstChild);

    while (feed.children.length > ScanProgress.MAX_FEED_ENTRIES) {
      feed.lastChild?.remove();
    }
  }

  onComplete(c: ScanComplete): void {
    if (!this.el) return;
    this.clearCountdown();
    const targetEl = this.el.querySelector<HTMLElement>('#scan-target');
    const targetPath = targetEl?.textContent ?? '';
    const savedEntries = [...this.matchFeedEntries];

    this.el.innerHTML = this.buildCompleteHTML(targetPath, c);
    this.currentScanId = null;

    const feed = this.el.querySelector<HTMLElement>('#match-feed');
    if (feed && savedEntries.length > 0) {
      for (const { filePath, rules } of savedEntries) {
        const entry = document.createElement('div');
        entry.className = 'px-5 py-2.5 text-xs flex items-center gap-3 hover:bg-surface-700 transition-colors';
        entry.innerHTML = `
          <span class="text-danger flex-shrink-0 text-base leading-none">▶</span>
          <div class="flex flex-col gap-0.5 min-w-0">
            <span class="text-surface-400 truncate font-mono">${escapeHtml(filePath)}</span>
            ${rules ? `<span class="text-danger/80 text-xs truncate">${escapeHtml(rules)}</span>` : ''}
          </div>
        `;
        feed.appendChild(entry);
      }
    }

    const openReportBtn = this.el.querySelector<HTMLButtonElement>('#open-report-btn');
    openReportBtn?.addEventListener('click', () => {
      const reportPath = openReportBtn.dataset['path'];
      if (reportPath) reportModal.open(reportPath);
    });

    const saveReportBtn = this.el.querySelector<HTMLButtonElement>('#save-report-btn');
    saveReportBtn?.addEventListener('click', () => {
      const reportPath = saveReportBtn.dataset['path'];
      if (reportPath) this.saveReportAs(reportPath);
    });

    const backBtn = this.el.querySelector<HTMLButtonElement>('#back-to-dashboard-btn');
    backBtn?.addEventListener('click', () => {
      this.clearCountdown();
      document.dispatchEvent(new CustomEvent('nav-switch', { detail: { view: 'dashboard' } }));
    });

    this.maybeStartAutoNavCountdown();
  }

  private async saveReportAs(reportPath: string): Promise<void> {
    try {
      const dest = await save({
        defaultPath: 'scan-report.html',
        filters: [{ name: 'HTML Report', extensions: ['html'] }],
      });
      if (!dest) return;
      await invoke('export_report_to_path', { reportPath, destPath: dest });
      showToast('Report saved successfully.', 'success');
    } catch (err) {
      showToast(`Failed to save report: ${err}`, 'error');
    }
  }

  private maybeStartAutoNavCountdown(): void {
    invoke<AppSettings>('get_settings').then(settings => {
      if (!settings.autoNavigateDashboard || !this.el) return;
      let remaining = ScanProgress.AUTO_NAV_SECONDS;
      const countdownEl = this.el.querySelector<HTMLElement>('#auto-nav-countdown');
      if (!countdownEl) return;
      countdownEl.classList.remove('hidden');
      countdownEl.textContent = `Navigating to Dashboard in ${remaining}s…`;

      this.countdownTimer = setInterval(() => {
        remaining -= 1;
        if (!this.el || !countdownEl.isConnected) {
          this.clearCountdown();
          return;
        }
        if (remaining <= 0) {
          this.clearCountdown();
          document.dispatchEvent(new CustomEvent('nav-switch', { detail: { view: 'dashboard' } }));
        } else {
          countdownEl.textContent = `Navigating to Dashboard in ${remaining}s…`;
        }
      }, 1000);
    }).catch(() => {});
  }

  private clearCountdown(): void {
    if (this.countdownTimer !== null) {
      clearInterval(this.countdownTimer);
      this.countdownTimer = null;
    }
  }

  onError(scanId: string, error: string): void {
    if (scanId !== this.currentScanId) return;
    this.currentScanId = null;
    this.clearCountdown();
    if (!this.el) return;

    this.el.innerHTML = `
      <div class="flex flex-col gap-4">
        <div class="flex items-center gap-2">
          <span class="inline-block w-2.5 h-2.5 bg-danger rounded-full"></span>
          <h2 class="text-xs font-semibold tracking-widest text-danger uppercase">Scan Error</h2>
        </div>
        <div class="bg-surface-800 border border-danger rounded-2xl p-6 flex flex-col gap-4">
          <div class="text-white text-sm">${escapeHtml(error)}</div>
          <div>
            <button
              id="error-back-btn"
              class="rounded-full px-6 py-2 border border-primary text-primary hover:bg-primary/10 font-semibold text-sm transition-colors"
            >
              BACK TO DASHBOARD
            </button>
          </div>
        </div>
      </div>
    `;

    const backBtn = this.el.querySelector<HTMLButtonElement>('#error-back-btn');
    backBtn?.addEventListener('click', () => {
      document.dispatchEvent(new CustomEvent('nav-switch', { detail: { view: 'dashboard' } }));
    });
  }
}
