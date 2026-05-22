import type { ScanProgress as ScanProgressEvent, ScanComplete } from '../types/index';
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

export class ScanProgress {
  private el: HTMLElement | null = null;
  private currentScanId: string | null = null;
  private matchFeedEntries: string[] = [];
  private static readonly MAX_FEED_ENTRIES = 50;

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
          </div>

          <div class="flex gap-3 flex-wrap">
            ${complete.reportPath ? `
              <button
                id="open-report-btn"
                class="rounded-full px-6 py-2 bg-primary hover:bg-primary-hover text-black font-semibold text-sm transition-colors"
                data-path="${complete.reportPath}"
              >
                OPEN REPORT
              </button>
            ` : ''}
            <button
              id="back-to-dashboard-btn"
              class="rounded-full px-6 py-2 border border-primary text-primary hover:bg-primary/10 font-semibold text-sm transition-colors"
            >
              BACK TO DASHBOARD
            </button>
          </div>
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

    if (p.matchCount > this.matchFeedEntries.length) {
      this.appendMatchFeedEntry(p.currentFile);
    }
  }

  private appendMatchFeedEntry(filePath: string): void {
    if (!this.el) return;

    this.matchFeedEntries.unshift(filePath);
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
      <span class="text-surface-500 truncate font-mono">${escapeHtml(filePath)}</span>
    `;

    feed.insertBefore(entry, feed.firstChild);

    while (feed.children.length > ScanProgress.MAX_FEED_ENTRIES) {
      feed.lastChild?.remove();
    }
  }

  onComplete(c: ScanComplete): void {
    if (!this.el) return;
    const targetEl = this.el.querySelector<HTMLElement>('#scan-target');
    const targetPath = targetEl?.textContent ?? '';
    const savedEntries = [...this.matchFeedEntries];

    this.el.innerHTML = this.buildCompleteHTML(targetPath, c);
    this.currentScanId = null;

    const feed = this.el.querySelector<HTMLElement>('#match-feed');
    if (feed && savedEntries.length > 0) {
      for (const filePath of savedEntries) {
        const entry = document.createElement('div');
        entry.className = 'px-5 py-2.5 text-xs flex items-center gap-3 hover:bg-surface-700 transition-colors';
        entry.innerHTML = `
          <span class="text-danger flex-shrink-0 text-base leading-none">▶</span>
          <span class="text-surface-500 truncate font-mono">${filePath}</span>
        `;
        feed.appendChild(entry);
      }
    }

    const openReportBtn = this.el.querySelector<HTMLButtonElement>('#open-report-btn');
    openReportBtn?.addEventListener('click', () => {
      const reportPath = openReportBtn.dataset['path'];
      if (reportPath) reportModal.open(reportPath);
    });

    const backBtn = this.el.querySelector<HTMLButtonElement>('#back-to-dashboard-btn');
    backBtn?.addEventListener('click', () => {
      document.dispatchEvent(new CustomEvent('nav-switch', { detail: { view: 'dashboard' } }));
    });
  }

  onError(scanId: string, error: string): void {
    if (scanId !== this.currentScanId) return;
    this.currentScanId = null;
    if (!this.el) return;

    this.el.innerHTML = `
      <div class="flex flex-col gap-4">
        <div class="flex items-center gap-2">
          <span class="inline-block w-2.5 h-2.5 bg-danger rounded-full"></span>
          <h2 class="text-xs font-semibold tracking-widest text-danger uppercase">Scan Error</h2>
        </div>
        <div class="bg-surface-800 border border-danger rounded-2xl p-6 flex flex-col gap-4">
          <div class="text-white text-sm">${error}</div>
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
