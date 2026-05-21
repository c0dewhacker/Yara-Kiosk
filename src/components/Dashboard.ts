import { invoke } from '@tauri-apps/api/core';
import { open } from '@tauri-apps/plugin-dialog';
import type { UsbDevice, ReportEntry } from '../types/index';
import { showToast } from '../utils/toast';
import { formatBytes } from '../utils/format';
import { escapeHtml } from '../utils/escape';

export class Dashboard {
  private el: HTMLElement | null = null;
  private usbDevices: Map<string, UsbDevice> = new Map();

  mount(container: HTMLElement): void {
    this.el = document.createElement('div');
    this.el.className = 'flex flex-col gap-8 h-full overflow-y-auto p-8';
    this.el.innerHTML = this.buildHTML();
    container.appendChild(this.el);
    this.bindEvents();
    this.loadRecentActivity();
  }

  private buildHTML(): string {
    return `
      <!-- Hero strip with dot-grid texture -->
      <div class="relative rounded-2xl overflow-hidden border border-surface-600 bg-surface-800 p-6 flex flex-col gap-1">
        <div class="absolute inset-0 bg-dot-grid bg-[size:1rem_1rem] opacity-30 pointer-events-none"></div>
        <div class="relative">
          <h1 class="text-2xl font-bold tracking-tight">
            <span class="bg-yarax-gradient bg-clip-text text-transparent">YARA-X</span>
            <span class="text-white"> Security Scanner</span>
          </h1>
          <p class="text-surface-500 text-sm mt-1">Insert a USB drive or select a directory to begin scanning.</p>
        </div>
      </div>

      <!-- USB Devices -->
      <div>
        <h2 class="text-xs font-semibold tracking-widest text-surface-500 uppercase mb-3">USB Devices</h2>
        <div id="usb-devices-panel" class="bg-surface-800 border border-surface-600 rounded-2xl p-5">
          <div id="usb-empty" class="text-surface-500 text-sm flex items-center gap-3">
            <span class="text-warning opacity-70">◉</span>
            No drives detected — waiting for USB insertion…
          </div>
          <div id="usb-list" class="flex flex-col gap-3 hidden"></div>
        </div>
      </div>

      <!-- Manual Scan -->
      <div>
        <h2 class="text-xs font-semibold tracking-widest text-surface-500 uppercase mb-3">Manual Scan</h2>
        <div class="bg-surface-800 border border-surface-600 rounded-2xl p-5 flex flex-col gap-4">
          <div class="flex gap-3">
            <input
              id="manual-path-input"
              type="text"
              placeholder="/path/to/directory"
              class="flex-1 bg-surface-700 border border-surface-600 rounded-xl px-4 py-2.5 text-sm text-white placeholder-surface-500 focus:outline-none focus:border-primary transition-colors"
            />
            <button
              id="browse-btn"
              class="rounded-full px-5 py-2 border border-primary text-primary hover:bg-primary/10 font-semibold text-sm transition-colors whitespace-nowrap"
            >
              BROWSE
            </button>
          </div>
          <div>
            <button
              id="scan-dir-btn"
              class="rounded-full px-6 py-2 bg-primary hover:bg-primary-hover text-black font-semibold text-sm transition-colors"
            >
              SCAN DIRECTORY
            </button>
          </div>
        </div>
      </div>

      <!-- Recent Activity -->
      <div>
        <h2 class="text-xs font-semibold tracking-widest text-surface-500 uppercase mb-3">Recent Activity</h2>
        <div id="recent-activity" class="bg-surface-800 border border-surface-600 rounded-2xl overflow-hidden">
          <div id="activity-loading" class="p-6 text-surface-500 text-sm">Loading…</div>
          <div id="activity-empty" class="p-6 text-surface-500 text-sm hidden">No scan reports yet.</div>
          <table id="activity-table" class="w-full text-sm hidden">
            <thead>
              <tr class="border-b border-surface-600 text-xs text-surface-500 uppercase tracking-wider">
                <th class="text-left px-5 py-3">Date</th>
                <th class="text-left px-5 py-3">Target</th>
                <th class="text-right px-5 py-3">Matches</th>
                <th class="text-right px-5 py-3"></th>
              </tr>
            </thead>
            <tbody id="activity-tbody" class="divide-y divide-surface-600"></tbody>
          </table>
        </div>
      </div>
    `;
  }

  private bindEvents(): void {
    if (!this.el) return;

    const browseBtn = this.el.querySelector<HTMLButtonElement>('#browse-btn');
    browseBtn?.addEventListener('click', async () => {
      try {
        const selected = await open({ directory: true, multiple: false, title: 'Select directory to scan' });
        if (typeof selected === 'string') {
          const input = this.el?.querySelector<HTMLInputElement>('#manual-path-input');
          if (input) input.value = selected;
        }
      } catch (err) {
        showToast(`Could not open directory picker: ${err}`, 'error');
      }
    });

    const scanDirBtn = this.el.querySelector<HTMLButtonElement>('#scan-dir-btn');
    scanDirBtn?.addEventListener('click', async () => {
      const path = this.el?.querySelector<HTMLInputElement>('#manual-path-input')?.value.trim() ?? '';
      if (!path) {
        showToast('Please enter or browse to a directory path.', 'error');
        return;
      }
      await this.startPathScan(path);
    });
  }

  private async startPathScan(path: string): Promise<void> {
    try {
      const scanId = await invoke<string>('scan_path', { path });
      document.dispatchEvent(new CustomEvent('scan-started', { detail: { scanId, targetPath: path } }));
    } catch (err) {
      showToast(`Scan failed to start: ${err}`, 'error');
    }
  }

  private async startUsbScan(mountPoint: string): Promise<void> {
    try {
      const scanId = await invoke<string>('scan_usb', { mountPoint });
      document.dispatchEvent(new CustomEvent('scan-started', { detail: { scanId, targetPath: mountPoint } }));
    } catch (err) {
      showToast(`USB scan failed to start: ${err}`, 'error');
    }
  }

  onUsbDetected(device: UsbDevice): void {
    this.usbDevices.set(device.mountPoint, device);
    this.renderUsbDevices();
  }

  onUsbRemoved(mountPoint: string): void {
    this.usbDevices.delete(mountPoint);
    this.renderUsbDevices();
  }

  private renderUsbDevices(): void {
    if (!this.el) return;
    const empty = this.el.querySelector<HTMLElement>('#usb-empty');
    const list = this.el.querySelector<HTMLElement>('#usb-list');
    if (!empty || !list) return;

    if (this.usbDevices.size === 0) {
      empty.classList.remove('hidden');
      list.classList.add('hidden');
      list.innerHTML = '';
      return;
    }

    empty.classList.add('hidden');
    list.classList.remove('hidden');
    list.innerHTML = '';

    for (const device of this.usbDevices.values()) {
      const card = document.createElement('div');
      card.className = 'flex items-center justify-between bg-surface-700 border border-surface-600 rounded-xl px-5 py-4';
      card.innerHTML = `
        <div class="flex flex-col gap-1">
          <div class="flex items-center gap-2">
            <span class="inline-block w-2 h-2 bg-success rounded-full"></span>
            <span class="text-white font-semibold text-sm">${escapeHtml(device.label ?? 'Untitled Drive')}</span>
          </div>
          <div class="text-surface-500 text-xs font-mono">${escapeHtml(device.mountPoint)} · ${formatBytes(device.sizeBytes)}</div>
        </div>
        <button
          class="usb-scan-btn rounded-full px-5 py-2 bg-primary hover:bg-primary-hover text-black font-semibold text-sm transition-colors"
          data-mount="${escapeHtml(device.mountPoint)}"
        >
          SCAN THIS DRIVE
        </button>
      `;
      list.appendChild(card);
    }

    list.querySelectorAll<HTMLButtonElement>('.usb-scan-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const mountPoint = btn.dataset['mount'];
        if (mountPoint) this.startUsbScan(mountPoint);
      });
    });
  }

  async refresh(): Promise<void> {
    await this.loadRecentActivity();
  }

  private async loadRecentActivity(): Promise<void> {
    if (!this.el) return;
    const loading = this.el.querySelector<HTMLElement>('#activity-loading');
    const empty = this.el.querySelector<HTMLElement>('#activity-empty');
    const table = this.el.querySelector<HTMLElement>('#activity-table');
    const tbody = this.el.querySelector<HTMLElement>('#activity-tbody');
    if (!loading || !empty || !table || !tbody) return;

    loading.classList.remove('hidden');
    empty.classList.add('hidden');
    table.classList.add('hidden');

    try {
      const reports = await invoke<ReportEntry[]>('list_reports');
      const recent = reports.slice(0, 5);
      loading.classList.add('hidden');

      if (recent.length === 0) {
        empty.classList.remove('hidden');
        return;
      }

      tbody.innerHTML = '';
      for (const entry of recent) {
        const row = document.createElement('tr');
        row.className = 'hover:bg-surface-700 transition-colors';
        const matchBadge = entry.matchCount === 0
          ? `<span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-success/20 text-success">Clean</span>`
          : `<span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-danger/20 text-danger">${entry.matchCount} threat${entry.matchCount !== 1 ? 's' : ''}</span>`;

        row.innerHTML = `
          <td class="px-5 py-3 text-surface-500 text-xs whitespace-nowrap">${new Date(entry.createdAt).toLocaleString()}</td>
          <td class="px-5 py-3 text-white text-xs truncate max-w-xs font-mono">${escapeHtml(entry.targetPath)}</td>
          <td class="px-5 py-3 text-right">${matchBadge}</td>
          <td class="px-5 py-3 text-right">
            <button class="open-report-btn text-xs rounded-full px-3 py-1 border border-primary text-primary hover:bg-primary/10 transition-colors font-semibold" data-path="${escapeHtml(entry.reportPath)}">
              OPEN
            </button>
          </td>
        `;
        tbody.appendChild(row);
      }

      tbody.querySelectorAll<HTMLButtonElement>('.open-report-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
          e.stopPropagation();
          const reportPath = btn.dataset['path'];
          if (reportPath) {
            try {
              await invoke('open_report', { reportPath });
            } catch (err) {
              showToast(`Could not open report: ${err}`, 'error');
            }
          }
        });
      });

      table.classList.remove('hidden');
    } catch (err) {
      loading.classList.add('hidden');
      empty.classList.remove('hidden');
      showToast(`Failed to load reports: ${err}`, 'error');
    }
  }
}
