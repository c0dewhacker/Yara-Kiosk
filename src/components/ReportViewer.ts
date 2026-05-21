import { invoke } from '@tauri-apps/api/core';
import type { ReportEntry } from '../types/index';
import { showToast } from '../utils/toast';
import { escapeHtml } from '../utils/escape';

export class ReportViewer {
  private el: HTMLElement | null = null;
  private allReports: ReportEntry[] = [];
  private filterText = '';

  mount(container: HTMLElement): void {
    this.el = document.createElement('div');
    this.el.className = 'flex flex-col gap-6 h-full overflow-y-auto p-8';
    this.el.innerHTML = this.buildShellHTML();
    container.appendChild(this.el);
    this.bindEvents();
    this.loadReports();
  }

  private buildShellHTML(): string {
    return `
      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-xl font-bold text-white tracking-tight">Scan Reports</h1>
          <p class="text-surface-500 text-sm mt-0.5">History of completed YARA-X scans</p>
        </div>
        <button
          id="reports-refresh-btn"
          class="rounded-full px-5 py-2 border border-primary text-primary hover:bg-primary/10 font-semibold text-sm transition-colors"
        >
          REFRESH
        </button>
      </div>

      <div>
        <input
          id="reports-filter-input"
          type="text"
          placeholder="Filter by path or date…"
          class="w-full bg-surface-800 border border-surface-600 rounded-xl px-4 py-2.5 text-sm text-white placeholder-surface-500 focus:outline-none focus:border-primary transition-colors"
        />
      </div>

      <div class="bg-surface-800 border border-surface-600 rounded-2xl overflow-hidden flex-1">
        <div id="reports-loading" class="p-6 text-surface-500 text-sm">Loading reports…</div>
        <div id="reports-empty" class="p-6 text-surface-500 text-sm hidden">No scan reports found.</div>
        <div id="reports-no-match" class="p-6 text-surface-500 text-sm hidden">No reports match the filter.</div>
        <div class="overflow-x-auto" id="reports-table-wrap">
          <table id="reports-table" class="w-full text-sm hidden">
            <thead class="sticky top-0 bg-surface-800">
              <tr class="border-b border-surface-600 text-xs text-surface-500 uppercase tracking-wider">
                <th class="text-left px-5 py-3 font-medium">Date</th>
                <th class="text-left px-5 py-3 font-medium">Target Path</th>
                <th class="text-right px-5 py-3 font-medium">Result</th>
                <th class="text-right px-5 py-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody id="reports-tbody" class="divide-y divide-surface-600"></tbody>
          </table>
        </div>
      </div>
    `;
  }

  private bindEvents(): void {
    if (!this.el) return;

    const refreshBtn = this.el.querySelector<HTMLButtonElement>('#reports-refresh-btn');
    refreshBtn?.addEventListener('click', () => this.refresh());

    const filterInput = this.el.querySelector<HTMLInputElement>('#reports-filter-input');
    filterInput?.addEventListener('input', () => {
      this.filterText = filterInput.value.trim().toLowerCase();
      this.renderTable();
    });
  }

  async refresh(): Promise<void> {
    await this.loadReports();
  }

  private async loadReports(): Promise<void> {
    if (!this.el) return;

    const loading = this.el.querySelector<HTMLElement>('#reports-loading');
    const empty = this.el.querySelector<HTMLElement>('#reports-empty');
    const noMatch = this.el.querySelector<HTMLElement>('#reports-no-match');
    const table = this.el.querySelector<HTMLElement>('#reports-table');

    if (loading) loading.classList.remove('hidden');
    if (empty) empty.classList.add('hidden');
    if (noMatch) noMatch.classList.add('hidden');
    if (table) table.classList.add('hidden');

    try {
      this.allReports = await invoke<ReportEntry[]>('list_reports');
      if (loading) loading.classList.add('hidden');
      this.renderTable();
    } catch (err) {
      if (loading) loading.classList.add('hidden');
      if (empty) empty.classList.remove('hidden');
      showToast(`Failed to load reports: ${err}`, 'error');
    }
  }

  private renderTable(): void {
    if (!this.el) return;

    const empty = this.el.querySelector<HTMLElement>('#reports-empty');
    const noMatch = this.el.querySelector<HTMLElement>('#reports-no-match');
    const table = this.el.querySelector<HTMLElement>('#reports-table');
    const tbody = this.el.querySelector<HTMLElement>('#reports-tbody');

    if (!empty || !noMatch || !table || !tbody) return;

    if (this.allReports.length === 0) {
      empty.classList.remove('hidden');
      noMatch.classList.add('hidden');
      table.classList.add('hidden');
      return;
    }

    const filtered = this.filterText
      ? this.allReports.filter(r =>
          r.targetPath.toLowerCase().includes(this.filterText) ||
          new Date(r.createdAt).toLocaleString().toLowerCase().includes(this.filterText)
        )
      : this.allReports;

    if (filtered.length === 0) {
      empty.classList.add('hidden');
      noMatch.classList.remove('hidden');
      table.classList.add('hidden');
      return;
    }

    empty.classList.add('hidden');
    noMatch.classList.add('hidden');
    table.classList.remove('hidden');

    tbody.innerHTML = '';

    for (const entry of filtered) {
      const row = document.createElement('tr');
      row.className = 'hover:bg-surface-700 transition-colors';

      const matchBadge = entry.matchCount === 0
        ? `<span class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-success/20 text-success">Clean</span>`
        : `<span class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium bg-danger/20 text-danger">${entry.matchCount.toLocaleString()} threat${entry.matchCount !== 1 ? 's' : ''}</span>`;

      row.innerHTML = `
        <td class="px-5 py-3.5 text-surface-500 text-xs whitespace-nowrap">${new Date(entry.createdAt).toLocaleString()}</td>
        <td class="px-5 py-3.5 text-white text-xs max-w-sm">
          <div class="truncate font-mono" title="${escapeHtml(entry.targetPath)}">${escapeHtml(entry.targetPath)}</div>
        </td>
        <td class="px-5 py-3.5 text-right">${matchBadge}</td>
        <td class="px-5 py-3.5 text-right">
          <button
            class="open-report-btn text-xs rounded-full px-3 py-1 border border-primary text-primary hover:bg-primary/10 transition-colors font-semibold"
            data-path="${escapeHtml(entry.reportPath)}"
          >
            OPEN
          </button>
        </td>
      `;

      tbody.appendChild(row);
    }

    tbody.querySelectorAll<HTMLButtonElement>('.open-report-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        const reportPath = btn.dataset['path'];
        if (!reportPath) return;
        try {
          await invoke('open_report', { reportPath });
        } catch (err) {
          showToast(`Could not open report: ${err}`, 'error');
        }
      });
    });
  }
}
