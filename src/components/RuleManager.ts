import { invoke } from '@tauri-apps/api/core';
import { open as pickFile, save as pickSave } from '@tauri-apps/plugin-dialog';
import type {
  AppSettings, RuleFetchProgress,
  RuleSourceConfig, RuleFile, YaraForgeTier,
} from '../types/index';
import { showToast as toast } from '../utils/toast';
import { formatBytes } from '../utils/format';
import { escapeHtml } from '../utils/escape';

// ── Virtual scroll constants ─────────────────────────────────────────────────
// Each row has py-3 (24px) + ~33px content = ~57px. Enforced via min-height.
const ROW_H = 57;
const OVERSCAN = 25;

interface EditorHandle {
  getValue(): string;
  setValue(value: string): void;
  dispose(): void;
}

export class RuleManager {
  private el: HTMLElement | null = null;
  private settings: AppSettings | null = null;
  private tab: 'sources' | 'rules' = 'sources';
  private rules: RuleFile[] = [];
  private selected = new Set<string>();
  private editPath = '';
  private editorHandle: EditorHandle | null = null;
  private static MAX_STATUS = 20;

  // Virtual scroll state
  private vs = {
    top: null as HTMLDivElement | null,
    bottom: null as HTMLDivElement | null,
    startIdx: -1,
    endIdx: -1,
  };
  private scrollRAF: number | null = null;
  private _cachedFiltered: RuleFile[] | null = null;

  mount(container: HTMLElement): void {
    this.el = document.createElement('div');
    this.el.className = 'flex flex-col h-full overflow-hidden';
    this.el.innerHTML = this.html();
    container.appendChild(this.el);
    this.wire();
    this.refresh();
  }

  private q<T extends Element>(sel: string): T | null {
    return this.el?.querySelector<T>(sel) ?? null;
  }

  // ── HTML ────────────────────────────────────────────────────────────────────

  private html(): string {
    return `
      <div class="flex items-center justify-between px-8 pt-8 pb-4 shrink-0">
        <div>
          <h1 class="text-xl font-bold text-white tracking-tight">Rule Manager</h1>
          <p class="text-surface-500 text-sm mt-0.5">Manage YARA rule sources and files</p>
        </div>
        <div class="flex gap-2">
          <button id="tab-sources" class="rounded-full px-5 py-2 text-sm font-semibold bg-primary text-black">SOURCES</button>
          <button id="tab-rules" class="rounded-full px-5 py-2 text-sm font-semibold border border-surface-600 text-surface-400 hover:text-white transition-colors">RULES</button>
        </div>
      </div>

      <div id="panel-sources" class="flex-1 overflow-y-auto px-8 pb-8 flex flex-col gap-6">
        <div class="flex items-center justify-between">
          <h2 class="text-xs font-semibold tracking-widest text-surface-500 uppercase">Rule Sources</h2>
          <button id="add-source-btn" class="rounded-full px-5 py-2 bg-primary hover:bg-primary-hover text-black font-semibold text-xs transition-colors">+ ADD SOURCE</button>
        </div>
        <div id="sources-list" class="bg-surface-800 border border-surface-600 rounded-2xl divide-y divide-surface-600">
          <div class="p-5 text-surface-500 text-xs">Loading…</div>
        </div>
        <div>
          <h2 class="text-xs font-semibold tracking-widest text-surface-500 uppercase mb-3">Google Threat Intelligence (GTI) API Key</h2>
          <div class="bg-surface-800 border border-surface-600 rounded-2xl p-5 flex gap-3">
            <input id="vt-api-key-input" type="password" placeholder="Enter GTI API key…" autocomplete="off"
              class="flex-1 bg-surface-700 border border-surface-600 rounded-xl px-4 py-2.5 text-sm text-white placeholder-surface-500 focus:outline-none focus:border-primary transition-colors" />
            <button id="save-api-key-btn" class="rounded-full px-5 py-2 bg-primary hover:bg-primary-hover text-black font-semibold text-sm transition-colors whitespace-nowrap">SAVE</button>
          </div>
        </div>
        <div>
          <h2 class="text-xs font-semibold tracking-widest text-surface-500 uppercase mb-3">Air-Gap Sync</h2>
          <div class="bg-surface-800 border border-surface-600 rounded-2xl p-5 flex flex-col gap-4">
            <div class="flex gap-3 flex-wrap">
              <button id="import-pkg-btn" class="rounded-full px-6 py-2 border border-primary text-primary hover:bg-primary/10 font-semibold text-sm transition-colors">IMPORT .ykpk</button>
              <button id="export-pkg-btn" class="rounded-full px-6 py-2 border border-primary text-primary hover:bg-primary/10 font-semibold text-sm transition-colors">EXPORT PACKAGE</button>
            </div>
            <p class="text-xs text-surface-500">Transfer rule packages via USB for air-gapped deployments.</p>
          </div>
        </div>
        <div>
          <h2 class="text-xs font-semibold tracking-widest text-surface-500 uppercase mb-3">Status</h2>
          <div class="bg-surface-800 border border-surface-600 rounded-2xl p-5">
            <div id="status-area" class="flex flex-col gap-1 max-h-44 overflow-y-auto font-mono text-xs">
              <span class="text-surface-500 italic">Ready.</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Rules panel: overflow-hidden so only the list scrolls, not the whole panel -->
      <div id="panel-rules" class="flex-1 overflow-hidden px-8 pb-8 flex-col gap-3 hidden">
        <!-- Filter bar: no longer needs sticky since the panel itself doesn't scroll -->
        <div class="flex items-center gap-3 flex-wrap shrink-0 pt-2 pb-1">
          <input id="rules-search" type="text" placeholder="Search rules…"
            class="flex-1 min-w-48 bg-surface-800 border border-surface-600 rounded-xl px-4 py-2.5 text-sm text-white placeholder-surface-500 focus:outline-none focus:border-primary" />
          <select id="rules-filter-source" class="bg-surface-800 border border-surface-600 rounded-xl px-4 py-2.5 text-sm text-white">
            <option value="">All Sources</option>
          </select>
          <select id="rules-filter-status" class="bg-surface-800 border border-surface-600 rounded-xl px-4 py-2.5 text-sm text-white">
            <option value="">All</option>
            <option value="enabled">Enabled</option>
            <option value="disabled">Disabled</option>
          </select>
          <button id="rules-refresh-btn" class="rounded-full px-5 py-2 border border-primary text-primary hover:bg-primary/10 text-sm font-semibold transition-colors">REFRESH</button>
        </div>
        <div class="flex items-center gap-3 shrink-0">
          <label class="flex items-center gap-2 text-xs text-surface-400 cursor-pointer select-none">
            <input id="select-all" type="checkbox" class="rounded accent-primary" /><span>Select All</span>
          </label>
          <button id="bulk-enable" class="rounded-full px-4 py-1.5 border border-success text-success hover:bg-success/10 text-xs font-semibold transition-colors">ENABLE</button>
          <button id="bulk-disable" class="rounded-full px-4 py-1.5 border border-warning text-warning hover:bg-warning/10 text-xs font-semibold transition-colors">DISABLE</button>
          <button id="bulk-delete" class="rounded-full px-4 py-1.5 border border-danger text-danger hover:bg-danger/10 text-xs font-semibold transition-colors">DELETE</button>
          <span id="selection-count" class="text-xs text-surface-500 ml-1"></span>
          <span id="rules-count" class="text-xs text-surface-500 ml-auto"></span>
        </div>
        <!-- Virtual-scrolled list: fills remaining height, only this element scrolls -->
        <div id="rules-list" class="bg-surface-800 border border-surface-600 rounded-2xl flex-1 overflow-y-auto min-h-0">
          <div class="p-5 text-surface-500 text-xs">Loading rules…</div>
        </div>
      </div>

      <!-- Add Source Modal -->
      <div id="modal-add" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
        <div class="bg-surface-800 border border-surface-600 rounded-2xl p-6 w-full max-w-md flex flex-col gap-4">
          <h3 class="text-white font-semibold text-base">Add Rule Source</h3>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs text-surface-400">Type</label>
            <select id="modal-kind" class="bg-surface-700 border border-surface-600 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-primary">
              <option value="yaraForge">YARA Forge</option>
              <option value="directory">Local Directory</option>
              <option value="url">Custom URL (.zip or .yar)</option>
              <option value="gti">Google Threat Intelligence (GTI)</option>
            </select>
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs text-surface-400">Name</label>
            <input id="modal-name" type="text" placeholder="My Rules…"
              class="bg-surface-700 border border-surface-600 rounded-xl px-4 py-2.5 text-sm text-white placeholder-surface-500 focus:outline-none focus:border-primary" />
          </div>
          <div id="modal-extra" class="flex flex-col gap-3"></div>
          <div class="flex gap-3 justify-end pt-1">
            <button id="modal-cancel" class="rounded-full px-5 py-2 border border-surface-600 text-surface-400 hover:text-white text-sm font-semibold transition-colors">CANCEL</button>
            <button id="modal-confirm" class="rounded-full px-5 py-2 bg-primary hover:bg-primary-hover text-black text-sm font-semibold transition-colors">ADD</button>
          </div>
        </div>
      </div>

      <!-- Rule Editor Modal -->
      <div id="editor-drawer" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-6">
        <div class="bg-surface-800 border border-surface-600 rounded-2xl w-full max-w-5xl p-6 flex flex-col gap-4" style="height:80vh;max-height:calc(100vh - 3rem)">
          <div class="flex items-center justify-between shrink-0">
            <span id="editor-filename" class="text-white font-semibold text-sm font-mono truncate max-w-xs"></span>
            <div class="flex gap-2">
              <button id="editor-clone" class="rounded-full px-4 py-1.5 border border-primary text-primary hover:bg-primary/10 text-xs font-semibold transition-colors">CLONE</button>
              <button id="editor-save" class="rounded-full px-4 py-1.5 bg-primary hover:bg-primary-hover text-black text-xs font-semibold transition-colors">SAVE</button>
              <button id="editor-close" class="rounded-full px-4 py-1.5 border border-surface-600 text-surface-400 hover:text-white text-xs font-semibold transition-colors">CLOSE</button>
            </div>
          </div>
          <div id="editor-monaco" class="flex-1 min-h-0 rounded-xl overflow-hidden border border-surface-600"></div>
        </div>
      </div>
    `;
  }

  // ── Wiring ──────────────────────────────────────────────────────────────────

  private wire(): void {
    this.q('#tab-sources')?.addEventListener('click', () => this.switchTab('sources'));
    this.q('#tab-rules')?.addEventListener('click', () => this.switchTab('rules'));

    this.q('#add-source-btn')?.addEventListener('click', () => this.openAddModal());
    this.q('#save-api-key-btn')?.addEventListener('click', () => this.saveApiKey());
    this.q('#import-pkg-btn')?.addEventListener('click', () => this.importPackage());
    this.q('#export-pkg-btn')?.addEventListener('click', () => this.exportPackage());

    this.q('#modal-kind')?.addEventListener('change', () => this.updateModalExtra());
    this.q('#modal-cancel')?.addEventListener('click', () => this.closeModal());
    this.q('#modal-confirm')?.addEventListener('click', () => this.confirmAddSource());

    this.q('#rules-refresh-btn')?.addEventListener('click', () => this.loadRules());
    this.q('#rules-search')?.addEventListener('input', () => this.renderRules());
    this.q('#rules-filter-source')?.addEventListener('change', () => this.renderRules());
    this.q('#rules-filter-status')?.addEventListener('change', () => this.renderRules());
    this.q('#select-all')?.addEventListener('change', (e) =>
      this.toggleSelectAll((e.target as HTMLInputElement).checked));
    this.q('#bulk-enable')?.addEventListener('click', () => this.bulkToggle(true));
    this.q('#bulk-disable')?.addEventListener('click', () => this.bulkToggle(false));
    this.q('#bulk-delete')?.addEventListener('click', () => this.bulkDelete());

    this.q('#editor-close')?.addEventListener('click', () => this.closeEditor());
    this.q('#editor-save')?.addEventListener('click', () => this.saveEditorContent());
    this.q('#editor-clone')?.addEventListener('click', () => this.cloneEditingFile());

    this.q('#modal-add')?.addEventListener('click', (e) => {
      if (e.target === e.currentTarget) this.closeModal();
    });
    this.q('#editor-drawer')?.addEventListener('click', (e) => {
      if (e.target === e.currentTarget) this.closeEditor();
    });

    // Virtual scroll listener — throttled via rAF
    this.q('#rules-list')?.addEventListener('scroll', () => {
      if (this.scrollRAF !== null) cancelAnimationFrame(this.scrollRAF);
      this.scrollRAF = requestAnimationFrame(() => this.renderVirtual());
    }, { passive: true });
  }

  private switchTab(tab: 'sources' | 'rules'): void {
    this.tab = tab;
    const active = 'rounded-full px-5 py-2 text-sm font-semibold bg-primary text-black';
    const idle   = 'rounded-full px-5 py-2 text-sm font-semibold border border-surface-600 text-surface-400 hover:text-white transition-colors';

    const srcBtn = this.q<HTMLButtonElement>('#tab-sources');
    const rulBtn = this.q<HTMLButtonElement>('#tab-rules');
    if (srcBtn) srcBtn.className = tab === 'sources' ? active : idle;
    if (rulBtn) rulBtn.className = tab === 'rules'   ? active : idle;

    const srcPanel = this.q('#panel-sources');
    const rulPanel = this.q('#panel-rules');
    srcPanel?.classList.toggle('hidden', tab !== 'sources');
    srcPanel?.classList.toggle('flex',   tab === 'sources');
    rulPanel?.classList.toggle('hidden', tab !== 'rules');
    rulPanel?.classList.toggle('flex',   tab === 'rules');

    if (tab === 'rules' && this.rules.length === 0) this.loadRules();
  }

  // ── Sources ──────────────────────────────────────────────────────────────────

  private async loadSources(): Promise<void> {
    const list = this.q<HTMLElement>('#sources-list');
    if (!list) return;
    try {
      const sources = await invoke<RuleSourceConfig[]>('list_sources');
      list.innerHTML = '';

      if (sources.length === 0) {
        list.innerHTML = '<div class="p-5 text-surface-500 text-xs">No rule sources configured. Click "+ ADD SOURCE" to get started.</div>';
        return;
      }

      for (const src of sources) {
        const kindLabel = this.kindLabel(src);
        const fetched = src.fetchedAt ? new Date(src.fetchedAt).toLocaleString() : 'Never fetched';
        const countHtml = src.ruleCount > 0
          ? `<span class="text-success font-semibold">${src.ruleCount.toLocaleString()}</span>`
          : '<span class="text-surface-500">0</span>';
        const canFetch = src.kind.kind !== 'directory';

        const row = document.createElement('div');
        row.className = 'flex items-center gap-4 px-5 py-4';
        row.innerHTML = `
          <label class="relative inline-flex items-center cursor-pointer shrink-0">
            <input type="checkbox" class="sr-only peer" ${src.enabled ? 'checked' : ''} />
            <div class="w-10 h-5 rounded-full bg-surface-600 peer-checked:bg-primary transition-colors after:content-[''] after:absolute after:top-0.5 after:left-0.5 after:w-4 after:h-4 after:rounded-full after:bg-white after:transition-all peer-checked:after:translate-x-5"></div>
          </label>
          <div class="flex-1 min-w-0">
            <div class="flex items-center gap-2">
              <span class="text-white font-semibold text-sm truncate">${escapeHtml(src.name)}</span>
              <span class="shrink-0 text-xs px-2 py-0.5 rounded-full bg-surface-700 text-surface-400">${kindLabel}</span>
            </div>
            <div class="text-surface-500 text-xs mt-0.5">${countHtml} rules · ${fetched}</div>
          </div>
          ${canFetch ? `<button data-action="fetch" data-id="${src.id}" class="rounded-full px-4 py-1.5 border border-primary text-primary hover:bg-primary/10 text-xs font-semibold transition-colors whitespace-nowrap">${src.fetchedAt ? 'UPDATE' : 'FETCH'}</button>` : ''}
          <button data-action="remove" data-id="${src.id}" class="rounded-full px-4 py-1.5 border border-danger text-danger hover:bg-danger/10 text-xs font-semibold transition-colors">REMOVE</button>
        `;

        row.querySelector('input[type=checkbox]')?.addEventListener('change', (e) => {
          const checked = (e.target as HTMLInputElement).checked;
          invoke('toggle_source', { id: src.id, enabled: checked })
            .then(() => {
              this.log(`${src.name} ${checked ? 'enabled' : 'disabled'}.`, 'info');
              document.dispatchEvent(new CustomEvent('rule-stats-changed'));
            })
            .catch((err: unknown) => toast(`Toggle failed: ${err}`, 'error'));
        });

        row.querySelector('[data-action="fetch"]')?.addEventListener('click', (e) => {
          this.fetchSource(src.id, src.name, e.currentTarget as HTMLButtonElement);
        });

        row.querySelector('[data-action="remove"]')?.addEventListener('click', () => {
          if (!confirm(`Remove source "${src.name}"? Its downloaded rules will be deleted.`)) return;
          invoke('remove_source', { id: src.id })
            .then(() => {
              this.log(`Source "${src.name}" removed.`, 'info');
              this.loadSources();
              document.dispatchEvent(new CustomEvent('rule-stats-changed'));
            })
            .catch((err: unknown) => toast(`Remove failed: ${err}`, 'error'));
        });

        list.appendChild(row);
      }
    } catch (err) {
      list.innerHTML = `<div class="p-5 text-danger text-xs">Failed to load sources: ${escapeHtml(String(err))}</div>`;
    }
  }

  private kindLabel(src: RuleSourceConfig): string {
    switch (src.kind.kind) {
      case 'yaraForge': return `YARA Forge (${src.kind.tier})`;
      case 'gti': return 'GTI';
      case 'directory': return 'Directory';
      case 'url': return 'URL';
      default: return 'Unknown';
    }
  }

  private async fetchSource(id: string, name: string, btn: HTMLButtonElement): Promise<void> {
    const orig = btn.textContent ?? 'FETCH';
    btn.disabled = true; btn.textContent = 'FETCHING…'; btn.classList.add('opacity-50', 'cursor-not-allowed');
    try {
      this.log(`Fetching ${name}…`, 'info');
      await invoke('fetch_source', { id });
      this.log(`${name} fetched successfully.`, 'success');
      toast(`${name} updated.`, 'success');
      this.loadSources();
    } catch (err) {
      this.log(`Fetch failed: ${err}`, 'error');
      toast(`Fetch failed: ${err}`, 'error');
    } finally {
      btn.disabled = false; btn.textContent = orig; btn.classList.remove('opacity-50', 'cursor-not-allowed');
    }
  }

  // ── Add Source Modal ─────────────────────────────────────────────────────────

  private openAddModal(): void {
    const modal = this.q<HTMLElement>('#modal-add');
    if (!modal) return;
    const nameInput = this.q<HTMLInputElement>('#modal-name');
    if (nameInput) nameInput.value = '';
    const kindSel = this.q<HTMLSelectElement>('#modal-kind');
    if (kindSel) kindSel.value = 'yaraForge';
    this.updateModalExtra();
    modal.classList.remove('hidden');
  }

  private closeModal(): void {
    this.q('#modal-add')?.classList.add('hidden');
  }

  private updateModalExtra(): void {
    const kind = this.q<HTMLSelectElement>('#modal-kind')?.value ?? 'yaraForge';
    const extra = this.q<HTMLElement>('#modal-extra');
    if (!extra) return;
    if (kind === 'yaraForge') {
      extra.innerHTML = `
        <label class="text-xs text-surface-400">Tier</label>
        <select id="modal-tier" class="bg-surface-700 border border-surface-600 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-primary">
          <option value="core">Core (~4,960 rules)</option>
          <option value="extended">Extended (~10,591 rules)</option>
          <option value="full">Full (~11,658 rules)</option>
        </select>`;
    } else if (kind === 'directory') {
      extra.innerHTML = `
        <label class="text-xs text-surface-400">Directory Path</label>
        <div class="flex gap-2">
          <input id="modal-dir-path" type="text" placeholder="/path/to/rules" readonly
            class="flex-1 bg-surface-700 border border-surface-600 rounded-xl px-4 py-2.5 text-sm text-white placeholder-surface-500 focus:outline-none focus:border-primary" />
          <button id="modal-browse" class="rounded-full px-4 py-2 border border-primary text-primary hover:bg-primary/10 text-xs font-semibold transition-colors">BROWSE</button>
        </div>`;
      this.el?.querySelector('#modal-browse')?.addEventListener('click', async () => {
        const selected = await pickFile({ directory: true, multiple: false, title: 'Select rules directory' });
        const pathInput = this.q<HTMLInputElement>('#modal-dir-path');
        if (pathInput && selected && typeof selected === 'string') pathInput.value = selected;
      });
    } else if (kind === 'url') {
      extra.innerHTML = `
        <label class="text-xs text-surface-400">URL (.zip or .yar)</label>
        <input id="modal-url" type="url" placeholder="https://…"
          class="bg-surface-700 border border-surface-600 rounded-xl px-4 py-2.5 text-sm text-white placeholder-surface-500 focus:outline-none focus:border-primary" />`;
    } else if (kind === 'gti') {
      extra.innerHTML = `
        <label class="text-xs text-surface-400">Filter (Optional)</label>
        <input id="modal-gti-filter" type="text" placeholder="e.g. name:foo or enabled:true"
          class="bg-surface-700 border border-surface-600 rounded-xl px-4 py-2.5 text-sm text-white placeholder-surface-500 focus:outline-none focus:border-primary" />
        <p class="text-xs text-surface-500 mt-1">Uses the GTI API key configured below. Leave blank to retrieve all crowdsourced rules.</p>`;
    }
  }

  private async confirmAddSource(): Promise<void> {
    const kind = this.q<HTMLSelectElement>('#modal-kind')?.value ?? 'yaraForge';
    const name = this.q<HTMLInputElement>('#modal-name')?.value.trim() ?? '';
    if (!name) { toast('Enter a source name.', 'error'); return; }

    let kindPayload: Record<string, unknown>;
    if (kind === 'yaraForge') {
      const tier = (this.q<HTMLSelectElement>('#modal-tier')?.value ?? 'core') as YaraForgeTier;
      kindPayload = { kind: 'yaraForge', tier };
    } else if (kind === 'directory') {
      const path = this.q<HTMLInputElement>('#modal-dir-path')?.value.trim() ?? '';
      if (!path) { toast('Select a directory.', 'error'); return; }
      kindPayload = { kind: 'directory', path };
    } else if (kind === 'url') {
      const url = this.q<HTMLInputElement>('#modal-url')?.value.trim() ?? '';
      if (!url) { toast('Enter a URL.', 'error'); return; }
      kindPayload = { kind: 'url', url };
    } else if (kind === 'gti') {
      const filter = this.q<HTMLInputElement>('#modal-gti-filter')?.value.trim() || null;
      kindPayload = { kind: 'gti', filter };
    } else {
      toast('Invalid source kind.', 'error');
      return;
    }

    try {
      await invoke('add_source', { name, kind: kindPayload });
      this.closeModal();
      this.log(`Source "${name}" added.`, 'success');
      toast(`Source "${name}" added.`, 'success');
      this.loadSources();
    } catch (err) {
      toast(`Failed to add source: ${err}`, 'error');
    }
  }

  // ── Rules Panel (virtual scroll) ─────────────────────────────────────────────

  private async loadRules(): Promise<void> {
    const list = this.q<HTMLElement>('#rules-list');
    if (list) list.innerHTML = '<div class="p-5 text-surface-500 text-xs">Loading…</div>';
    try {
      this.rules = await invoke<RuleFile[]>('list_rules');
      this.selected.clear();
      this._cachedFiltered = null;
      this.populateSourceFilter();
      this.setupVirtualList();
      this.renderRules();
    } catch (err) {
      if (list) list.innerHTML = `<div class="p-5 text-danger text-xs">Failed to load rules: ${escapeHtml(String(err))}</div>`;
    }
  }

  /** Initialise the two spacer anchors used by the virtual scroll engine. */
  private setupVirtualList(): void {
    const list = this.q<HTMLElement>('#rules-list');
    if (!list) return;
    list.innerHTML = '';
    list.scrollTop = 0;
    const top = document.createElement('div');
    const bottom = document.createElement('div');
    list.appendChild(top);
    list.appendChild(bottom);
    this.vs = { top, bottom, startIdx: -1, endIdx: -1 };
  }

  private populateSourceFilter(): void {
    const sel = this.q<HTMLSelectElement>('#rules-filter-source');
    if (!sel) return;
    const sources = [...new Set(this.rules.map(r => r.sourceName))].sort();
    const current = sel.value;
    sel.innerHTML = '<option value="">All Sources</option>' +
      sources.map(s => `<option value="${s}"${s === current ? ' selected' : ''}>${s}</option>`).join('');
  }

  private filteredRules(): RuleFile[] {
    if (this._cachedFiltered) return this._cachedFiltered;
    const search = (this.q<HTMLInputElement>('#rules-search')?.value ?? '').toLowerCase();
    const srcFilter = this.q<HTMLSelectElement>('#rules-filter-source')?.value ?? '';
    const statusFilter = this.q<HTMLSelectElement>('#rules-filter-status')?.value ?? '';
    this._cachedFiltered = this.rules.filter(r => {
      if (search && !r.name.toLowerCase().includes(search)) return false;
      if (srcFilter && r.sourceName !== srcFilter) return false;
      if (statusFilter === 'enabled' && !r.enabled) return false;
      if (statusFilter === 'disabled' && r.enabled) return false;
      return true;
    });
    return this._cachedFiltered;
  }

  /**
   * Called when filters change. Scrolls the list back to top and triggers
   * a full re-render. The scroll listener handles all subsequent updates.
   */
  private renderRules(): void {
    if (!this.vs.top) return;
    this._cachedFiltered = null;
    const list = this.q<HTMLElement>('#rules-list');
    if (list) list.scrollTop = 0;
    this.vs.startIdx = -1;
    this.vs.endIdx = -1;
    this.renderVirtual();
  }

  /**
   * Core virtual-scroll renderer. Calculates which rows are visible and only
   * renders those plus OVERSCAN rows on each side. Safe to call on every
   * scroll tick — it bails early when the visible window hasn't changed.
   */
  private renderVirtual(): void {
    const list = this.q<HTMLElement>('#rules-list');
    if (!list || !this.vs.top || !this.vs.bottom) return;

    const visible = this.filteredRules();
    const total = visible.length;

    // Update count label
    const countEl = this.q<HTMLElement>('#rules-count');
    if (countEl) {
      countEl.textContent = `${total.toLocaleString()} rule${total !== 1 ? 's' : ''}`;
    }

    if (total === 0) {
      this.vs.top.style.height = '0px';
      this.vs.bottom.style.height = '0px';
      this.clearRenderedRows();
      const empty = document.createElement('div');
      empty.className = 'p-5 text-surface-500 text-xs';
      empty.textContent = 'No rule files found.';
      this.vs.bottom.before(empty);
      this.updateSelectionCount();
      return;
    }

    const containerH = list.clientHeight;
    const scrollTop  = list.scrollTop;

    const startIdx = Math.max(0, Math.floor(scrollTop / ROW_H) - OVERSCAN);
    const endIdx   = Math.min(total, Math.ceil((scrollTop + containerH) / ROW_H) + OVERSCAN);

    // Always update spacer heights (they keep total scroll height correct).
    this.vs.top.style.height    = `${startIdx * ROW_H}px`;
    this.vs.bottom.style.height = `${(total - endIdx) * ROW_H}px`;

    // Only re-render rows when the window shifts.
    if (startIdx === this.vs.startIdx && endIdx === this.vs.endIdx) return;
    this.vs.startIdx = startIdx;
    this.vs.endIdx   = endIdx;

    this.clearRenderedRows();
    const frag = document.createDocumentFragment();
    for (let i = startIdx; i < endIdx; i++) {
      frag.appendChild(this.buildRuleRow(visible[i]));
    }
    this.vs.bottom.before(frag);

    this.updateSelectionCount();
    const allCb = this.q<HTMLInputElement>('#select-all');
    if (allCb) allCb.checked = total > 0 && visible.every(r => this.selected.has(r.path));
  }

  /** Remove all nodes between the two spacer anchors. */
  private clearRenderedRows(): void {
    const top    = this.vs.top;
    const bottom = this.vs.bottom;
    if (!top || !bottom || !top.parentElement) return;
    let node = top.nextSibling;
    while (node && node !== bottom) {
      const next = node.nextSibling;
      top.parentElement.removeChild(node);
      node = next;
    }
  }

  /** Build a single rule row element and attach its event listeners. */
  private buildRuleRow(rule: RuleFile): HTMLElement {
    const sizeFmt = formatBytes(rule.sizeBytes);
    const mod = rule.modifiedAt ? new Date(rule.modifiedAt).toLocaleDateString() : '—';
    const checked = this.selected.has(rule.path);

    const row = document.createElement('div');
    row.className = 'flex items-center gap-3 px-4 py-3 hover:bg-surface-700/30 transition-colors border-b border-surface-600 last:border-b-0';
    row.style.minHeight = `${ROW_H}px`;
    row.innerHTML = `
      <input type="checkbox" data-select data-path="${rule.path}" ${checked ? 'checked' : ''} class="rounded accent-primary shrink-0" />
      <div class="flex-1 min-w-0">
        <div class="flex items-center gap-2">
          <span class="text-white text-sm truncate font-medium">${rule.name}</span>
          <span class="shrink-0 text-xs px-2 py-0.5 rounded-full bg-surface-700 text-surface-500">${rule.sourceName}</span>
        </div>
        <div class="text-surface-500 text-xs mt-0.5">${sizeFmt} · ${mod}</div>
      </div>
      <label class="relative inline-flex items-center cursor-pointer shrink-0">
        <input type="checkbox" data-toggle class="sr-only peer rule-toggle" ${rule.enabled ? 'checked' : ''} />
        <div class="w-8 h-4 rounded-full bg-surface-600 peer-checked:bg-primary transition-colors after:content-[''] after:absolute after:top-0.5 after:left-0.5 after:w-3 after:h-3 after:rounded-full after:bg-white after:transition-all peer-checked:after:translate-x-4"></div>
      </label>
      <button data-action="edit" class="text-surface-400 hover:text-primary text-xs font-semibold transition-colors px-2 py-1">EDIT</button>
      <button data-action="clone" class="text-surface-400 hover:text-primary text-xs font-semibold transition-colors px-2 py-1">CLONE</button>
    `;

    row.querySelector<HTMLInputElement>('[data-select]')?.addEventListener('change', (e) => {
      const cb = e.target as HTMLInputElement;
      cb.checked ? this.selected.add(rule.path) : this.selected.delete(rule.path);
      this.updateSelectionCount();
    });

    row.querySelector<HTMLInputElement>('[data-toggle]')?.addEventListener('change', (e) => {
      const enabled = (e.target as HTMLInputElement).checked;
      invoke('toggle_rule', { path: rule.path, enabled })
        .then(() => {
          rule.enabled = enabled;
          document.dispatchEvent(new CustomEvent('rule-stats-changed'));
        })
        .catch((err: unknown) => toast(`Toggle failed: ${err}`, 'error'));
    });

    row.querySelector('[data-action="edit"]')?.addEventListener('click', () => this.openEditor(rule));

    row.querySelector('[data-action="clone"]')?.addEventListener('click', async () => {
      try {
        const cloned = await invoke<RuleFile>('clone_rule', { path: rule.path });
        toast(`Cloned as ${cloned.name}`, 'success');
        await this.loadRules();
      } catch (err) { toast(`Clone failed: ${err}`, 'error'); }
    });

    return row;
  }

  private updateSelectionCount(): void {
    const cnt = this.q<HTMLElement>('#selection-count');
    if (cnt) cnt.textContent = this.selected.size > 0 ? `${this.selected.size} selected` : '';
  }

  private toggleSelectAll(checked: boolean): void {
    const visible = this.filteredRules();
    visible.forEach(r => checked ? this.selected.add(r.path) : this.selected.delete(r.path));
    // Force re-render so checkboxes in the visible window update.
    this.vs.startIdx = -1;
    this.vs.endIdx = -1;
    this.renderVirtual();
  }

  private async bulkToggle(enabled: boolean): Promise<void> {
    if (this.selected.size === 0) { toast('Select rules first.', 'info'); return; }
    await Promise.allSettled([...this.selected].map(p => invoke('toggle_rule', { path: p, enabled })));
    toast(`${this.selected.size} rule(s) ${enabled ? 'enabled' : 'disabled'}.`, 'success');
    document.dispatchEvent(new CustomEvent('rule-stats-changed'));
    await this.loadRules();
  }

  private async bulkDelete(): Promise<void> {
    if (this.selected.size === 0) { toast('Select rules first.', 'info'); return; }
    if (!confirm(`Delete ${this.selected.size} rule file(s)? This cannot be undone.`)) return;
    await Promise.allSettled([...this.selected].map(p => invoke('delete_rule', { path: p })));
    toast(`${this.selected.size} rule(s) deleted.`, 'success');
    document.dispatchEvent(new CustomEvent('rule-stats-changed'));
    this.selected.clear();
    await this.loadRules();
  }

  // ── Editor Drawer ─────────────────────────────────────────────────────────────

  private async openEditor(rule: RuleFile): Promise<void> {
    this.editPath = rule.path;
    const filename = this.q<HTMLElement>('#editor-filename');
    if (filename) filename.textContent = rule.name;
    this.q('#editor-drawer')?.classList.remove('hidden');

    let src = '// Loading…';
    try {
      src = await invoke<string>('get_rule_content', { path: rule.path });
    } catch (err) {
      src = `// Failed to load: ${err}`;
    }

    const container = this.q<HTMLElement>('#editor-monaco');
    if (!container) return;

    if (this.editorHandle) {
      this.editorHandle.setValue(src);
    } else {
      const { createYaraEditor } = await import('../editor/yara-editor');
      this.editorHandle = await createYaraEditor(container, src);
    }
  }

  private closeEditor(): void {
    this.q('#editor-drawer')?.classList.add('hidden');
    this.editPath = '';
    // Keep the editor instance alive to avoid re-initialising Monaco on next open.
  }

  private async saveEditorContent(): Promise<void> {
    const content = this.editorHandle?.getValue() ?? '';
    try {
      await invoke('save_rule_content', { path: this.editPath, content });
      toast('Rule saved.', 'success');
      this.closeEditor();
      if (this.tab === 'rules') await this.loadRules();
    } catch (err) { toast(`Save failed: ${err}`, 'error'); }
  }

  private async cloneEditingFile(): Promise<void> {
    try {
      const cloned = await invoke<RuleFile>('clone_rule', { path: this.editPath });
      toast(`Cloned as ${cloned.name}`, 'success');
      this.closeEditor();
      if (this.tab === 'rules') await this.loadRules();
    } catch (err) { toast(`Clone failed: ${err}`, 'error'); }
  }

  // ── Settings / Packages ───────────────────────────────────────────────────────

  private async saveApiKey(): Promise<void> {
    const key = this.q<HTMLInputElement>('#vt-api-key-input')?.value.trim() ?? '';
    try {
      const s = this.settings ?? await invoke<AppSettings>('get_settings');
      const updated = { ...s, gtiApiKey: key || null };
      await invoke('save_settings', { settings: updated });
      this.settings = updated;
      this.log('API key saved.', 'success');
      toast('GTI API key saved.', 'success');
    } catch (err) { toast(`Failed to save API key: ${err}`, 'error'); }
  }

  private async importPackage(): Promise<void> {
    try {
      const sel = await pickFile({ multiple: false, filters: [{ name: 'YKPK Package', extensions: ['ykpk'] }], title: 'Select YKPK package' });
      if (!sel || typeof sel !== 'string') return;
      this.log(`Importing ${sel}…`, 'info');
      await invoke('import_rule_package', { packagePath: sel });
      this.log('Package imported.', 'success');
      toast('Rule package imported.', 'success');
      await this.loadSources();
    } catch (err) { toast(`Import failed: ${err}`, 'error'); }
  }

  private async exportPackage(): Promise<void> {
    try {
      const sel = await pickSave({ filters: [{ name: 'YKPK Package', extensions: ['ykpk'] }], title: 'Export rule package', defaultPath: 'rules.ykpk' });
      if (!sel) return;
      this.log(`Exporting to ${sel}…`, 'info');
      await invoke('export_rule_package', { outputPath: sel });
      this.log(`Exported to ${sel}.`, 'success');
      toast('Rule package exported.', 'success');
    } catch (err) { toast(`Export failed: ${err}`, 'error'); }
  }

  // ── Public API ────────────────────────────────────────────────────────────────

  async refresh(): Promise<void> {
    await Promise.all([this.loadSources(), this.loadApiKey()]);
  }

  private async loadApiKey(): Promise<void> {
    try {
      this.settings = await invoke<AppSettings>('get_settings');
      const input = this.q<HTMLInputElement>('#vt-api-key-input');
      if (input && this.settings.gtiApiKey) input.value = this.settings.gtiApiKey;
    } catch { /* non-fatal */ }
  }

  onFetchProgress(p: RuleFetchProgress): void {
    this.log(`[${p.source}] ${p.status} — ${p.rulesLoaded.toLocaleString()} rules`, 'info');
  }

  onFetchComplete(source: string, total: number): void {
    this.log(`[${source}] Fetch complete — ${total.toLocaleString()} rules.`, 'success');
    toast(`${source}: ${total.toLocaleString()} rules loaded.`, 'success');
    this.loadSources();
  }

  onFetchError(source: string, error: string): void {
    this.log(`[${source}] Error: ${error}`, 'error');
    toast(`${source} fetch error: ${error}`, 'error');
  }

  private log(msg: string, type: 'info' | 'success' | 'error'): void {
    const area = this.q<HTMLElement>('#status-area');
    if (!area) return;
    const ts = new Date().toLocaleTimeString();
    const cls = type === 'error' ? 'text-danger' : type === 'success' ? 'text-success' : 'text-surface-500';
    const line = document.createElement('div');
    line.className = cls;
    line.textContent = `[${ts}] ${msg}`;
    area.insertBefore(line, area.firstChild);
    while (area.children.length > RuleManager.MAX_STATUS) area.lastChild?.remove();
  }
}
