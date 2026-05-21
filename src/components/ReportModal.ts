import { invoke } from '@tauri-apps/api/core';
import { showToast } from '../utils/toast';

export class ReportModal {
  private overlay: HTMLDivElement | null = null;
  private escHandler: ((e: KeyboardEvent) => void) | null = null;

  // Lazily inject the overlay into <body> on first use.
  private mount(): HTMLDivElement {
    if (this.overlay) return this.overlay;

    const el = document.createElement('div');
    el.id = 'report-modal-overlay';
    el.style.display = 'none';
    el.className = 'fixed inset-0 z-50 flex flex-col bg-black/75 backdrop-blur-sm';
    el.innerHTML = `
      <div class="flex flex-col m-4 flex-1 bg-[#0a0e1a] border border-surface-600 rounded-2xl overflow-hidden shadow-2xl">
        <div class="flex items-center justify-between px-5 py-3 border-b border-surface-600 shrink-0 bg-surface-900">
          <div class="flex items-center gap-2 min-w-0">
            <span class="text-primary font-semibold text-sm shrink-0">Scan Report</span>
            <span class="text-surface-600 text-xs shrink-0">&mdash;</span>
            <span id="rmo-title" class="text-surface-400 text-xs font-mono truncate"></span>
          </div>
          <button
            id="rmo-close"
            aria-label="Close report"
            class="shrink-0 ml-4 rounded-lg p-1.5 text-surface-500 hover:text-white hover:bg-surface-700 transition-colors"
          >
            <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
        </div>

        <div class="relative flex-1 min-h-0">
          <div
            id="rmo-loading"
            class="absolute inset-0 flex items-center justify-center text-surface-500 text-sm"
          >
            Loading report…
          </div>
          <iframe
            id="rmo-frame"
            class="absolute inset-0 w-full h-full border-0 opacity-0 transition-opacity duration-200"
            sandbox="allow-scripts"
            title="Scan Report"
          ></iframe>
        </div>
      </div>
    `;

    document.body.appendChild(el);
    el.querySelector('#rmo-close')?.addEventListener('click', () => this.close());

    this.overlay = el;
    return el;
  }

  async open(reportPath: string): Promise<void> {
    const overlay = this.mount();
    const title = overlay.querySelector<HTMLElement>('#rmo-title');
    const loading = overlay.querySelector<HTMLElement>('#rmo-loading');
    const frame = overlay.querySelector<HTMLIFrameElement>('#rmo-frame');

    // Reset state before showing.
    if (title) title.textContent = reportPath.split('/').pop() ?? reportPath;
    if (loading) loading.style.display = 'flex';
    if (frame) {
      frame.removeAttribute('srcdoc');
      frame.style.opacity = '0';
    }
    overlay.style.display = 'flex';

    // Close on Escape.
    this.escHandler = (e: KeyboardEvent) => { if (e.key === 'Escape') this.close(); };
    document.addEventListener('keydown', this.escHandler);

    try {
      const html = await invoke<string>('get_report_html', { path: reportPath });

      if (frame) {
        // srcdoc assigned via JS — no HTML-encoding issues.
        frame.srcdoc = html;
        // Fade the iframe in once it has loaded.
        frame.onload = () => {
          if (loading) loading.style.display = 'none';
          frame.style.opacity = '1';
        };
      }
    } catch (err) {
      this.close();
      showToast(`Could not load report: ${err}`, 'error');
    }
  }

  close(): void {
    if (this.overlay) this.overlay.style.display = 'none';
    if (this.escHandler) {
      document.removeEventListener('keydown', this.escHandler);
      this.escHandler = null;
    }
  }
}

// Singleton — import this instance everywhere.
export const reportModal = new ReportModal();
