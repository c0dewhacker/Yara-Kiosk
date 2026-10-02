import * as monaco from 'monaco-editor';
import editorWorker from 'monaco-editor/editor/editor.worker.js?worker';
import { registerYaraLanguage } from './yara-monarch';

// Must be set before any monaco.editor.create() call.
if (!('MonacoEnvironment' in globalThis)) {
  (globalThis as unknown as Record<string, unknown>).MonacoEnvironment = {
    getWorker(_: string) { return new editorWorker(); },
  };
}

let languageRegistered = false;

function ensureLanguage(): void {
  if (languageRegistered) return;
  registerYaraLanguage(monaco);
  languageRegistered = true;
}

// ── YARA validation ──────────────────────────────────────────────────────────

interface YaraError {
  line: number;
  col: number;
  message: string;
}

interface YaraCompilerInstance {
  addSource(source: string): void;
  readonly errors: string[];
  readonly warnings: string[];
  free(): void;
}

type YaraCompilerCtor = new () => YaraCompilerInstance;

// Matches yara-x error location annotations: "--> rule_0.yar:3:5"
const LOC_RE = /-->\s*[^:]+:(\d+):(\d+)/;
// Strip ANSI colour codes emitted by yara-x in some builds.
const ANSI_RE = /\x1b\[[0-9;]*m/g;

function parseErrors(raw: string[]): YaraError[] {
  return raw.map(msg => {
    const clean = msg.replace(ANSI_RE, '');
    const m = LOC_RE.exec(clean);
    const text = clean.split('\n')[0]?.replace(/^error(\[\w+\])?:\s*/, '') ?? clean;
    return {
      line: m ? parseInt(m[1], 10) : 1,
      col:  m ? parseInt(m[2], 10) : 1,
      message: text.trim(),
    };
  });
}

let initPromise: Promise<boolean> | null = null;
let CompilerCtor: YaraCompilerCtor | null = null;

function loadYaraX(): Promise<boolean> {
  if (initPromise) return initPromise;
  initPromise = (async () => {
    try {
      const mod = await import('@virustotal/yara-x');
      // Vite transforms `new URL(literal, import.meta.url)` at build time for
      // source files: it bundles the WASM as a hashed asset and rewrites the
      // expression to the final asset URL. The WASM in node_modules is NOT
      // picked up automatically, so we reference it explicitly here.
      const wasmAsset = new URL(
        '../../node_modules/@virustotal/yara-x/pkg/yara_x_js_bg.wasm',
        import.meta.url,
      );
      type InitFn = (opts: { module_or_path: URL }) => Promise<unknown>;
      await (mod.default as InitFn)({ module_or_path: wasmAsset });
      CompilerCtor = mod.Compiler as unknown as YaraCompilerCtor;
      return true;
    } catch (err) {
      // Surface the failure so a CSP block, missing WASM, or API drift is
      // visible in the dev console instead of silently turning off
      // syntax-error highlighting in the editor.
      console.error('[yara-editor] Failed to load yara-x WASM:', err);
      return false;
    }
  })();
  return initPromise;
}

async function compileErrors(content: string): Promise<YaraError[]> {
  if (!await loadYaraX() || !CompilerCtor) return [];
  const compiler = new CompilerCtor();
  try {
    try {
      compiler.addSource(content);
    } catch (addErr) {
      // addSource throws on unrecoverable parse errors; details should still
      // appear in compiler.errors. Log so a regression in that contract is
      // obvious.
      console.debug('[yara-editor] addSource threw:', addErr);
    }
    const rawErrors = compiler.errors;
    if (rawErrors.length === 0) return [];
    return parseErrors(rawErrors);
  } finally {
    compiler.free();
  }
}

// ── Marker helpers ───────────────────────────────────────────────────────────

function errorsToMarkers(
  errors: YaraError[],
  model: monaco.editor.ITextModel,
): monaco.editor.IMarkerData[] {
  return errors.map(e => ({
    severity: monaco.MarkerSeverity.Error,
    message: e.message,
    startLineNumber: e.line,
    startColumn: e.col,
    endLineNumber: e.line,
    endColumn: model.getLineMaxColumn(Math.min(e.line, model.getLineCount())),
  }));
}

async function validateModel(model: monaco.editor.ITextModel): Promise<void> {
  if (model.isDisposed()) return;
  const errors = await compileErrors(model.getValue());
  if (model.isDisposed()) return;
  monaco.editor.setModelMarkers(model, 'yara', errorsToMarkers(errors, model));
}

// ── Public API ───────────────────────────────────────────────────────────────

export interface EditorHandle {
  getValue(): string;
  setValue(value: string): void;
  dispose(): void;
}

export async function createYaraEditor(
  container: HTMLElement,
  initialValue: string,
): Promise<EditorHandle> {
  ensureLanguage();

  const editor = monaco.editor.create(container, {
    value: initialValue,
    language: 'yara',
    theme: 'yara-dark',
    fontSize: 13,
    fontFamily: "'Fira Code', 'Cascadia Code', 'JetBrains Mono', 'Consolas', monospace",
    minimap: { enabled: false },
    scrollBeyondLastLine: false,
    automaticLayout: true,
    lineNumbers: 'on',
    renderLineHighlight: 'line',
    scrollbar: { vertical: 'auto', horizontal: 'auto' },
    wordWrap: 'off',
    tabSize: 2,
    insertSpaces: true,
    folding: true,
    bracketPairColorization: { enabled: true },
    padding: { top: 8, bottom: 8 },
  });

  const model = editor.getModel();
  let debounce: ReturnType<typeof setTimeout> | null = null;

  if (model) {
    model.onDidChangeContent(() => {
      if (debounce) clearTimeout(debounce);
      debounce = setTimeout(() => void validateModel(model), 600);
    });
    void validateModel(model);
  }

  return {
    getValue: () => editor.getValue(),
    setValue(v: string) {
      const m = editor.getModel();
      if (m) m.setValue(v);
    },
    dispose() {
      if (debounce) clearTimeout(debounce);
      const m = editor.getModel();
      if (m && !m.isDisposed()) monaco.editor.setModelMarkers(m, 'yara', []);
      editor.dispose();
    },
  };
}
