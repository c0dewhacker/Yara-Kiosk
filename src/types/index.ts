export interface AppSettings {
  autoStartScans: boolean;
  gtiApiKey: string | null;
  maxFileSizeMb: number;
}

export interface RuleStats {
  totalRules: number;
  lastUpdated: string | null;
}

export interface ReportEntry {
  scanId: string;
  targetPath: string;
  createdAt: string;
  matchCount: number;
  reportPath: string;
}

export interface UsbDevice {
  mountPoint: string;
  label: string | null;
  sizeBytes: number;
}

export interface ScanProgress {
  scanId: string;
  filesScanned: number;
  totalFiles: number;
  matchCount: number;
  currentFile: string;
}

export interface ScanComplete {
  scanId: string;
  reportPath: string;
  matchCount: number;
  filesScanned: number;
  durationMs: number;
}

export interface RuleFetchProgress {
  source: string;
  rulesLoaded: number;
  status: string;
}

export type YaraForgeTier = 'core' | 'extended' | 'full';

export type SourceKind =
  | { kind: 'yaraForge'; tier: YaraForgeTier }
  | { kind: 'gti'; filter: string | null }
  | { kind: 'directory'; path: string }
  | { kind: 'url'; url: string };

export interface RuleSourceConfig {
  id: string;
  name: string;
  kind: SourceKind;
  enabled: boolean;
  ruleCount: number;
  fetchedAt: string | null;
}

export interface RuleFile {
  path: string;
  sourceId: string;
  sourceName: string;
  name: string;
  enabled: boolean;
  sizeBytes: number;
  modifiedAt: string | null;
}
