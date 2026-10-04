export interface RuntimeInfo {
  node: string;
  undici: string | null;
  platform: string;
  arch: string;
  proxyConfigured: boolean;
  proxyEnvEnabled: boolean;
  noProxyMatch: boolean;
  systemCaSupported: boolean;
  systemCaEnabled: boolean;
  extraCaConfigured: boolean;
  extraCaExists: boolean | null;
  tlsVerificationDisabled: boolean;
}
export interface Check {
  ok: boolean | null;
  codes?: string[];
  reason?: string;
}
export interface Finding {
  code: string;
  confidence: 'confirmed' | 'likely' | 'possible' | 'unknown';
  summary: string;
  evidence: string[];
  nextSteps: string[];
}
export interface Report {
  schemaVersion: 1;
  timestamp: string;
  outcome: 'ok' | 'failed';
  request: { url: string; method: string; status?: number; durationMs?: number };
  runtime: RuntimeInfo;
  error: { codes: string[] } | null;
  checks: Record<string, Check>;
  checkDurationMs?: number;
  findings: Finding[];
}
export interface DiagnoseOptions {
  timeoutMs?: number;
  method?: 'HEAD' | 'GET';
  signal?: AbortSignal;
  compareSystemCa?: boolean;
}
export interface ExplainOptions {
  url?: string | URL;
  method?: string;
  status?: number;
  durationMs?: number;
  runtime?: RuntimeInfo;
  checks?: Record<string, Check>;
}
export function diagnose(url: string | URL, options?: DiagnoseOptions): Promise<Report>;
export function explain(error: unknown, options?: ExplainOptions): Report;
export function formatReport(report: Report, format?: 'text' | 'json' | 'markdown'): string;
export function observe(options: { onReport: (report: Report) => void | Promise<void>; includeSuccessful?: boolean }): () => void;

export interface SiteOptions extends DiagnoseOptions {
  ssh?: string;
  sshConfig?: string;
  nginxConfig?: string;
  local?: boolean;
  sudo?: boolean;
  service?: string;
  /** Last discovered unit, used if its upstream port is no longer listening. */
  discoveredService?: string;
  logs?: string[];
  includeLogs?: boolean;
  onProgress?: (message: string) => void;
}
export interface LogEntry {
  source: string;
  kind: string;
  timestamp: string | null;
  confidence: Finding['confidence'];
  correlation: 'probe' | 'site-request' | 'service' | 'time-unverified';
  code: string;
  summary: string;
  nextStep: string;
  excerpt: string;
}
export interface SiteReport {
  kind: 'site';
  schemaVersion: 1;
  timestamp: string;
  url: string;
  availability: 'up' | 'unavailable' | 'restricted';
  outcome: 'ok' | 'failed';
  complete: boolean;
  website: Report;
  server: null | {
    location: string;
    error: string | null;
    nginx: null | { installed: boolean; version: string | null; service: string; process: string; config: string; configError: string | null; siteMatched: boolean };
    app: null | { service: string; state: string; discovered: boolean };
    issues: string[];
  };
  logs: LogEntry[];
}
export function inspectSite(url: string | URL, options?: SiteOptions): Promise<SiteReport>;
export function formatSiteReport(report: SiteReport, format?: 'text' | 'json' | 'markdown', color?: boolean): string;
