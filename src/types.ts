export type Severity = "info" | "low" | "medium" | "high" | "critical";

export const SEVERITIES: Severity[] = ["info", "low", "medium", "high", "critical"];

export interface Finding {
  /** Stable rule identifier from the catalog in rules.ts, e.g. "WSS-HDR-001". */
  ruleId: string;
  check: string;
  severity: Severity;
  title: string;
  detail: string;
  recommendation: string;
  /** OWASP Top 10 (2021) category, e.g. "A05:2021 Security Misconfiguration". */
  owasp?: string;
  cwe?: string[];
  references?: string[];
  /** URL the evidence came from (after redirects). */
  url?: string;
}

export interface ScanContext {
  targetUrl: URL;
  timeoutMs: number;
  /** Extra attempts after a network error, timeout or 502/503/504/429. */
  retries: number;
  retryDelayMs: number;
  maxRedirects: number;
  /** Host patterns the scanner may send requests to ("example.com", "*.example.com"). */
  scope: string[];
  /** Pause between exposed-file probes, to stay polite to the target. */
  probeDelayMs: number;
}

export type CheckFn = (ctx: ScanContext) => Promise<Finding[]>;
