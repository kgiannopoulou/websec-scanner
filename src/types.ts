export type Severity = "info" | "low" | "medium" | "high";

export interface Finding {
  check: string;
  severity: Severity;
  title: string;
  detail: string;
  recommendation: string;
}

export interface ScanContext {
  targetUrl: URL;
  timeoutMs: number;
}

export type CheckFn = (ctx: ScanContext) => Promise<Finding[]>;
