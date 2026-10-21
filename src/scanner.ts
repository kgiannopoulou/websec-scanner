import { headersCheck } from "./checks/headers.js";
import { cookiesCheck } from "./checks/cookies.js";
import { tlsCheck } from "./checks/tls.js";
import { exposedFilesCheck } from "./checks/exposedFiles.js";
import { corsCheck } from "./checks/cors.js";
import { serverBannerCheck } from "./checks/serverBanner.js";
import { RULES, finding } from "./rules.js";
import { SEVERITIES, type CheckFn, type Finding, type ScanContext, type Severity } from "./types.js";

export const ALL_CHECKS: Record<string, CheckFn> = {
  headers: headersCheck,
  cookies: cookiesCheck,
  tls: tlsCheck,
  "exposed-files": exposedFilesCheck,
  cors: corsCheck,
  "info-disclosure": serverBannerCheck,
};

export const DEFAULTS = {
  timeoutMs: 8000,
  retries: 1,
  retryDelayMs: 250,
  maxRedirects: 5,
  probeDelayMs: 150,
} as const;

/** Runs every check that isn't skipped. A check that throws becomes an info finding instead of aborting the scan. */
export async function runScan(ctx: ScanContext, skip: Set<string> = new Set()): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const [name, check] of Object.entries(ALL_CHECKS)) {
    if (skip.has(name)) continue;
    try {
      findings.push(...(await check(ctx)));
    } catch (err) {
      findings.push(
        finding(RULES.scanError, {
          check: name,
          severity: "info",
          title: `Check '${name}' failed to run`,
          detail: err instanceof Error ? err.message : String(err),
          recommendation: "N/A",
        })
      );
    }
  }
  return findings;
}

export const EXIT = {
  ok: 0,
  findingsAtThreshold: 1,
  usage: 2,
  unreachable: 3,
} as const;

export type FailOn = Severity | "none";

/** Exit code for CI: 1 if any finding is at or above the --fail-on severity, else 0. */
export function exitCodeFor(findings: Finding[], failOn: FailOn): number {
  if (failOn === "none") return EXIT.ok;
  const threshold = SEVERITIES.indexOf(failOn);
  const failing = findings.some((f) => SEVERITIES.indexOf(f.severity) >= threshold);
  return failing ? EXIT.findingsAtThreshold : EXIT.ok;
}
