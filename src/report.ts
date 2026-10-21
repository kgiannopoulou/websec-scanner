import chalk from "chalk";
import { ALL_RULES } from "./rules.js";
import type { Finding, Severity } from "./types.js";

export const VERSION = "1.1.0";

const SEVERITY_WEIGHT: Record<Severity, number> = { info: 0, low: 2, medium: 5, high: 10, critical: 25 };
const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEVERITY_COLOR: Record<Severity, (s: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow.bold,
  low: chalk.cyan,
  info: chalk.gray,
};

export function score(findings: Finding[]): { score: number; grade: string } {
  const penalty = findings.reduce((sum, f) => sum + SEVERITY_WEIGHT[f.severity], 0);
  const raw = Math.max(0, 100 - penalty);
  let grade = "A";
  if (raw < 90) grade = "B";
  if (raw < 75) grade = "C";
  if (raw < 50) grade = "D";
  if (raw < 25) grade = "F";
  return { score: raw, grade };
}

export function summary(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

export function printConsoleReport(target: string, findings: Finding[]): void {
  const { score: s, grade } = score(findings);
  console.log("\n" + chalk.bold(`WebSec Scanner report for ${target}`));
  console.log(chalk.bold(`Score: ${s}/100 (grade ${grade})\n`));

  if (findings.length === 0) {
    console.log(chalk.green("No issues found by the checks in this tool."));
    return;
  }

  for (const severity of SEVERITY_ORDER) {
    const group = findings.filter((f) => f.severity === severity);
    if (group.length === 0) continue;
    console.log(SEVERITY_COLOR[severity](`\n${severity.toUpperCase()} (${group.length})`));
    for (const f of group) {
      console.log(`  - [${f.ruleId}] ${f.title}`);
      console.log(`    ${chalk.dim(f.detail)}`);
      console.log(`    ${chalk.italic("Fix:")} ${f.recommendation}`);
      if (f.owasp) console.log(`    ${chalk.dim(`${f.owasp} · ${f.cwe?.join(", ") ?? ""}`)}`);
    }
  }
  console.log("");
}

export function toJson(target: string, findings: Finding[]): string {
  const { score: s, grade } = score(findings);
  return JSON.stringify(
    { target, scannedAt: new Date().toISOString(), score: s, grade, summary: summary(findings), findings },
    null,
    2
  );
}

const SARIF_LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

// GitHub code scanning reads this property to rank results (0.0-10.0).
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "3.0",
  info: "0.0",
};

/** SARIF 2.1.0 log, for GitHub code scanning and other SARIF viewers. */
export function toSarif(target: string, findings: Finding[]): string {
  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "websec-scanner",
            version: VERSION,
            informationUri: "https://github.com/kgiannopoulou/websec-scanner",
            rules: ALL_RULES.map((rule) => ({
              id: rule.id,
              name: rule.name.replace(/[^A-Za-z0-9]+/g, ""),
              shortDescription: { text: rule.name },
              ...(rule.references[0] ? { helpUri: rule.references[0] } : {}),
              properties: {
                tags: ["security", ...(rule.owasp ? [rule.owasp] : []), ...(rule.cwe ?? [])],
              },
            })),
          },
        },
        invocations: [{ executionSuccessful: true, endTimeUtc: new Date().toISOString() }],
        results: findings.map((f) => ({
          ruleId: f.ruleId,
          level: SARIF_LEVEL[f.severity],
          message: { text: `${f.title}. ${f.detail} Fix: ${f.recommendation}` },
          locations: [
            {
              physicalLocation: { artifactLocation: { uri: f.url ?? target } },
            },
          ],
          properties: { severity: f.severity, "security-severity": SECURITY_SEVERITY[f.severity] },
        })),
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}

export function toHtml(target: string, findings: Finding[]): string {
  const { score: s, grade } = score(findings);
  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
  const rows = sorted
    .map(
      (f) => `<tr class="sev-${f.severity}">
        <td>${f.severity.toUpperCase()}</td>
        <td><code>${escapeHtml(f.ruleId)}</code></td>
        <td>${escapeHtml(f.title)}</td>
        <td>${escapeHtml(f.detail)}</td>
        <td>${escapeHtml(f.recommendation)}</td>
        <td>${f.owasp ? escapeHtml(f.owasp) : ""}${f.cwe ? `<br>${escapeHtml(f.cwe.join(", "))}` : ""}${
          f.references?.[0] ? `<br><a href="${escapeHtml(f.references[0])}">reference</a>` : ""
        }</td>
      </tr>`
    )
    .join("\n");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WebSec Scanner Report — ${escapeHtml(target)}</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 1100px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }
  h1 { font-size: 1.4rem; }
  .score { font-size: 1.1rem; margin-bottom: 1.5rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  th, td { border: 1px solid #ddd; padding: 0.5rem; text-align: left; vertical-align: top; }
  th { background: #f5f5f5; }
  tr.sev-critical { background: #f8d0cc; }
  tr.sev-high { background: #fdecea; }
  tr.sev-medium { background: #fff8e1; }
  tr.sev-low { background: #e8f4fd; }
  tr.sev-info { background: #f5f5f5; }
</style>
</head>
<body>
  <h1>WebSec Scanner Report</h1>
  <p><strong>Target:</strong> ${escapeHtml(target)}<br>
     <strong>Scanned:</strong> ${new Date().toISOString()}</p>
  <p class="score"><strong>Score:</strong> ${s}/100 (grade ${grade})</p>
  <table>
    <thead><tr><th>Severity</th><th>Rule</th><th>Title</th><th>Detail</th><th>Recommendation</th><th>OWASP / CWE</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="6">No issues found by the checks in this tool.</td></tr>'}</tbody>
  </table>
</body>
</html>`;
}

export function escapeHtml(input: string): string {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
