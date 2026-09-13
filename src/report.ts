import chalk from "chalk";
import type { Finding, Severity } from "./types.js";

const SEVERITY_WEIGHT: Record<Severity, number> = { info: 0, low: 2, medium: 5, high: 10 };
const SEVERITY_ORDER: Severity[] = ["high", "medium", "low", "info"];
const SEVERITY_COLOR: Record<Severity, (s: string) => string> = {
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
      console.log(`  - [${f.check}] ${f.title}`);
      console.log(`    ${chalk.dim(f.detail)}`);
      console.log(`    ${chalk.italic("Fix:")} ${f.recommendation}`);
    }
  }
  console.log("");
}

export function toJson(target: string, findings: Finding[]): string {
  const { score: s, grade } = score(findings);
  return JSON.stringify({ target, scannedAt: new Date().toISOString(), score: s, grade, findings }, null, 2);
}

export function toHtml(target: string, findings: Finding[]): string {
  const { score: s, grade } = score(findings);
  const rows = findings
    .map(
      (f) => `<tr class="sev-${f.severity}">
        <td>${f.severity.toUpperCase()}</td>
        <td>${escapeHtml(f.check)}</td>
        <td>${escapeHtml(f.title)}</td>
        <td>${escapeHtml(f.detail)}</td>
        <td>${escapeHtml(f.recommendation)}</td>
      </tr>`
    )
    .join("\n");

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WebSec Scanner Report — ${escapeHtml(target)}</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }
  h1 { font-size: 1.4rem; }
  .score { font-size: 1.1rem; margin-bottom: 1.5rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  th, td { border: 1px solid #ddd; padding: 0.5rem; text-align: left; vertical-align: top; }
  th { background: #f5f5f5; }
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
    <thead><tr><th>Severity</th><th>Check</th><th>Title</th><th>Detail</th><th>Recommendation</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="5">No issues found by the checks in this tool.</td></tr>'}</tbody>
  </table>
</body>
</html>`;
}

function escapeHtml(input: string): string {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
