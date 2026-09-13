import { fetchSafe } from "../http.js";
import type { CheckFn, Finding } from "../types.js";

interface ProbePath {
  path: string;
  severity: Finding["severity"];
  label: string;
}

const PROBE_PATHS: ProbePath[] = [
  { path: "/.env", severity: "high", label: "Environment file (.env) — often contains secrets/DB credentials" },
  { path: "/.git/config", severity: "high", label: "Exposed .git directory — can leak full source history" },
  { path: "/.git/HEAD", severity: "high", label: "Exposed .git directory — can leak full source history" },
  { path: "/wp-config.php.bak", severity: "high", label: "WordPress config backup — may contain DB credentials" },
  { path: "/config.php.bak", severity: "medium", label: "Config backup file" },
  { path: "/backup.zip", severity: "medium", label: "Backup archive" },
  { path: "/.DS_Store", severity: "low", label: "macOS directory metadata — can reveal file/folder structure" },
  { path: "/.aws/credentials", severity: "high", label: "AWS credentials file" },
  { path: "/server-status", severity: "medium", label: "Apache server-status page — can leak internal request info" },
];

async function bodyLooksLikeRealFile(res: Response): Promise<boolean> {
  const contentType = res.headers.get("content-type") ?? "";
  if (contentType.includes("text/html")) {
    // Likely a custom error/catch-all page returning 200, not the real file.
    return false;
  }
  const text = await res.text().catch(() => "");
  return text.trim().length > 0;
}

export const exposedFilesCheck: CheckFn = async (ctx) => {
  const findings: Finding[] = [];
  const base = `${ctx.targetUrl.protocol}//${ctx.targetUrl.host}`;

  for (const probe of PROBE_PATHS) {
    const res = await fetchSafe(`${base}${probe.path}`, {}, ctx.timeoutMs);
    // Small delay between requests to stay polite to the target.
    await new Promise((r) => setTimeout(r, 150));

    if (!res || res.status !== 200) continue;
    if (!(await bodyLooksLikeRealFile(res))) continue;

    findings.push({
      check: "exposed-files",
      severity: probe.severity,
      title: `Potentially exposed file: ${probe.path}`,
      detail: `${probe.label}. Server responded 200 OK for ${probe.path}.`,
      recommendation:
        "Remove the file from the public web root, block access via server config, or add it to your deployment's exclude list. Never deploy .env, .git, or backup files into a publicly served directory.",
    });
  }

  return findings;
};
