import { fetchSafe } from "../http.js";
import { RULES, finding } from "../rules.js";
import type { CheckFn, Finding } from "../types.js";

interface ProbePath {
  path: string;
  severity: Finding["severity"];
  label: string;
  /** Content the real file would contain; avoids false positives from catch-all 200 pages. */
  signature?: RegExp;
}

export const PROBE_PATHS: ProbePath[] = [
  { path: "/.env", severity: "critical", label: "Environment file (.env) — often contains secrets/DB credentials", signature: /^\s*[A-Z_][A-Z0-9_]*\s*=/m },
  { path: "/.git/config", severity: "critical", label: "Exposed .git directory — can leak full source history", signature: /\[core\]/ },
  { path: "/.git/HEAD", severity: "critical", label: "Exposed .git directory — can leak full source history", signature: /^ref: refs\// },
  { path: "/.aws/credentials", severity: "critical", label: "AWS credentials file", signature: /aws_access_key_id/i },
  { path: "/wp-config.php.bak", severity: "high", label: "WordPress config backup — may contain DB credentials", signature: /DB_PASSWORD|DB_NAME/ },
  { path: "/config.php.bak", severity: "medium", label: "Config backup file" },
  { path: "/backup.zip", severity: "medium", label: "Backup archive" },
  { path: "/.DS_Store", severity: "low", label: "macOS directory metadata — can reveal file/folder structure" },
  { path: "/server-status", severity: "medium", label: "Apache server-status page — can leak internal request info", signature: /Apache Server Status/i },
];

async function bodyLooksLikeRealFile(res: Response, probe: ProbePath): Promise<boolean> {
  const contentType = res.headers.get("content-type") ?? "";
  // server-status is legitimately HTML; for anything else an HTML body is a catch-all/error page.
  if (contentType.includes("text/html") && probe.path !== "/server-status") return false;
  const text = await res.text().catch(() => "");
  if (text.trim().length === 0) return false;
  return probe.signature ? probe.signature.test(text) : true;
}

export const exposedFilesCheck: CheckFn = async (ctx) => {
  const findings: Finding[] = [];
  const base = `${ctx.targetUrl.protocol}//${ctx.targetUrl.host}`;
  // A redirect away from /.env is not the file, so probes never follow redirects.
  const probeCtx = { ...ctx, maxRedirects: 0 };

  for (const [i, probe] of PROBE_PATHS.entries()) {
    if (i > 0 && ctx.probeDelayMs > 0) await new Promise((r) => setTimeout(r, ctx.probeDelayMs));
    const res = await fetchSafe(probeCtx, `${base}${probe.path}`);
    if (!res || res.status !== 200) continue;
    if (!(await bodyLooksLikeRealFile(res, probe))) continue;

    findings.push(
      finding(RULES.exposedFile, {
        check: "exposed-files",
        severity: probe.severity,
        title: `Potentially exposed file: ${probe.path}`,
        detail: `${probe.label}. Server responded 200 OK for ${probe.path}.`,
        recommendation:
          "Remove the file from the public web root, block access via server config, or add it to your deployment's exclude list. Never deploy .env, .git, or backup files into a publicly served directory.",
        url: `${base}${probe.path}`,
      })
    );
  }

  return findings;
};
