import { fetchSafe } from "../http.js";
import type { CheckFn, Finding } from "../types.js";

interface HeaderRule {
  header: string;
  severity: Finding["severity"];
  recommendation: string;
  validate?: (value: string) => string | null; // returns a problem description, or null if OK
}

const RULES: HeaderRule[] = [
  {
    header: "content-security-policy",
    severity: "medium",
    recommendation:
      "Add a Content-Security-Policy header to restrict which scripts, styles, and resources the browser may load, mitigating XSS and data-injection attacks.",
  },
  {
    header: "strict-transport-security",
    severity: "high",
    recommendation:
      "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' so browsers always connect over HTTPS, preventing SSL-stripping / downgrade attacks.",
  },
  {
    header: "x-content-type-options",
    severity: "low",
    recommendation:
      "Add 'X-Content-Type-Options: nosniff' to stop browsers from MIME-sniffing responses away from the declared Content-Type.",
    validate: (v) =>
      v.toLowerCase() !== "nosniff" ? "Present but not set to 'nosniff'." : null,
  },
  {
    header: "x-frame-options",
    severity: "medium",
    recommendation:
      "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' (or a frame-ancestors CSP directive) to prevent clickjacking via iframes.",
  },
  {
    header: "referrer-policy",
    severity: "low",
    recommendation:
      "Add a 'Referrer-Policy' header (e.g. 'strict-origin-when-cross-origin') to avoid leaking full URLs to third-party sites via the Referer header.",
  },
  {
    header: "permissions-policy",
    severity: "info",
    recommendation:
      "Add a 'Permissions-Policy' header to explicitly disable browser features (camera, microphone, geolocation, etc.) your site doesn't use.",
  },
];

export const headersCheck: CheckFn = async (ctx) => {
  const findings: Finding[] = [];
  const res = await fetchSafe(ctx.targetUrl.toString(), {}, ctx.timeoutMs);

  if (!res) {
    findings.push({
      check: "headers",
      severity: "info",
      title: "Could not connect to target",
      detail: `No response received from ${ctx.targetUrl.toString()}.`,
      recommendation: "Verify the URL is reachable and try again.",
    });
    return findings;
  }

  for (const rule of RULES) {
    const value = res.headers.get(rule.header);
    if (value === null) {
      findings.push({
        check: "headers",
        severity: rule.severity,
        title: `Missing security header: ${rule.header}`,
        detail: `The response did not include a '${rule.header}' header.`,
        recommendation: rule.recommendation,
      });
      continue;
    }
    const problem = rule.validate?.(value);
    if (problem) {
      findings.push({
        check: "headers",
        severity: rule.severity,
        title: `Misconfigured header: ${rule.header}`,
        detail: `${problem} (value: '${value}')`,
        recommendation: rule.recommendation,
      });
    }
  }

  return findings;
};
