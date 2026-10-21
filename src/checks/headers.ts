import { fetchSafe } from "../http.js";
import { RULES, finding, type Rule } from "../rules.js";
import type { CheckFn, Finding } from "../types.js";

interface HeaderRule {
  header: string;
  rule: Rule;
  severity: Finding["severity"];
  recommendation: string;
  /** Only meaningful on HTTPS responses (browsers ignore it over plain HTTP). */
  httpsOnly?: boolean;
  /** Another header that satisfies this rule, e.g. CSP frame-ancestors for X-Frame-Options. */
  satisfiedBy?: (headers: Headers) => boolean;
  validate?: (value: string) => string | null; // returns a problem description, or null if OK
}

const HEADER_RULES: HeaderRule[] = [
  {
    header: "content-security-policy",
    rule: RULES.missingCsp,
    severity: "medium",
    recommendation:
      "Add a Content-Security-Policy header to restrict which scripts, styles, and resources the browser may load, mitigating XSS and data-injection attacks.",
  },
  {
    header: "strict-transport-security",
    rule: RULES.missingHsts,
    severity: "high",
    httpsOnly: true,
    recommendation:
      "Add 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' so browsers always connect over HTTPS, preventing SSL-stripping / downgrade attacks.",
    validate: (v) => {
      const maxAge = /max-age=(\d+)/i.exec(v);
      if (!maxAge) return "Present but has no max-age directive.";
      if (Number(maxAge[1]) < 15552000) return "max-age is shorter than 180 days.";
      return null;
    },
  },
  {
    header: "x-content-type-options",
    rule: RULES.contentTypeOptions,
    severity: "low",
    recommendation:
      "Add 'X-Content-Type-Options: nosniff' to stop browsers from MIME-sniffing responses away from the declared Content-Type.",
    validate: (v) => (v.toLowerCase() !== "nosniff" ? "Present but not set to 'nosniff'." : null),
  },
  {
    header: "x-frame-options",
    rule: RULES.missingFrameOptions,
    severity: "medium",
    satisfiedBy: (h) => /frame-ancestors/i.test(h.get("content-security-policy") ?? ""),
    recommendation:
      "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' (or a frame-ancestors CSP directive) to prevent clickjacking via iframes.",
  },
  {
    header: "referrer-policy",
    rule: RULES.missingReferrerPolicy,
    severity: "low",
    recommendation:
      "Add a 'Referrer-Policy' header (e.g. 'strict-origin-when-cross-origin') to avoid leaking full URLs to third-party sites via the Referer header.",
  },
  {
    header: "permissions-policy",
    rule: RULES.missingPermissionsPolicy,
    severity: "info",
    recommendation:
      "Add a 'Permissions-Policy' header to explicitly disable browser features (camera, microphone, geolocation, etc.) your site doesn't use.",
  },
];

export const headersCheck: CheckFn = async (ctx) => {
  const findings: Finding[] = [];
  const res = await fetchSafe(ctx, ctx.targetUrl.toString());

  if (!res) {
    findings.push(
      finding(RULES.scanError, {
        check: "headers",
        severity: "info",
        title: "Could not connect to target",
        detail: `No response received from ${ctx.targetUrl.toString()}.`,
        recommendation: "Verify the URL is reachable and try again.",
      })
    );
    return findings;
  }

  const isHttps = new URL(res.url).protocol === "https:";

  for (const rule of HEADER_RULES) {
    if (rule.httpsOnly && !isHttps) continue;
    const value = res.headers.get(rule.header);
    if (value === null) {
      if (rule.satisfiedBy?.(res.headers)) continue;
      findings.push(
        finding(rule.rule, {
          check: "headers",
          severity: rule.severity,
          title: `Missing security header: ${rule.header}`,
          detail: `The response did not include a '${rule.header}' header.`,
          recommendation: rule.recommendation,
          url: res.url,
        })
      );
      continue;
    }
    const problem = rule.validate?.(value);
    if (problem) {
      findings.push(
        finding(rule.rule, {
          check: "headers",
          severity: rule.severity,
          title: `Misconfigured header: ${rule.header}`,
          detail: `${problem} (value: '${value}')`,
          recommendation: rule.recommendation,
          url: res.url,
        })
      );
    }
  }

  return findings;
};
