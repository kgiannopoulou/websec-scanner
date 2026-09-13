import { fetchSafe } from "../http.js";
import type { CheckFn, Finding } from "../types.js";

function parseCookieName(setCookieLine: string): string {
  const eq = setCookieLine.indexOf("=");
  return eq === -1 ? setCookieLine.trim() : setCookieLine.slice(0, eq).trim();
}

export const cookiesCheck: CheckFn = async (ctx) => {
  const findings: Finding[] = [];
  const res = await fetchSafe(ctx.targetUrl.toString(), {}, ctx.timeoutMs);
  if (!res) return findings;

  // undici (Node's fetch) exposes multiple Set-Cookie headers via getSetCookie().
  const headersWithGetSetCookie = res.headers as Headers & {
    getSetCookie?: () => string[];
  };
  const rawCookies: string[] =
    typeof headersWithGetSetCookie.getSetCookie === "function"
      ? headersWithGetSetCookie.getSetCookie()
      : (() => {
          const single = res.headers.get("set-cookie");
          return single ? [single] : [];
        })();

  const isHttps = ctx.targetUrl.protocol === "https:";

  for (const raw of rawCookies) {
    const name = parseCookieName(raw);
    const lower = raw.toLowerCase();
    const missing: string[] = [];

    if (!lower.includes("httponly")) missing.push("HttpOnly");
    if (isHttps && !lower.includes("secure")) missing.push("Secure");
    if (!lower.includes("samesite")) missing.push("SameSite");

    if (missing.length > 0) {
      findings.push({
        check: "cookies",
        severity: missing.includes("HttpOnly") || missing.includes("Secure") ? "medium" : "low",
        title: `Cookie '${name}' missing attribute(s): ${missing.join(", ")}`,
        detail: `Set-Cookie header: ${raw}`,
        recommendation:
          "Set HttpOnly on cookies that don't need JS access (mitigates XSS-based theft), Secure so cookies are only sent over HTTPS, and SameSite=Lax/Strict to reduce CSRF exposure.",
      });
    }
  }

  return findings;
};
