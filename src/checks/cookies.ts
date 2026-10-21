import { fetchChain } from "../http.js";
import { RULES, finding } from "../rules.js";
import type { CheckFn, Finding } from "../types.js";

function parseCookieName(setCookieLine: string): string {
  const eq = setCookieLine.indexOf("=");
  return eq === -1 ? setCookieLine.trim() : setCookieLine.slice(0, eq).trim();
}

/** Attribute names present on a Set-Cookie line (the part after the first ';'). */
function cookieAttributes(setCookieLine: string): Set<string> {
  return new Set(
    setCookieLine
      .split(";")
      .slice(1)
      .map((part) => part.split("=")[0].trim().toLowerCase())
  );
}

export const cookiesCheck: CheckFn = async (ctx) => {
  const findings: Finding[] = [];
  // Login flows often set cookies on a redirect, so inspect every hop.
  const chain = await fetchChain(ctx, ctx.targetUrl.toString());
  const seen = new Set<string>();

  for (const res of chain) {
    const isHttps = new URL(res.url).protocol === "https:";
    for (const raw of res.headers.getSetCookie()) {
      const name = parseCookieName(raw);
      if (seen.has(name)) continue;
      seen.add(name);

      const attrs = cookieAttributes(raw);
      const missing: string[] = [];
      if (!attrs.has("httponly")) missing.push("HttpOnly");
      if (isHttps && !attrs.has("secure")) missing.push("Secure");
      if (!attrs.has("samesite")) missing.push("SameSite");
      if (missing.length === 0) continue;

      findings.push(
        finding(RULES.cookieAttributes, {
          check: "cookies",
          severity: missing.includes("HttpOnly") || missing.includes("Secure") ? "medium" : "low",
          title: `Cookie '${name}' missing attribute(s): ${missing.join(", ")}`,
          detail: `Set-Cookie header: ${raw}`,
          recommendation:
            "Set HttpOnly on cookies that don't need JS access (mitigates XSS-based theft), Secure so cookies are only sent over HTTPS, and SameSite=Lax/Strict to reduce CSRF exposure.",
          url: res.url,
        })
      );
    }
  }

  return findings;
};
