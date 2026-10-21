import { fetchSafe } from "../http.js";
import { RULES, finding } from "../rules.js";
import type { CheckFn, Finding } from "../types.js";

export const PROBE_ORIGIN = "https://evil-origin-test.example.com";

export const corsCheck: CheckFn = async (ctx) => {
  const findings: Finding[] = [];
  const res = await fetchSafe(ctx, ctx.targetUrl.toString(), { headers: { Origin: PROBE_ORIGIN } });
  if (!res) return findings;

  const allowOrigin = res.headers.get("access-control-allow-origin");
  const allowCreds = res.headers.get("access-control-allow-credentials")?.toLowerCase() === "true";

  if (allowOrigin === "*" && allowCreds) {
    findings.push(
      finding(RULES.corsWildcardCredentials, {
        check: "cors",
        severity: "high",
        title: "Dangerous CORS configuration: wildcard origin with credentials",
        detail:
          "Server sent 'Access-Control-Allow-Origin: *' together with 'Access-Control-Allow-Credentials: true', which browsers should reject — but any relaxed variant of this pattern allows any site to read authenticated responses.",
        recommendation:
          "Never combine a wildcard origin with credentialed requests. Maintain an explicit allow-list of trusted origins.",
        url: res.url,
      })
    );
  } else if (allowOrigin === PROBE_ORIGIN) {
    findings.push(
      finding(RULES.corsReflectedOrigin, {
        check: "cors",
        // Reflection only exposes authenticated data when credentials are allowed too.
        severity: allowCreds ? "high" : "medium",
        title: `CORS reflects arbitrary Origin header${allowCreds ? " (with credentials)" : ""}`,
        detail: `Server reflected an unrecognized test origin ('${PROBE_ORIGIN}') back in Access-Control-Allow-Origin.`,
        recommendation:
          "Validate the Origin header against a strict allow-list on the server instead of reflecting whatever value the client sends.",
        url: res.url,
      })
    );
  }

  return findings;
};
