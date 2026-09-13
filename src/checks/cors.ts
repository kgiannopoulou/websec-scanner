import { fetchSafe } from "../http.js";
import type { CheckFn, Finding } from "../types.js";

const PROBE_ORIGIN = "https://evil-origin-test.example.com";

export const corsCheck: CheckFn = async (ctx) => {
  const findings: Finding[] = [];
  const res = await fetchSafe(
    ctx.targetUrl.toString(),
    { headers: { Origin: PROBE_ORIGIN } },
    ctx.timeoutMs
  );
  if (!res) return findings;

  const allowOrigin = res.headers.get("access-control-allow-origin");
  const allowCreds = res.headers.get("access-control-allow-credentials");

  if (allowOrigin === "*" && allowCreds?.toLowerCase() === "true") {
    findings.push({
      check: "cors",
      severity: "high",
      title: "Dangerous CORS configuration: wildcard origin with credentials",
      detail:
        "Server sent 'Access-Control-Allow-Origin: *' together with 'Access-Control-Allow-Credentials: true', which browsers should reject — but any relaxed variant of this pattern allows any site to read authenticated responses.",
      recommendation:
        "Never combine a wildcard origin with credentialed requests. Maintain an explicit allow-list of trusted origins.",
    });
  } else if (allowOrigin === PROBE_ORIGIN) {
    findings.push({
      check: "cors",
      severity: "high",
      title: "CORS reflects arbitrary Origin header",
      detail: `Server reflected an unrecognized test origin ('${PROBE_ORIGIN}') back in Access-Control-Allow-Origin.`,
      recommendation:
        "Validate the Origin header against a strict allow-list on the server instead of reflecting whatever value the client sends.",
    });
  }

  return findings;
};
