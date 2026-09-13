import { fetchSafe } from "../http.js";
import type { CheckFn, Finding } from "../types.js";

const VERSION_PATTERN = /\d+\.\d+/;

export const serverBannerCheck: CheckFn = async (ctx) => {
  const findings: Finding[] = [];
  const res = await fetchSafe(ctx.targetUrl.toString(), {}, ctx.timeoutMs);
  if (!res) return findings;

  for (const header of ["server", "x-powered-by"]) {
    const value = res.headers.get(header);
    if (!value) continue;

    const revealsVersion = VERSION_PATTERN.test(value);
    findings.push({
      check: "info-disclosure",
      severity: revealsVersion ? "medium" : "low",
      title: `'${header}' header discloses server technology`,
      detail: `${header}: ${value}`,
      recommendation: `Suppress or genericize the '${header}' header at the server/proxy level so specific software versions aren't advertised to attackers scoping for known exploits.`,
    });
  }

  return findings;
};
