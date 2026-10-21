import { connect, type PeerCertificate } from "node:tls";
import { RULES, finding } from "../rules.js";
import type { CheckFn, Finding } from "../types.js";

const WEAK_PROTOCOLS = new Set(["TLSv1", "TLSv1.1", "SSLv3"]);

/** Turns what the TLS handshake revealed into findings. Pure, so it can be unit-tested. */
export function evaluateTls(
  info: { protocol: string | null; cert: Partial<PeerCertificate> | null; authorized: boolean; authorizationError?: string },
  now = Date.now()
): Finding[] {
  const findings: Finding[] = [];

  if (info.protocol && WEAK_PROTOCOLS.has(info.protocol)) {
    findings.push(
      finding(RULES.weakTlsProtocol, {
        check: "tls",
        severity: "high",
        title: `Outdated TLS protocol in use: ${info.protocol}`,
        detail: `The server negotiated ${info.protocol}, which is considered insecure.`,
        recommendation: "Disable TLS 1.0/1.1 and SSLv3; require TLS 1.2 or higher (prefer TLS 1.3).",
      })
    );
  }

  if (info.cert?.valid_to) {
    const validTo = new Date(info.cert.valid_to);
    const daysLeft = Math.floor((validTo.getTime() - now) / (1000 * 60 * 60 * 24));
    if (daysLeft < 0) {
      findings.push(
        finding(RULES.certExpired, {
          check: "tls",
          severity: "high",
          title: "TLS certificate has expired",
          detail: `Certificate expired on ${info.cert.valid_to}.`,
          recommendation: "Renew the TLS certificate immediately.",
        })
      );
    } else if (daysLeft < 14) {
      findings.push(
        finding(RULES.certExpiringSoon, {
          check: "tls",
          severity: "medium",
          title: "TLS certificate expiring soon",
          detail: `Certificate expires in ${daysLeft} day(s) (${info.cert.valid_to}).`,
          recommendation: "Renew the TLS certificate before it expires to avoid a service outage or browser warnings.",
        })
      );
    }
  }

  if (!info.authorized) {
    findings.push(
      finding(RULES.certUntrusted, {
        check: "tls",
        severity: "high",
        title: "TLS certificate is not trusted",
        detail: info.authorizationError
          ? `Verification error: ${info.authorizationError}`
          : "The certificate chain did not verify against trusted CAs.",
        recommendation:
          "Use a certificate issued by a trusted CA (e.g. via Let's Encrypt) and ensure the full chain is served.",
      })
    );
  }

  return findings;
}

export const tlsCheck: CheckFn = async (ctx) => {
  if (ctx.targetUrl.protocol !== "https:") {
    return [
      finding(RULES.noHttps, {
        check: "tls",
        severity: "high",
        title: "Site not served over HTTPS",
        detail: `Target URL uses '${ctx.targetUrl.protocol}' instead of 'https:'.`,
        recommendation:
          "Serve the site exclusively over HTTPS and redirect all HTTP traffic to HTTPS to protect data in transit.",
        url: ctx.targetUrl.toString(),
      }),
    ];
  }

  const host = ctx.targetUrl.hostname;
  const port = ctx.targetUrl.port ? Number(ctx.targetUrl.port) : 443;

  return new Promise<Finding[]>((resolve) => {
    const socket = connect(
      { host, port, servername: host, timeout: ctx.timeoutMs, rejectUnauthorized: false },
      () => {
        const findings = evaluateTls({
          protocol: socket.getProtocol(),
          cert: socket.getPeerCertificate(),
          authorized: socket.authorized,
          authorizationError: socket.authorizationError?.toString(),
        });
        socket.end();
        resolve(findings.map((f) => ({ ...f, url: ctx.targetUrl.toString() })));
      }
    );

    socket.on("error", () => resolve([]));
    socket.on("timeout", () => {
      socket.destroy();
      resolve([]);
    });
  });
};
