import { connect } from "node:tls";
import type { CheckFn, Finding } from "../types.js";

const WEAK_PROTOCOLS = new Set(["TLSv1", "TLSv1.1", "SSLv3"]);

export const tlsCheck: CheckFn = async (ctx) => {
  const findings: Finding[] = [];

  if (ctx.targetUrl.protocol !== "https:") {
    findings.push({
      check: "tls",
      severity: "high",
      title: "Site not served over HTTPS",
      detail: `Target URL uses '${ctx.targetUrl.protocol}' instead of 'https:'.`,
      recommendation:
        "Serve the site exclusively over HTTPS and redirect all HTTP traffic to HTTPS to protect data in transit.",
    });
    return findings;
  }

  const host = ctx.targetUrl.hostname;
  const port = ctx.targetUrl.port ? Number(ctx.targetUrl.port) : 443;

  const result = await new Promise<Finding[]>((resolve) => {
    const localFindings: Finding[] = [];
    const socket = connect(
      { host, port, servername: host, timeout: ctx.timeoutMs, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol();

        if (protocol && WEAK_PROTOCOLS.has(protocol)) {
          localFindings.push({
            check: "tls",
            severity: "high",
            title: `Outdated TLS protocol in use: ${protocol}`,
            detail: `The server negotiated ${protocol}, which is considered insecure.`,
            recommendation: "Disable TLS 1.0/1.1 and SSLv3; require TLS 1.2 or higher (prefer TLS 1.3).",
          });
        }

        if (cert && cert.valid_to) {
          const validTo = new Date(cert.valid_to);
          const daysLeft = Math.floor((validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
          if (daysLeft < 0) {
            localFindings.push({
              check: "tls",
              severity: "high",
              title: "TLS certificate has expired",
              detail: `Certificate expired on ${cert.valid_to}.`,
              recommendation: "Renew the TLS certificate immediately.",
            });
          } else if (daysLeft < 14) {
            localFindings.push({
              check: "tls",
              severity: "medium",
              title: "TLS certificate expiring soon",
              detail: `Certificate expires in ${daysLeft} day(s) (${cert.valid_to}).`,
              recommendation: "Renew the TLS certificate before it expires to avoid a service outage or browser warnings.",
            });
          }
        }

        if (!socket.authorized) {
          localFindings.push({
            check: "tls",
            severity: "high",
            title: "TLS certificate is not trusted",
            detail: socket.authorizationError
              ? `Verification error: ${socket.authorizationError}`
              : "The certificate chain did not verify against trusted CAs.",
            recommendation:
              "Use a certificate issued by a trusted CA (e.g. via Let's Encrypt) and ensure the full chain is served.",
          });
        }

        socket.end();
        resolve(localFindings);
      }
    );

    socket.on("error", () => resolve(localFindings));
    socket.on("timeout", () => {
      socket.destroy();
      resolve(localFindings);
    });
  });

  return [...findings, ...result];
};
