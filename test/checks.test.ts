import { describe, expect, it } from "vitest";
import { cookiesCheck } from "../src/checks/cookies.js";
import { corsCheck, PROBE_ORIGIN } from "../src/checks/cors.js";
import { exposedFilesCheck } from "../src/checks/exposedFiles.js";
import { headersCheck } from "../src/checks/headers.js";
import { serverBannerCheck } from "../src/checks/serverBanner.js";
import { evaluateTls, tlsCheck } from "../src/checks/tls.js";
import { RULES } from "../src/rules.js";
import { context, SECURE_HEADERS, serve } from "./helpers.js";

describe("headers check", () => {
  it("reports each missing header with its rule, OWASP category and CWE", async () => {
    const base = await serve((_req, res) => res.writeHead(200).end());
    const findings = await headersCheck(context(base));
    const ids = findings.map((f) => f.ruleId);
    expect(ids).toEqual([
      RULES.missingCsp.id,
      RULES.contentTypeOptions.id,
      RULES.missingFrameOptions.id,
      RULES.missingReferrerPolicy.id,
      RULES.missingPermissionsPolicy.id,
    ]);
    expect(findings[0].owasp).toBe("A05:2021 Security Misconfiguration");
    expect(findings[0].cwe).toEqual(["CWE-693"]);
  });

  it("does not ask for HSTS over plain HTTP", async () => {
    const base = await serve((_req, res) => res.writeHead(200).end());
    const findings = await headersCheck(context(base));
    expect(findings.some((f) => f.ruleId === RULES.missingHsts.id)).toBe(false);
  });

  it("accepts CSP frame-ancestors instead of X-Frame-Options", async () => {
    const base = await serve((_req, res) => res.writeHead(200, SECURE_HEADERS).end());
    expect(await headersCheck(context(base))).toEqual([]);
  });

  it("flags X-Content-Type-Options with the wrong value", async () => {
    const base = await serve((_req, res) =>
      res.writeHead(200, { ...SECURE_HEADERS, "x-content-type-options": "sniff" }).end()
    );
    const [f] = await headersCheck(context(base));
    expect(f.title).toBe("Misconfigured header: x-content-type-options");
  });

  it("reports an unreachable target as info", async () => {
    const findings = await headersCheck(context("http://127.0.0.1:1"));
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "info", ruleId: RULES.scanError.id });
  });
});

describe("cookies check", () => {
  it("flags missing HttpOnly and SameSite", async () => {
    const base = await serve((_req, res) => res.writeHead(200, { "set-cookie": "session=abc; Path=/" }).end());
    const [f] = await cookiesCheck(context(base));
    expect(f.title).toBe("Cookie 'session' missing attribute(s): HttpOnly, SameSite");
    expect(f.severity).toBe("medium");
  });

  it("only lacks SameSite → low", async () => {
    const base = await serve((_req, res) => res.writeHead(200, { "set-cookie": "pref=1; HttpOnly" }).end());
    const [f] = await cookiesCheck(context(base));
    expect(f.severity).toBe("low");
  });

  it("does not mistake a cookie value for an attribute", async () => {
    const base = await serve((_req, res) =>
      res.writeHead(200, { "set-cookie": "note=httponly-samesite; Path=/" }).end()
    );
    const [f] = await cookiesCheck(context(base));
    expect(f.title).toContain("HttpOnly, SameSite");
  });

  it("inspects cookies set on a redirect", async () => {
    const base = await serve((req, res) => {
      if (req.url === "/") res.writeHead(302, { location: "/home", "set-cookie": "sid=1; Path=/" }).end();
      else res.writeHead(200).end();
    });
    const findings = await cookiesCheck(context(base));
    expect(findings.map((f) => f.title)).toEqual(["Cookie 'sid' missing attribute(s): HttpOnly, SameSite"]);
  });

  it("passes a fully flagged cookie", async () => {
    const base = await serve((_req, res) =>
      res.writeHead(200, { "set-cookie": "sid=1; HttpOnly; Secure; SameSite=Lax" }).end()
    );
    expect(await cookiesCheck(context(base))).toEqual([]);
  });
});

describe("cors check", () => {
  it("flags a reflected origin with credentials as high", async () => {
    const base = await serve((req, res) =>
      res
        .writeHead(200, {
          "access-control-allow-origin": req.headers.origin ?? "",
          "access-control-allow-credentials": "true",
        })
        .end()
    );
    const [f] = await corsCheck(context(base));
    expect(f).toMatchObject({ ruleId: RULES.corsReflectedOrigin.id, severity: "high" });
  });

  it("flags a reflected origin without credentials as medium", async () => {
    const base = await serve((req, res) =>
      res.writeHead(200, { "access-control-allow-origin": req.headers.origin ?? "" }).end()
    );
    const [f] = await corsCheck(context(base));
    expect(f.severity).toBe("medium");
  });

  it("flags wildcard + credentials", async () => {
    const base = await serve((_req, res) =>
      res
        .writeHead(200, { "access-control-allow-origin": "*", "access-control-allow-credentials": "true" })
        .end()
    );
    const [f] = await corsCheck(context(base));
    expect(f.ruleId).toBe(RULES.corsWildcardCredentials.id);
  });

  it("ignores an allow-list that doesn't include the probe origin", async () => {
    const base = await serve((_req, res) =>
      res.writeHead(200, { "access-control-allow-origin": "https://app.example.com" }).end()
    );
    expect(await corsCheck(context(base))).toEqual([]);
    expect(PROBE_ORIGIN).not.toBe("https://app.example.com");
  });
});

describe("exposed files check", () => {
  it("flags a real .env as critical", async () => {
    const base = await serve((req, res) => {
      if (req.url === "/.env") res.writeHead(200, { "content-type": "text/plain" }).end("DB_PASSWORD=hunter2\n");
      else res.writeHead(404).end();
    });
    const findings = await exposedFilesCheck(context(base));
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ severity: "critical", url: `${base}/.env` });
  });

  it("ignores a catch-all page that answers 200 for every path", async () => {
    const base = await serve((_req, res) => res.writeHead(200, { "content-type": "text/html" }).end("<h1>Home</h1>"));
    expect(await exposedFilesCheck(context(base))).toEqual([]);
  });

  it("ignores a plain-text 200 that doesn't match the file's signature", async () => {
    const base = await serve((_req, res) => res.writeHead(200, { "content-type": "text/plain" }).end("Not found"));
    const findings = await exposedFilesCheck(context(base));
    // Only probes without a signature (backups, .DS_Store) can match arbitrary content.
    expect(findings.every((f) => !f.title.includes(".env") && !f.title.includes(".git"))).toBe(true);
  });

  it("does not follow a redirect from a probe path", async () => {
    const base = await serve((req, res) => {
      if (req.url === "/.env") res.writeHead(302, { location: "/real.env" }).end();
      else if (req.url === "/real.env") res.writeHead(200, { "content-type": "text/plain" }).end("A=1");
      else res.writeHead(404).end();
    });
    expect(await exposedFilesCheck(context(base))).toEqual([]);
  });
});

describe("server banner check", () => {
  it("rates a version number as medium and a bare product as low", async () => {
    const base = await serve((_req, res) =>
      res.writeHead(200, { server: "nginx/1.18.0", "x-powered-by": "Express" }).end()
    );
    const findings = await serverBannerCheck(context(base));
    expect(findings.map((f) => f.severity)).toEqual(["medium", "low"]);
  });
});

describe("tls check", () => {
  it("flags a plain-HTTP target", async () => {
    const [f] = await tlsCheck(context("http://127.0.0.1:1"));
    expect(f).toMatchObject({ ruleId: RULES.noHttps.id, severity: "high", owasp: "A02:2021 Cryptographic Failures" });
  });

  it("evaluates protocol, expiry and trust", () => {
    const now = Date.parse("2026-01-01T00:00:00Z");
    const ids = (info: Parameters<typeof evaluateTls>[0]) => evaluateTls(info, now).map((f) => f.ruleId);

    expect(ids({ protocol: "TLSv1.3", cert: { valid_to: "Jun 1 00:00:00 2026 GMT" }, authorized: true })).toEqual([]);
    expect(ids({ protocol: "TLSv1.1", cert: null, authorized: true })).toEqual([RULES.weakTlsProtocol.id]);
    expect(ids({ protocol: "TLSv1.3", cert: { valid_to: "Dec 1 00:00:00 2025 GMT" }, authorized: true })).toEqual([
      RULES.certExpired.id,
    ]);
    expect(ids({ protocol: "TLSv1.3", cert: { valid_to: "Jan 5 00:00:00 2026 GMT" }, authorized: true })).toEqual([
      RULES.certExpiringSoon.id,
    ]);
    expect(ids({ protocol: "TLSv1.3", cert: null, authorized: false, authorizationError: "SELF_SIGNED" })).toEqual([
      RULES.certUntrusted.id,
    ]);
  });
});
