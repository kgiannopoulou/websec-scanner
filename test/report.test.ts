import { describe, expect, it } from "vitest";
import { escapeHtml, score, summary, toHtml, toJson, toSarif } from "../src/report.js";
import { ALL_RULES, RULES, finding } from "../src/rules.js";
import { exitCodeFor, runScan, EXIT } from "../src/scanner.js";
import type { Finding } from "../src/types.js";
import { context, serve } from "./helpers.js";

const sample: Finding[] = [
  finding(RULES.exposedFile, {
    check: "exposed-files",
    severity: "critical",
    title: "Potentially exposed file: /.env",
    detail: "200 OK",
    recommendation: "Remove it.",
    url: "https://example.com/.env",
  }),
  finding(RULES.missingCsp, {
    check: "headers",
    severity: "medium",
    title: "Missing security header: content-security-policy",
    detail: "<none>",
    recommendation: "Add one.",
  }),
];

describe("rule catalog", () => {
  it("has unique ids", () => {
    const ids = ALL_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("maps every security rule to OWASP, CWE and a reference", () => {
    for (const rule of ALL_RULES.filter((r) => r !== RULES.scanError)) {
      expect(rule.owasp, rule.id).toMatch(/^A\d\d:2021 /);
      expect(rule.cwe?.length, rule.id).toBeGreaterThan(0);
      expect(rule.references[0], rule.id).toMatch(/^https:\/\/(cheatsheetseries\.)?owasp\.org\//);
    }
  });
});

describe("scoring", () => {
  it("weights critical findings heaviest", () => {
    expect(score(sample)).toEqual({ score: 70, grade: "C" });
    expect(score([])).toEqual({ score: 100, grade: "A" });
  });

  it("counts findings per severity", () => {
    expect(summary(sample)).toEqual({ critical: 1, high: 0, medium: 1, low: 0, info: 0 });
  });
});

describe("exit codes", () => {
  it("fails when a finding is at or above the threshold", () => {
    expect(exitCodeFor(sample, "high")).toBe(EXIT.findingsAtThreshold);
    expect(exitCodeFor(sample, "medium")).toBe(EXIT.findingsAtThreshold);
    expect(exitCodeFor(sample.slice(1), "high")).toBe(EXIT.ok);
    expect(exitCodeFor(sample, "none")).toBe(EXIT.ok);
    expect(exitCodeFor([], "info")).toBe(EXIT.ok);
  });
});

describe("outputs", () => {
  it("JSON includes summary and rule metadata", () => {
    const json = JSON.parse(toJson("https://example.com/", sample));
    expect(json.summary.critical).toBe(1);
    expect(json.findings[0]).toMatchObject({ ruleId: "WSS-FILE-001", cwe: ["CWE-538"] });
  });

  it("SARIF is a valid 2.1.0 log with levels and rule definitions", () => {
    const sarif = JSON.parse(toSarif("https://example.com/", sample));
    expect(sarif.version).toBe("2.1.0");
    const run = sarif.runs[0];
    expect(run.tool.driver.rules).toHaveLength(ALL_RULES.length);
    const ruleIds = new Set(run.tool.driver.rules.map((r: { id: string }) => r.id));
    for (const result of run.results) expect(ruleIds.has(result.ruleId)).toBe(true);
    expect(run.results.map((r: { level: string }) => r.level)).toEqual(["error", "warning"]);
    expect(run.results[0].locations[0].physicalLocation.artifactLocation.uri).toBe("https://example.com/.env");
    expect(run.results[1].locations[0].physicalLocation.artifactLocation.uri).toBe("https://example.com/");
    expect(run.results[0].properties["security-severity"]).toBe("9.5");
  });

  it("HTML escapes finding content", () => {
    const html = toHtml("https://example.com/", sample);
    expect(html).toContain("&lt;none&gt;");
    expect(html).not.toContain("<none>");
    expect(escapeHtml(`"<&>`)).toBe("&quot;&lt;&amp;&gt;");
  });
});

describe("runScan", () => {
  it("runs every check against a misconfigured server and honours --skip", async () => {
    const base = await serve((req, res) => {
      if (req.url === "/.git/HEAD") res.writeHead(200, { "content-type": "text/plain" }).end("ref: refs/heads/main\n");
      else res.writeHead(200, { "set-cookie": "sid=1", server: "Apache/2.4.1" }).end("<html></html>");
    });
    const findings = await runScan(context(base), new Set(["tls"]));
    const checks = new Set(findings.map((f) => f.check));
    expect(checks).toEqual(new Set(["headers", "cookies", "exposed-files", "info-disclosure"]));
    expect(exitCodeFor(findings, "critical")).toBe(EXIT.findingsAtThreshold);
  });
});
