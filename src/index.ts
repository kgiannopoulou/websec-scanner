#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { Command, InvalidArgumentError, Option } from "commander";
import chalk from "chalk";
import { fetchSafe } from "./http.js";
import { printConsoleReport, toHtml, toJson, toSarif, VERSION } from "./report.js";
import { ALL_CHECKS, DEFAULTS, EXIT, exitCodeFor, runScan, type FailOn } from "./scanner.js";
import { inScope, parseScope } from "./scope.js";
import { SEVERITIES, type ScanContext } from "./types.js";

function nonNegativeInt(value: string): number {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0) throw new InvalidArgumentError("must be a non-negative integer");
  return n;
}

const program = new Command();

program
  .name("websec-scanner")
  .description(
    "Scans a website for common security misconfigurations (headers, cookies, TLS, exposed files, CORS). " +
      "Only scan targets you own or are explicitly authorized to test."
  )
  .version(VERSION)
  .argument("<url>", "target URL, e.g. https://example.com")
  .option("--json <file>", "write JSON report to file")
  .option("--html <file>", "write HTML report to file")
  .option("--sarif <file>", "write SARIF 2.1.0 report to file (GitHub code scanning)")
  .option("--skip <checks>", `comma-separated checks to skip (${Object.keys(ALL_CHECKS).join(", ")})`)
  .option("--timeout <ms>", "per-request timeout in milliseconds", nonNegativeInt, DEFAULTS.timeoutMs)
  .option("--retries <n>", "retries after a network error, timeout or 429/502/503/504", nonNegativeInt, DEFAULTS.retries)
  .option("--max-redirects <n>", "redirect hops to follow (0 disables)", nonNegativeInt, DEFAULTS.maxRedirects)
  .option(
    "--scope <hosts>",
    "comma-separated hosts the scanner may contact, '*.example.com' allowed (default: the target host only)"
  )
  .addOption(
    new Option("--fail-on <severity>", "exit with code 1 if any finding is at or above this severity")
      .choices([...SEVERITIES, "none"])
      .default("high")
  )
  .option("-q, --quiet", "don't print the console report")
  .option("-y, --yes", "confirm you are authorized to scan this target (required)")
  .action(async (urlArg: string, opts) => {
    if (!opts.yes) {
      console.error(
        chalk.red.bold("\nRefusing to scan: authorization not confirmed.\n") +
          "This tool sends requests to the target, including probes for common sensitive file paths.\n" +
          "Only run it against systems you own or have explicit written permission to test.\n\n" +
          `Re-run with ${chalk.bold("--yes")} once you've confirmed you're authorized.\n`
      );
      process.exitCode = EXIT.usage;
      return;
    }

    let targetUrl: URL;
    try {
      targetUrl = new URL(urlArg);
    } catch {
      console.error(chalk.red(`Invalid URL: ${urlArg}`));
      process.exitCode = EXIT.usage;
      return;
    }
    if (targetUrl.protocol !== "http:" && targetUrl.protocol !== "https:") {
      console.error(chalk.red(`Unsupported protocol '${targetUrl.protocol}', use http or https.`));
      process.exitCode = EXIT.usage;
      return;
    }

    const scope = parseScope(opts.scope, targetUrl);
    if (!inScope(targetUrl, scope)) {
      console.error(chalk.red(`Target host '${targetUrl.hostname}' is not inside --scope (${scope.join(", ")}).`));
      process.exitCode = EXIT.usage;
      return;
    }

    const skip = new Set((opts.skip as string | undefined)?.split(",").map((s) => s.trim()) ?? []);
    const unknown = [...skip].filter((name) => !(name in ALL_CHECKS));
    if (unknown.length > 0) {
      console.error(chalk.red(`Unknown check(s) in --skip: ${unknown.join(", ")}`));
      process.exitCode = EXIT.usage;
      return;
    }

    const ctx: ScanContext = {
      targetUrl,
      timeoutMs: opts.timeout,
      retries: opts.retries,
      retryDelayMs: DEFAULTS.retryDelayMs,
      maxRedirects: opts.maxRedirects,
      scope,
      probeDelayMs: DEFAULTS.probeDelayMs,
    };

    if (!opts.quiet) console.log(chalk.dim(`Scanning ${targetUrl.toString()} (scope: ${scope.join(", ")}) ...`));

    if (!(await fetchSafe(ctx, targetUrl.toString()))) {
      console.error(chalk.red(`Target unreachable: ${targetUrl.toString()}`));
      process.exitCode = EXIT.unreachable;
      return;
    }

    const findings = await runScan(ctx, skip);
    const target = targetUrl.toString();

    if (!opts.quiet) printConsoleReport(target, findings);

    const outputs: [string | undefined, string, () => string][] = [
      [opts.json, "JSON", () => toJson(target, findings)],
      [opts.html, "HTML", () => toHtml(target, findings)],
      [opts.sarif, "SARIF", () => toSarif(target, findings)],
    ];
    for (const [file, label, render] of outputs) {
      if (!file) continue;
      await writeFile(file, render(), "utf-8");
      if (!opts.quiet) console.log(chalk.dim(`${label} report written to ${file}`));
    }

    process.exitCode = exitCodeFor(findings, opts.failOn as FailOn);
  });

program.parseAsync(process.argv);
