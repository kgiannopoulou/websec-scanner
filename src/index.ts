#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { Command } from "commander";
import chalk from "chalk";
import { headersCheck } from "./checks/headers.js";
import { cookiesCheck } from "./checks/cookies.js";
import { tlsCheck } from "./checks/tls.js";
import { exposedFilesCheck } from "./checks/exposedFiles.js";
import { corsCheck } from "./checks/cors.js";
import { serverBannerCheck } from "./checks/serverBanner.js";
import { printConsoleReport, toJson, toHtml } from "./report.js";
import type { CheckFn, Finding, ScanContext } from "./types.js";

const ALL_CHECKS: Record<string, CheckFn> = {
  headers: headersCheck,
  cookies: cookiesCheck,
  tls: tlsCheck,
  "exposed-files": exposedFilesCheck,
  cors: corsCheck,
  "info-disclosure": serverBannerCheck,
};

const program = new Command();

program
  .name("websec-scanner")
  .description(
    "Scans a website for common security misconfigurations (headers, cookies, TLS, exposed files, CORS). " +
      "Only scan targets you own or are explicitly authorized to test."
  )
  .version("1.0.0")
  .argument("<url>", "target URL, e.g. https://example.com")
  .option("--json <file>", "write JSON report to file")
  .option("--html <file>", "write HTML report to file")
  .option("--skip <checks>", "comma-separated list of checks to skip (e.g. exposed-files)")
  .option("--timeout <ms>", "per-request timeout in milliseconds", "8000")
  .option("-y, --yes", "confirm you are authorized to scan this target (required)")
  .action(async (urlArg: string, opts) => {
    if (!opts.yes) {
      console.error(
        chalk.red.bold("\nRefusing to scan: authorization not confirmed.\n") +
          "This tool sends requests to the target, including probes for common sensitive file paths.\n" +
          "Only run it against systems you own or have explicit written permission to test.\n\n" +
          `Re-run with ${chalk.bold("--yes")} once you've confirmed you're authorized.\n`
      );
      process.exitCode = 1;
      return;
    }

    let targetUrl: URL;
    try {
      targetUrl = new URL(urlArg);
    } catch {
      console.error(chalk.red(`Invalid URL: ${urlArg}`));
      process.exitCode = 1;
      return;
    }

    const skip = new Set((opts.skip as string | undefined)?.split(",").map((s) => s.trim()) ?? []);
    const ctx: ScanContext = { targetUrl, timeoutMs: Number(opts.timeout) };

    console.log(chalk.dim(`Scanning ${targetUrl.toString()} ...`));

    const findings: Finding[] = [];
    for (const [name, check] of Object.entries(ALL_CHECKS)) {
      if (skip.has(name)) continue;
      try {
        findings.push(...(await check(ctx)));
      } catch (err) {
        findings.push({
          check: name,
          severity: "info",
          title: `Check '${name}' failed to run`,
          detail: err instanceof Error ? err.message : String(err),
          recommendation: "N/A",
        });
      }
    }

    printConsoleReport(targetUrl.toString(), findings);

    if (opts.json) {
      await writeFile(opts.json, toJson(targetUrl.toString(), findings), "utf-8");
      console.log(chalk.dim(`JSON report written to ${opts.json}`));
    }
    if (opts.html) {
      await writeFile(opts.html, toHtml(targetUrl.toString(), findings), "utf-8");
      console.log(chalk.dim(`HTML report written to ${opts.html}`));
    }
  });

program.parseAsync(process.argv);
