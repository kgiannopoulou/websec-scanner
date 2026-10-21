# websec-scanner

[![CI](https://github.com/kgiannopoulou/websec-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/kgiannopoulou/websec-scanner/actions/workflows/ci.yml)

A CLI tool that scans a website for common security misconfigurations and produces a plain-English report with remediation advice. Every finding has a stable rule ID, a severity, an OWASP Top 10 category, CWE IDs and a reference link. Reports come out as console text, JSON, HTML or **SARIF** (for GitHub code scanning), and the exit codes are designed for CI pipelines.

> **⚠️ Authorized use only.** This tool sends HTTP requests to the target, including probes for commonly-exposed sensitive file paths (`.env`, `.git/config`, etc.). **Only scan websites you own or have explicit written permission to test.** The CLI refuses to run without an explicit `--yes` confirmation, and it never contacts a host outside `--scope`.

## What it checks

| Check | Rule IDs | What it looks for | OWASP Top 10 (2021) |
|---|---|---|---|
| **Security headers** | `WSS-HDR-001`…`006` | Missing/misconfigured `Content-Security-Policy`, `Strict-Transport-Security` (incl. short `max-age`), `X-Frame-Options` (or CSP `frame-ancestors`), `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` | A05 Security Misconfiguration |
| **Cookies** | `WSS-COOKIE-001` | Cookies missing `HttpOnly`, `Secure` or `SameSite`, including cookies set on redirects | A05 Security Misconfiguration |
| **TLS/SSL** | `WSS-TLS-001`…`005` | Non-HTTPS targets, TLS 1.0/1.1, expired or soon-to-expire certificates, untrusted chains | A02 Cryptographic Failures |
| **Exposed files** | `WSS-FILE-001` | `.env`, `.git/`, `.aws/credentials`, backups, `server-status` — matched by content signature to avoid catch-all false positives | A05 Security Misconfiguration |
| **CORS** | `WSS-CORS-001`, `002` | Wildcard origin with credentials, or reflection of an arbitrary `Origin` | A05 Security Misconfiguration |
| **Info disclosure** | `WSS-INFO-001` | `Server` / `X-Powered-By` headers leaking software versions | A05 Security Misconfiguration |

The full catalog (CWE IDs and reference links per rule) is in [`src/rules.ts`](src/rules.ts).

### Severity

| Severity | Meaning | Example |
|---|---|---|
| `critical` | Direct exposure of secrets or source code | Readable `/.env`, `/.git/config`, `/.aws/credentials` |
| `high` | Exploitable weakness in transport or browser trust | No HTTPS, missing HSTS, expired cert, CORS reflection with credentials |
| `medium` | Missing defence-in-depth against a common attack | No CSP, no clickjacking protection, version banner |
| `low` | Hardening gap with limited direct impact | Missing `Referrer-Policy`, cookie without `SameSite` |
| `info` | Informational or a check that couldn't run | Missing `Permissions-Policy`, unreachable target |

## Install

```bash
npm install
npm run build
```

Requires Node.js 20 or newer.

## Usage

```bash
node dist/index.js <url> --yes [options]
```

`--yes` is required and is an explicit statement that you are authorized to scan the target.

### Options

```
--json <file>          write a JSON report
--html <file>          write an HTML report
--sarif <file>         write a SARIF 2.1.0 report (GitHub code scanning)
--skip <checks>        comma-separated checks to skip: headers, cookies, tls, exposed-files, cors, info-disclosure
--timeout <ms>         per-request timeout (default 8000)
--retries <n>          retries after a network error, timeout or 429/502/503/504, with backoff (default 1)
--max-redirects <n>    redirect hops to follow, 0 disables (default 5)
--scope <hosts>        hosts the scanner may contact, e.g. "example.com,*.example.com" (default: the target host)
--fail-on <severity>   exit 1 if any finding is at or above this severity: info|low|medium|high|critical|none (default high)
-q, --quiet            no console report
```

### Safe request handling

- **Scope:** every request, including each redirect hop, is checked against `--scope`. A redirect to another host is recorded but never followed.
- **Redirects:** only `http`/`https` targets, capped by `--max-redirects`. Exposed-file probes never follow redirects, so a redirect from `/.env` to a login page isn't reported as an exposed file.
- **Retries:** transient failures are retried with exponential backoff, and every request has a hard timeout.
- **Politeness:** file probes run one at a time with a short pause between them.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan finished, nothing at or above `--fail-on` |
| `1` | Scan finished, at least one finding at or above `--fail-on` |
| `2` | Usage error: no `--yes`, invalid URL, target outside `--scope`, unknown check |
| `3` | Target unreachable |

### In a CI pipeline

```yaml
- run: node dist/index.js https://staging.example.com --yes --fail-on high --sarif websec.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: websec.sarif
```

### Example

```
$ node dist/index.js https://kgiannopoulou.github.io/website-portfolio/ --yes

WebSec Scanner report for https://kgiannopoulou.github.io/website-portfolio/
Score: 84/100 (grade B)

MEDIUM (2)
  - [WSS-HDR-001] Missing security header: content-security-policy
    The response did not include a 'content-security-policy' header.
    Fix: Add a Content-Security-Policy header to restrict which scripts, styles, and resources ...
    A05:2021 Security Misconfiguration · CWE-693
  ...
```

Full reports from a scan of my own portfolio site are in [`examples/`](examples/): [HTML](examples/sample-report.html), [JSON](examples/sample-report.json), [SARIF](examples/sample-report.sarif).

## Development

```bash
npm run lint        # ESLint (typescript-eslint)
npm run typecheck   # tsc --noEmit
npm test            # Vitest
npm run check       # all of the above + build
```

The tests start throwaway HTTP servers on `127.0.0.1` and run each check against them. They cover a well-configured server and a misconfigured one, redirect/scope handling, retries, timeouts, the false-positive guards and the output formats, so no external site is ever contacted. CI runs lint, type check, tests and build on Node 20 and 22.

## Why this project

Built as a hands-on complement to a full-stack development background. The goal was to apply OWASP Top 10 concepts (secure headers, cookie flags, transport security, information disclosure, CORS) as working code rather than just certification study. Each check maps to a real-world misconfiguration commonly flagged in web application security assessments.

## Possible extensions

- Subresource Integrity (SRI) checks on third-party `<script>` tags
- Authenticated scan mode (pass session cookies)
- Rate-limit / brute-force protection probing on login endpoints

## License

MIT
