# websec-scanner

A CLI tool that scans a website for common security misconfigurations and produces a plain-English report with remediation advice — built to practice application-security fundamentals (OWASP-style checks) on top of a Node.js/TypeScript stack.

> **⚠️ Authorized use only.** This tool sends HTTP requests to the target, including probes for commonly-exposed sensitive file paths (`.env`, `.git/config`, etc.). **Only scan websites you own or have explicit written permission to test.** The CLI refuses to run without an explicit `--yes` confirmation for this reason.

## What it checks

| Check | What it looks for |
|---|---|
| **Security headers** | Missing/misconfigured `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` |
| **Cookies** | Session cookies missing `HttpOnly`, `Secure`, or `SameSite` attributes |
| **TLS/SSL** | Non-HTTPS targets, outdated protocol versions (TLS 1.0/1.1), expired or soon-to-expire certificates, untrusted certificate chains |
| **Exposed files** | Common sensitive paths left publicly accessible (`.env`, `.git/config`, backup files, `.aws/credentials`, etc.) |
| **CORS** | Wildcard origins combined with credentialed requests, or origin-reflection misconfigurations |
| **Info disclosure** | `Server` / `X-Powered-By` headers leaking specific software versions |

Each finding includes a severity rating (`info` / `low` / `medium` / `high`) and a concrete fix.

## Install

```bash
npm install
npm run build
```

## Usage

```bash
node dist/index.js <url> --yes
```

`--yes` is required and is an explicit statement that you are authorized to scan the target.

### Options

```
--json <file>       write a JSON report to file
--html <file>       write an HTML report to file
--skip <checks>     comma-separated checks to skip (e.g. exposed-files)
--timeout <ms>      per-request timeout (default 8000)
```

### Example

```bash
node dist/index.js https://example.com --yes --html report.html
```

```
Scanning https://example.com/ ...

WebSec Scanner report for https://example.com/
Score: 78/100 (grade C)

HIGH (1)
  - [tls] Outdated TLS protocol in use: TLSv1.1
    The server negotiated TLSv1.1, which is considered insecure.
    Fix: Disable TLS 1.0/1.1 and SSLv3; require TLS 1.2 or higher (prefer TLS 1.3).

MEDIUM (2)
  - [headers] Missing security header: content-security-policy
    ...
```

## Example output

A real scan of [kgiannopoulou.github.io/website-portfolio](https://kgiannopoulou.github.io/website-portfolio/) (my own site — scanned with permission, obviously) is included in [`examples/`](./examples/sample-report.html).

## Why this project

Built as a hands-on complement to a full-stack development background — the goal was to apply OWASP Top 10 concepts (secure headers, cookie flags, transport security, information disclosure, CORS) as working code rather than just certification study. Each check maps to a real-world misconfiguration commonly flagged in web application security assessments.

## Possible extensions

- Subresource Integrity (SRI) checks on third-party `<script>` tags
- Basic clickjacking PoC page generator
- Rate-limit / brute-force protection probing on login endpoints
- Authenticated scan mode (pass session cookies)

## License

MIT
