import type { Finding, Severity } from "./types.js";

/**
 * Catalog of every rule the scanner can report. Findings reference a rule by
 * id so that JSON/SARIF output stays stable and each issue carries its OWASP
 * Top 10 category, CWE and a reference to read.
 */
export interface Rule {
  id: string;
  name: string;
  owasp?: string;
  cwe?: string[];
  references: string[];
}

const A02 = "A02:2021 Cryptographic Failures";
const A05 = "A05:2021 Security Misconfiguration";

const CS = "https://cheatsheetseries.owasp.org/cheatsheets";
const WSTG = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing";

export const RULES = {
  missingCsp: {
    id: "WSS-HDR-001",
    name: "Missing Content-Security-Policy",
    owasp: A05,
    cwe: ["CWE-693"],
    references: [`${CS}/Content_Security_Policy_Cheat_Sheet.html`],
  },
  missingHsts: {
    id: "WSS-HDR-002",
    name: "Missing Strict-Transport-Security",
    owasp: A05,
    cwe: ["CWE-319"],
    references: [`${CS}/HTTP_Strict_Transport_Security_Cheat_Sheet.html`],
  },
  contentTypeOptions: {
    id: "WSS-HDR-003",
    name: "Missing or invalid X-Content-Type-Options",
    owasp: A05,
    cwe: ["CWE-693"],
    references: [`${CS}/HTTP_Headers_Cheat_Sheet.html#x-content-type-options`],
  },
  missingFrameOptions: {
    id: "WSS-HDR-004",
    name: "Missing clickjacking protection",
    owasp: A05,
    cwe: ["CWE-1021"],
    references: [`${CS}/Clickjacking_Defense_Cheat_Sheet.html`],
  },
  missingReferrerPolicy: {
    id: "WSS-HDR-005",
    name: "Missing Referrer-Policy",
    owasp: A05,
    cwe: ["CWE-200"],
    references: [`${CS}/HTTP_Headers_Cheat_Sheet.html#referrer-policy`],
  },
  missingPermissionsPolicy: {
    id: "WSS-HDR-006",
    name: "Missing Permissions-Policy",
    owasp: A05,
    cwe: ["CWE-693"],
    references: [`${CS}/HTTP_Headers_Cheat_Sheet.html#permissions-policy-formerly-feature-policy`],
  },
  cookieAttributes: {
    id: "WSS-COOKIE-001",
    name: "Cookie missing security attributes",
    owasp: A05,
    cwe: ["CWE-1004", "CWE-614", "CWE-1275"],
    references: [`${CS}/Session_Management_Cheat_Sheet.html#cookies`],
  },
  noHttps: {
    id: "WSS-TLS-001",
    name: "Site not served over HTTPS",
    owasp: A02,
    cwe: ["CWE-319"],
    references: [`${CS}/Transport_Layer_Security_Cheat_Sheet.html`],
  },
  weakTlsProtocol: {
    id: "WSS-TLS-002",
    name: "Outdated TLS protocol",
    owasp: A02,
    cwe: ["CWE-327"],
    references: [`${CS}/Transport_Layer_Security_Cheat_Sheet.html#only-support-strong-protocols`],
  },
  certExpired: {
    id: "WSS-TLS-003",
    name: "TLS certificate expired",
    owasp: A02,
    cwe: ["CWE-298"],
    references: [`${CS}/Transport_Layer_Security_Cheat_Sheet.html`],
  },
  certExpiringSoon: {
    id: "WSS-TLS-004",
    name: "TLS certificate expiring soon",
    owasp: A02,
    cwe: ["CWE-298"],
    references: [`${CS}/Transport_Layer_Security_Cheat_Sheet.html`],
  },
  certUntrusted: {
    id: "WSS-TLS-005",
    name: "TLS certificate not trusted",
    owasp: A02,
    cwe: ["CWE-295"],
    references: [`${CS}/Transport_Layer_Security_Cheat_Sheet.html#use-strong-cryptographic-hashing-algorithms`],
  },
  exposedFile: {
    id: "WSS-FILE-001",
    name: "Sensitive file publicly accessible",
    owasp: A05,
    cwe: ["CWE-538"],
    references: [`${WSTG}/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information`],
  },
  corsWildcardCredentials: {
    id: "WSS-CORS-001",
    name: "CORS wildcard origin with credentials",
    owasp: A05,
    cwe: ["CWE-942"],
    references: [`${WSTG}/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing`],
  },
  corsReflectedOrigin: {
    id: "WSS-CORS-002",
    name: "CORS reflects arbitrary Origin",
    owasp: A05,
    cwe: ["CWE-942"],
    references: [`${WSTG}/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing`],
  },
  serverBanner: {
    id: "WSS-INFO-001",
    name: "Server technology disclosed in headers",
    owasp: A05,
    cwe: ["CWE-200"],
    references: [`${WSTG}/01-Information_Gathering/02-Fingerprint_Web_Server`],
  },
  scanError: {
    id: "WSS-SCAN-001",
    name: "Check could not complete",
    references: [],
  },
} satisfies Record<string, Rule>;

export const ALL_RULES: Rule[] = Object.values(RULES);

type FindingFields = Omit<Finding, "ruleId" | "owasp" | "cwe" | "references"> & { severity: Severity };

/** Builds a finding and attaches the rule's id, OWASP category, CWE and references. */
export function finding(rule: Rule, fields: FindingFields): Finding {
  return {
    ruleId: rule.id,
    ...fields,
    ...(rule.owasp ? { owasp: rule.owasp } : {}),
    ...(rule.cwe ? { cwe: rule.cwe } : {}),
    references: rule.references,
  };
}
