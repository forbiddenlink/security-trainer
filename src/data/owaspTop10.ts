/**
 * OWASP Top 10:2025 categories each module maps to.
 *
 * A module is mapped only when its core weakness appears in that category's
 * CWE list on owasp.org/Top10/2025 (checked 2026-10-02). Modules without a
 * clear CWE match (API, GraphQL, cloud, compliance, awareness topics,
 * prototype pollution, subdomain takeover) are intentionally left unmapped.
 */
export interface OwaspCategory {
  id: string;
  name: string;
  url: string;
}

const BASE = "https://owasp.org/Top10/2025/";

export const OWASP_TOP10_2025: Record<string, OwaspCategory> = {
  A01: {
    id: "A01",
    name: "Broken Access Control",
    url: `${BASE}A01_2025-Broken_Access_Control/`,
  },
  A02: {
    id: "A02",
    name: "Security Misconfiguration",
    url: `${BASE}A02_2025-Security_Misconfiguration/`,
  },
  A03: {
    id: "A03",
    name: "Software Supply Chain Failures",
    url: `${BASE}A03_2025-Software_Supply_Chain_Failures/`,
  },
  A04: {
    id: "A04",
    name: "Cryptographic Failures",
    url: `${BASE}A04_2025-Cryptographic_Failures/`,
  },
  A05: { id: "A05", name: "Injection", url: `${BASE}A05_2025-Injection/` },
  A06: {
    id: "A06",
    name: "Insecure Design",
    url: `${BASE}A06_2025-Insecure_Design/`,
  },
  A07: {
    id: "A07",
    name: "Authentication Failures",
    url: `${BASE}A07_2025-Authentication_Failures/`,
  },
  A08: {
    id: "A08",
    name: "Software or Data Integrity Failures",
    url: `${BASE}A08_2025-Software_or_Data_Integrity_Failures/`,
  },
  A09: {
    id: "A09",
    name: "Security Logging and Alerting Failures",
    url: `${BASE}A09_2025-Security_Logging_and_Alerting_Failures/`,
  },
};

// Module id -> categories, with the CWE that justifies each mapping.
const MODULE_MAP: Record<string, string[]> = {
  "idor-basics": ["A01"], // CWE-639 family, access control
  "path-traversal": ["A01"], // CWE-22
  "csrf-attacks": ["A01"], // CWE-352
  "ssrf-attacks": ["A01"], // CWE-918 (folded into A01 in 2025)
  "security-misconfig": ["A02"],
  "xxe-attacks": ["A02"], // CWE-611
  "cors-misconfig": ["A02"], // CWE-942
  "supply-chain-security": ["A03"], // CWE-1395
  "vulnerable-components": ["A03"], // CWE-1104
  "sensitive-data-exposure": ["A04"], // CWE-319
  "jwt-vulnerabilities": ["A04", "A07"], // CWE-347 signature checks, CWE-287
  "sql-injection": ["A05"], // CWE-89
  "xss-basics": ["A05"], // CWE-79
  "command-injection": ["A05"], // CWE-78
  "business-logic": ["A06"],
  "file-upload": ["A06"], // CWE-434
  clickjacking: ["A06"], // CWE-1021
  "race-conditions": ["A06"], // CWE-362
  "broken-auth": ["A07"], // CWE-287
  "session-management": ["A07"], // CWE-384, CWE-613
  "oauth-security": ["A07"],
  "insecure-deserialization": ["A08"], // CWE-502
  "logging-monitoring": ["A09"], // CWE-778
};

export function getOwaspCategories(moduleId: string): OwaspCategory[] {
  return (MODULE_MAP[moduleId] ?? []).map((id) => OWASP_TOP10_2025[id]);
}
