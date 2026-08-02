/**
 * Maps lab lesson IDs → Socratic tutor challenge context.
 * Static hints are probing questions (not spoilers) so learners discover the fix.
 */

import type { LabConfig } from "../types";
import type { SecurityChallenge } from "./useSocraticTutor";

export type TutorCategory = SecurityChallenge["category"];

const LAB_CATEGORY: Record<string, TutorCategory> = {
  "owasp-lab": "general",
  "sqli-lab": "sql-injection",
  "xss-lab": "xss",
  "idor-lab": "auth-bypass",
  "csrf-lab": "csrf",
  "misconfig-lab": "misconfig",
  "ssrf-lab": "ssrf",
  "xxe-lab": "xxe",
  "deser-lab": "deserialization",
  "data-exposure-lab": "general",
  "clickjacking-lab": "misconfig",
  "jwt-lab": "jwt",
  "business-logic-lab": "general",
  "vuln-comp-lab": "general",
  "logging-lab": "general",
  "auth-lab": "auth-bypass",
  "cmdi-lab": "command-injection",
  "path-lab": "path-traversal",
  "upload-lab": "file-upload",
  "cors-lab": "cors",
  "session-lab": "auth-bypass",
  "api-security-lab": "auth-bypass",
  "race-conditions-lab": "general",
  "ai-security-lab": "general",
  "supply-chain-lab": "general",
  "graphql-security-lab": "auth-bypass",
  "oauth-lab": "auth-bypass",
  "container-security-lab": "misconfig",
  "social-engineering-lab": "general",
  "proto-lab": "general",
  "subdomain-lab": "general",
  "ws-lab": "general",
  "cloud-config-audit-lab": "misconfig",
  "ir-simulation-lab": "general",
  "phishing-lab-triage": "general",
  "password-lab-policy": "general",
  "remote-lab-audit": "general",
  "gdpr-lab-privacy-audit": "general",
  "pci-lab-payment-flow": "general",
  "soc2-lab-gap-assessment": "general",
  "hipaa-lab-violation-finder": "general",
};

/** Progressive Socratic questions keyed by category (gentle → strong). */
const CATEGORY_STATIC_HINTS: Record<TutorCategory, [string, string, string]> = {
  "sql-injection": [
    "Where does user input meet the database query in this code?",
    "What happens if that input contains a quote character?",
    "How could you pass values separately from the SQL string itself?",
  ],
  xss: [
    "Which line treats user content as HTML instead of text?",
    "What does React do automatically when you render `{value}` vs raw HTML?",
    "Which prop should you remove so the framework escapes the comment?",
  ],
  csrf: [
    "Could a third-party site trigger this action using the user's cookies?",
    "What secret value could prove the request originated from your own form?",
    "Where should you compare a token from the request against the session?",
  ],
  "path-traversal": [
    "Who controls the path string being joined to the uploads directory?",
    "What does `../` do when resolved against a filesystem path?",
    "How can you ensure the final path still starts with the uploads root?",
  ],
  "auth-bypass": [
    "Is ownership or role checked on the server before returning data?",
    "What would happen if the client changed the ID or token before sending?",
    "Where should you compare the resource owner to the authenticated user?",
  ],
  ssrf: [
    "Who decides which URL the server will fetch?",
    "Which internal hosts would be dangerous if the server could reach them?",
    "How would an allowlist plus private-IP checks change that risk?",
  ],
  xxe: [
    "Does this XML parser allow DTDs or external entities by default?",
    "What local file could an attacker load via an external entity?",
    "Which parser flags should be set to refuse DTD and entity expansion?",
  ],
  "command-injection": [
    "Is user input concatenated into a shell command string?",
    "What characters would let an attacker append extra commands?",
    "How can you run the tool with an argument array instead of a shell string?",
  ],
  cors: [
    "Does this handler reflect any Origin header back as allowed?",
    "Which origins should actually be trusted for credentialed requests?",
    "How would you gate Access-Control-Allow-Origin behind an allowlist?",
  ],
  jwt: [
    "Which algorithms does verification currently accept?",
    "Why is the `none` algorithm dangerous for signed tokens?",
    "How would an explicit algorithm allowlist change verification?",
  ],
  deserialization: [
    "How is untrusted data turned into executable structure here?",
    "What happens if an attacker forges the payload without a signature?",
    "How could HMAC verification plus JSON.parse replace unsafe eval?",
  ],
  "file-upload": [
    "What trust does this code place in the client-provided filename?",
    "Which file types or extensions would be dangerous to accept?",
    "How can you rename uploads and validate content type server-side?",
  ],
  misconfig: [
    "Which settings look like defaults left on for convenience?",
    "What headers or flags would harden this against common probes?",
    "Which production values should replace debug/default credentials?",
  ],
  general: [
    "What assumption does this code make that an attacker can break?",
    "Where does untrusted input influence a security-sensitive decision?",
    "What check or transformation would make that influence impossible?",
  ],
};

const CATEGORY_TITLES: Record<TutorCategory, string> = {
  "sql-injection": "SQL Injection Lab",
  xss: "XSS Lab",
  csrf: "CSRF Lab",
  "path-traversal": "Path Traversal Lab",
  "auth-bypass": "Auth / Access Control Lab",
  ssrf: "SSRF Lab",
  xxe: "XXE Lab",
  "command-injection": "Command Injection Lab",
  cors: "CORS Lab",
  jwt: "JWT Lab",
  deserialization: "Deserialization Lab",
  "file-upload": "File Upload Lab",
  misconfig: "Misconfiguration Lab",
  general: "Security Lab",
};

export function getLabTutorCategory(lessonId: string): TutorCategory {
  return LAB_CATEGORY[lessonId] ?? "general";
}

export function buildLabTutorChallenge(
  lessonId: string,
  lab: LabConfig,
): SecurityChallenge {
  const category = getLabTutorCategory(lessonId);
  return {
    id: lessonId,
    title: CATEGORY_TITLES[category],
    category,
    vulnerableCode: lab.initialCode,
    staticHints: CATEGORY_STATIC_HINTS[category],
  };
}
