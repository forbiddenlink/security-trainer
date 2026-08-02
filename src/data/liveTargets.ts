/**
 * Local vulnerable-app targets from the companion security-lab docker compose.
 * Juice Shop :3333 · DVWA :3334 · WebGoat :3335
 */

export interface LiveTarget {
  id: string;
  name: string;
  hostPort: number;
  url: string;
  description: string;
  relatedModuleIds: string[];
  relatedCtfTags: string[];
}

export const LIVE_TARGETS: LiveTarget[] = [
  {
    id: "juice-shop",
    name: "OWASP Juice Shop",
    hostPort: 3333,
    url: "http://localhost:3333",
    description:
      "Modern Node/Angular playground covering OWASP Top 10 and more.",
    relatedModuleIds: [
      "owasp-intro",
      "sql-injection",
      "xss-basics",
      "idor-basics",
      "broken-auth",
      "csrf-attacks",
      "file-upload",
      "jwt-vulnerabilities",
    ],
    relatedCtfTags: ["web", "sqli", "xss", "cookie"],
  },
  {
    id: "dvwa",
    name: "DVWA",
    hostPort: 3334,
    url: "http://localhost:3334",
    description:
      "Classic intentionally vulnerable PHP app for SQLi, XSS, CSRF, and file upload.",
    relatedModuleIds: [
      "sql-injection",
      "xss-basics",
      "csrf-attacks",
      "file-upload",
      "command-injection",
      "broken-auth",
    ],
    relatedCtfTags: ["web", "sqli", "xss", "csrf"],
  },
  {
    id: "webgoat",
    name: "WebGoat",
    hostPort: 3335,
    url: "http://localhost:3335/WebGoat",
    description:
      "Guided OWASP lesson labs with step-by-step exploit walkthroughs.",
    relatedModuleIds: [
      "owasp-intro",
      "sql-injection",
      "xss-basics",
      "path-traversal",
      "ssrf-attacks",
      "xxe-attacks",
      "jwt-vulnerabilities",
    ],
    relatedCtfTags: ["web", "path", "ssrf", "xxe"],
  },
];

export function getTargetsForModule(moduleId: string): LiveTarget[] {
  return LIVE_TARGETS.filter((t) => t.relatedModuleIds.includes(moduleId));
}

export function getTargetsForCtfTags(tags: string[] = []): LiveTarget[] {
  const lower = tags.map((t) => t.toLowerCase());
  return LIVE_TARGETS.filter(
    (t) =>
      t.relatedCtfTags.some((tag) => lower.includes(tag)) ||
      lower.some((tag) => t.relatedCtfTags.includes(tag)),
  );
}
