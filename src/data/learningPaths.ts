import type { LearningPath } from "../types";

export const LEARNING_PATHS: LearningPath[] = [
  {
    id: "web-fundamentals",
    title: "Web Security Fundamentals",
    codename: "Operation Firewall",
    description:
      "Master the essential web security concepts. Learn to identify and prevent the most common vulnerabilities targeting web applications.",
    difficulty: "Beginner",
    modules: [
      "owasp-intro",
      "xss-basics",
      "sql-injection",
      "csrf-attacks",
      "clickjacking",
      "idor-basics",
      "sensitive-data",
      "cors-misconfig",
      "file-upload",
      "security-misconfiguration",
    ],
    certificateXp: 500,
    icon: "Shield",
  },
  {
    id: "api-backend",
    title: "API & Backend Security",
    codename: "Operation Backend",
    description:
      "Secure APIs and server-side systems. Deep dive into authentication, authorization, and backend-specific attack vectors.",
    difficulty: "Intermediate",
    modules: [
      "api-security",
      "jwt-vulnerabilities",
      "graphql-security",
      "broken-auth",
      "command-injection",
      "ssrf-attacks",
      "xxe-injection",
      "insecure-deserialization",
    ],
    certificateXp: 750,
    icon: "Server",
    requiredCompletions: 3,
  },
  {
    id: "advanced-threats",
    title: "Advanced Threat Analysis",
    codename: "Operation Shadow",
    description:
      "Elite-level security training. Tackle sophisticated attacks, modern infrastructure security, and emerging threat landscapes.",
    difficulty: "Advanced",
    modules: [
      "container-security",
      "supply-chain",
      "ai-security",
      "social-engineering",
      "business-logic",
      "race-conditions",
      "prototype-pollution",
      "subdomain-takeover",
      "oauth-attacks",
      "websocket-security",
    ],
    certificateXp: 1000,
    icon: "Target",
    requiredCompletions: 8,
  },
  {
    id: "security-everyone",
    title: "Security for Everyone",
    codename: "Operation Awareness",
    description:
      "Essential security awareness for all staff. Covers phishing, passwords, data handling, incident reporting, and safe remote work practices.",
    difficulty: "Beginner",
    modules: [
      "phishing-awareness",
      "password-data-hygiene",
      "incident-reporting",
      "safe-browsing-remote",
    ],
    certificateXp: 300,
    icon: "Users",
  },
  {
    id: "compliance-essentials",
    title: "Compliance & Regulatory",
    codename: "Operation Clearance",
    description:
      "Navigate regulatory requirements with confidence. Covers GDPR, PCI-DSS, SOC 2, and HIPAA fundamentals for technical and non-technical teams.",
    difficulty: "Intermediate",
    modules: [
      "gdpr-fundamentals",
      "pci-dss-essentials",
      "soc2-awareness",
      "hipaa-basics",
    ],
    certificateXp: 600,
    icon: "FileCheck",
    requiredCompletions: 2,
  },
  {
    id: "cloud-infrastructure",
    title: "Cloud & Infrastructure Security",
    codename: "Operation Skyline",
    description:
      "Secure modern cloud deployments and respond to incidents. Covers cloud security fundamentals, incident response, and container security.",
    difficulty: "Advanced",
    modules: [
      "cloud-security",
      "incident-response",
      "container-security",
      "supply-chain-security",
    ],
    certificateXp: 800,
    icon: "Cloud",
    requiredCompletions: 5,
  },
];

export const getPathById = (id: string): LearningPath | undefined =>
  LEARNING_PATHS.find((p) => p.id === id);
