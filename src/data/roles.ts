// Learner roles offered on the dashboard; each maps to a recommended path.
export const ROLES = [
  {
    id: "developer",
    title: "Developer",
    description: "I write code and want to build secure applications",
    recommendedPathId: "web-fundamentals",
  },
  {
    id: "devops",
    title: "DevOps / IT",
    description: "I manage infrastructure, deployments, and systems",
    recommendedPathId: "cloud-infrastructure",
  },
  {
    id: "manager",
    title: "Manager",
    description: "I lead teams and need to understand security risks",
    recommendedPathId: "compliance-essentials",
  },
  {
    id: "general",
    title: "Everyone else",
    description: "I use company tools and want to stay security-aware",
    recommendedPathId: "security-everyone",
  },
] as const;

export type RoleId = (typeof ROLES)[number]["id"];
