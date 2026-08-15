/**
 * Shared Socratic-tutor prompt construction + input validation.
 * Imported by BOTH the Vercel handler (api/socratic-hint.ts) and the local
 * Vite dev middleware (vite.socratic-plugin.ts) so the prompt shape can't drift.
 *
 * The server owns the prompt: clients send only validated fields, never raw
 * completion text, so the endpoint can't be used as a general LLM proxy.
 */

// Allowlisted challenge categories — mirrors SecurityChallenge["category"].
export const CATEGORIES = new Set([
  "sql-injection",
  "xss",
  "csrf",
  "path-traversal",
  "auth-bypass",
  "ssrf",
  "xxe",
  "command-injection",
  "cors",
  "jwt",
  "deserialization",
  "file-upload",
  "misconfig",
  "general",
]);

const INTENSITY: Record<1 | 2 | 3, string> = {
  1: "A very gentle hint — just point them in the right conceptual direction, do NOT name the vulnerability",
  2: "A moderate hint — name the concept but ask them to identify WHERE in the code it applies",
  3: "A strong hint — describe exactly what to look for without writing the fix",
};

export interface SocraticInput {
  category: string;
  level: 1 | 2 | 3;
  title: string;
  vulnerableCode: string;
  learnerQuestion: string;
}

/** Validate/normalize an untrusted request body. Returns null with a reason on failure. */
export function parseSocraticBody(
  body: unknown,
): { ok: true; value: SocraticInput } | { ok: false; error: string } {
  const b = (body ?? {}) as Record<string, unknown>;
  const category = String(b.category ?? "");
  if (!CATEGORIES.has(category))
    return { ok: false, error: "Invalid category" };
  const level = Number(b.level);
  if (![1, 2, 3].includes(level)) return { ok: false, error: "Invalid level" };
  return {
    ok: true,
    value: {
      category,
      level: level as 1 | 2 | 3,
      title: String(b.title ?? "Security challenge").slice(0, 120),
      vulnerableCode: String(b.vulnerableCode ?? "").slice(0, 2000),
      learnerQuestion: String(b.learnerQuestion ?? "").slice(0, 500),
    },
  };
}

export function buildSocraticPrompt(input: SocraticInput): string {
  const { category, level, title, vulnerableCode, learnerQuestion } = input;
  return `You are a cybersecurity instructor using the Socratic method.

Challenge: "${title}" (category: ${category})

Vulnerable code:
\`\`\`
${vulnerableCode.slice(0, 800)}
\`\`\`

${learnerQuestion ? `The learner asked: "${learnerQuestion}"` : "The learner is stuck."}

Hint level requested: ${level}/3
Instruction: ${INTENSITY[level]}

Return JSON with exactly:
{
  "hint": "<one probing question, <= 40 words>",
  "conceptPointer": "<the OWASP concept or technical term they should research>"
}`;
}
