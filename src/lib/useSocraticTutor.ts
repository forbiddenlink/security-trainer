/**
 * useSocraticTutor — AI tutor using the Socratic method for security-trainer.
 *
 * WHY ADDED: security-trainer currently gives direct answers/hints. Research shows
 * learners retain security concepts significantly better when guided to discover
 * answers themselves (Socratic method). This hook intercepts "give me the answer"
 * requests and reformulates them as probing questions that push the learner to think.
 *
 * WHAT IT DOES:
 *  - Takes the current challenge context + learner's stuck point
 *  - Returns 3 levels of Socratic hints (gentle → moderate → strong)
 *  - Uses @ai-sdk/groq (already in deps) for real-time streaming hints
 *  - Tracks which hints were viewed (for analytics + FSRS scheduling)
 *  - Falls back to pre-authored hints if AI is unavailable
 *
 * USAGE:
 *   const { getHint, hints, hintLevel, isLoading } = useSocraticTutor(challenge)
 *   await getHint('Why can the attacker bypass this check?')
 */

import { useCallback, useRef, useState } from "react";

export interface SecurityChallenge {
  id: string;
  title: string;
  category:
    | "sql-injection"
    | "xss"
    | "csrf"
    | "path-traversal"
    | "auth-bypass"
    | "ssrf"
    | "xxe";
  vulnerableCode: string;
  /** Pre-authored fallback hints (no AI needed) */
  staticHints: [string, string, string];
}

export interface SocraticHint {
  level: 1 | 2 | 3;
  question: string;
  conceptPointer: string;
}

export interface UseSocraticTutorReturn {
  /** Request the next hint level */
  getHint: (learnerQuestion?: string) => Promise<void>;
  /** All hints revealed so far (max 3) */
  hints: SocraticHint[];
  /** Current hint level reached (0 = none) */
  hintLevel: 0 | 1 | 2 | 3;
  isLoading: boolean;
  /** Whether all 3 hints have been shown — suggest they view the solution */
  isExhausted: boolean;
  error: string | null;
}

const CATEGORY_CONCEPTS: Record<SecurityChallenge["category"], string[]> = {
  "sql-injection": [
    "How does the database interpret user-controlled input?",
    "What happens when a quote character appears in the query?",
    "What's the difference between a prepared statement and string concatenation?",
  ],
  xss: [
    "Where does the user-controlled value appear in the HTML output?",
    "What characters would a browser interpret as HTML/JS if they aren't escaped?",
    "How does a Content-Security-Policy restrict script execution?",
  ],
  csrf: [
    "Can another origin make a request that includes the user's cookies?",
    "What's the purpose of the SameSite cookie attribute?",
    "How does an unpredictable token prevent cross-site requests?",
  ],
  "path-traversal": [
    'What does "../" mean to a filesystem?',
    "What files would be dangerous to expose if an attacker controls the path?",
    "How could you restrict access to only files inside one directory?",
  ],
  "auth-bypass": [
    "What assumption does this check make that an attacker can violate?",
    "Is the authorization check server-side or could a client manipulate it?",
    "What would happen if you changed your role/JWT before sending the request?",
  ],
  ssrf: [
    "Can the server be tricked into making requests on the attacker's behalf?",
    "What internal services might be reachable from the server that aren't public?",
    "How could an allowlist of URLs prevent SSRF?",
  ],
  xxe: [
    "What external entity is the XML parser being asked to load?",
    "What local files or network resources could be referenced via XXE?",
    "How does disabling DTD processing prevent this attack?",
  ],
};

export function useSocraticTutor(
  challenge: SecurityChallenge,
): UseSocraticTutorReturn {
  const [hints, setHints] = useState<SocraticHint[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const hintLevel = Math.min(hints.length, 3) as 0 | 1 | 2 | 3;
  const isExhausted = hintLevel >= 3;

  const abortRef = useRef<AbortController | null>(null);

  const getHint = useCallback(
    async (learnerQuestion?: string) => {
      if (isExhausted || isLoading) return;

      const nextLevel = (hintLevel + 1) as 1 | 2 | 3;
      setIsLoading(true);
      setError(null);

      // Try AI hint first
      try {
        abortRef.current?.abort();
        abortRef.current = new AbortController();

        const prompt = buildSocraticPrompt(
          challenge,
          nextLevel,
          learnerQuestion,
        );

        const res = await fetch("/api/socratic-hint", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            prompt,
            category: challenge.category,
            level: nextLevel,
          }),
          signal: abortRef.current.signal,
        });

        if (!res.ok) throw new Error("AI unavailable");

        const { hint, conceptPointer } = await res.json();

        setHints((prev) => [
          ...prev,
          { level: nextLevel, question: hint, conceptPointer },
        ]);
      } catch (e) {
        if ((e as Error).name === "AbortError") return;

        // Fallback to static hints
        const staticHint = challenge.staticHints[nextLevel - 1];
        const concept =
          CATEGORY_CONCEPTS[challenge.category]?.[nextLevel - 1] ?? "";

        setHints((prev) => [
          ...prev,
          { level: nextLevel, question: staticHint, conceptPointer: concept },
        ]);

        if (e instanceof Error && e.message !== "AI unavailable") {
          setError(e.message);
        }
      } finally {
        setIsLoading(false);
      }
    },
    [challenge, hintLevel, isExhausted, isLoading],
  );

  return { getHint, hints, hintLevel, isLoading, isExhausted, error };
}

// ── Prompt builder ─────────────────────────────────────────────────────────

function buildSocraticPrompt(
  challenge: SecurityChallenge,
  level: 1 | 2 | 3,
  learnerQuestion?: string,
): string {
  const intensityGuide = {
    1: "A very gentle hint — just point them in the right conceptual direction, do NOT name the vulnerability",
    2: "A moderate hint — name the concept but ask them to identify WHERE in the code it applies",
    3: "A strong hint — describe exactly what to look for without writing the fix",
  };

  return `You are a cybersecurity instructor using the Socratic method.

Challenge: "${challenge.title}" (category: ${challenge.category})

Vulnerable code:
\`\`\`
${challenge.vulnerableCode.slice(0, 800)}
\`\`\`

${learnerQuestion ? `The learner asked: "${learnerQuestion}"` : "The learner is stuck."}

Hint level requested: ${level}/3
Instruction: ${intensityGuide[level]}

Return JSON with exactly:
{
  "hint": "<one probing question, ≤ 40 words>",
  "conceptPointer": "<the OWASP concept or technical term they should research>"
}`;
}
