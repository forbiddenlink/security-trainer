/**
 * useSocraticTutor — AI tutor using the Socratic method for security-trainer.
 *
 * Returns progressive probing hints (gentle → strong). Falls back to
 * pre-authored staticHints when the AI endpoint is unavailable.
 */

import { useCallback, useEffect, useRef, useState } from "react";

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
    | "xxe"
    | "command-injection"
    | "cors"
    | "jwt"
    | "deserialization"
    | "file-upload"
    | "misconfig"
    | "general";
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
  /** Request the next hint level; returns the hint or null if exhausted/loading */
  getHint: (learnerQuestion?: string) => Promise<SocraticHint | null>;
  /** All hints revealed so far (max 3) */
  hints: SocraticHint[];
  /** Current hint level reached (0 = none) */
  hintLevel: 0 | 1 | 2 | 3;
  isLoading: boolean;
  /** Whether all 3 hints have been shown */
  isExhausted: boolean;
  error: string | null;
  /** Clear revealed hints (e.g. on lab reset) */
  resetHints: () => void;
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
  "command-injection": [
    "Is shell metacharacter interpretation possible with this input?",
    "What's safer: shell string concat or argv array execution?",
    "How do you validate/escape arguments before spawning a process?",
  ],
  cors: [
    "What does Access-Control-Allow-Origin: * imply for credentialed requests?",
    "Why reflecting the Origin header is dangerous?",
    "How does an allowlist of trusted origins reduce risk?",
  ],
  jwt: [
    "Why is algorithm confusion a risk for JWT verification?",
    "What does accepting the 'none' algorithm enable?",
    "How does pinning allowed algorithms protect verification?",
  ],
  deserialization: [
    "What's the difference between data and executable payloads?",
    "How does signature verification prove integrity of serialized state?",
    "Why is Function/eval-based deserialization unsafe?",
  ],
  "file-upload": [
    "What trust boundaries exist between filename, content-type, and bytes?",
    "How can path or extension tricks bypass naive filters?",
    "Why generate server-side filenames for uploads?",
  ],
  misconfig: [
    "Which defaults are convenient for developers but unsafe in production?",
    "What security headers reduce clickjacking and MIME sniffing?",
    "How do you inventory and harden exposed debug endpoints?",
  ],
  general: [
    "What trust boundary is being crossed in this code?",
    "Where does untrusted input influence a privileged action?",
    "What invariant should remain true even if the attacker controls inputs?",
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
  const hintsLenRef = useRef(0);
  // Keep the latest length in a ref (updated in an effect, never during render)
  // so getHint reads a fresh count without re-creating on every hint.
  useEffect(() => {
    hintsLenRef.current = hints.length;
  }, [hints.length]);

  // Reset when switching labs (skip first mount — state is already empty).
  const firstMountRef = useRef(true);
  useEffect(() => {
    if (firstMountRef.current) {
      firstMountRef.current = false;
      return;
    }
    abortRef.current?.abort();
    setHints([]);
    setError(null);
    setIsLoading(false);
  }, [challenge.id]);

  const resetHints = useCallback(() => {
    abortRef.current?.abort();
    setHints([]);
    setError(null);
    setIsLoading(false);
  }, []);

  const getHint = useCallback(
    async (learnerQuestion?: string): Promise<SocraticHint | null> => {
      if (hintsLenRef.current >= 3 || isLoading) return null;

      const nextLevel = (hintsLenRef.current + 1) as 1 | 2 | 3;
      setIsLoading(true);
      setError(null);

      const fallbackHint = (): SocraticHint => {
        const staticHint = challenge.staticHints[nextLevel - 1];
        const concept =
          CATEGORY_CONCEPTS[challenge.category]?.[nextLevel - 1] ?? "";
        return {
          level: nextLevel,
          question: staticHint,
          conceptPointer: concept,
        };
      };

      try {
        abortRef.current?.abort();
        abortRef.current = new AbortController();

        // The server builds the Socratic prompt from these validated fields,
        // so this endpoint can't be abused as a general-purpose LLM proxy.
        const res = await fetch("/api/socratic-hint", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            category: challenge.category,
            level: nextLevel,
            title: challenge.title,
            vulnerableCode: challenge.vulnerableCode,
            learnerQuestion: learnerQuestion ?? "",
          }),
          signal: abortRef.current.signal,
        });

        if (!res.ok) throw new Error("AI unavailable");

        const data = (await res.json()) as {
          hint?: string;
          conceptPointer?: string;
        };

        const hint: SocraticHint = {
          level: nextLevel,
          question: data.hint?.trim() || fallbackHint().question,
          conceptPointer:
            data.conceptPointer?.trim() || fallbackHint().conceptPointer,
        };

        setHints((prev) => [...prev, hint]);
        return hint;
      } catch (e) {
        if ((e as Error).name === "AbortError") return null;

        const hint = fallbackHint();
        setHints((prev) => [...prev, hint]);

        if (e instanceof Error && e.message !== "AI unavailable") {
          setError(e.message);
        }
        return hint;
      } finally {
        setIsLoading(false);
      }
    },
    [challenge, isLoading],
  );

  return {
    getHint,
    hints,
    hintLevel,
    isLoading,
    isExhausted,
    error,
    resetHints,
  };
}
