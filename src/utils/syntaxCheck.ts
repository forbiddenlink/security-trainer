/**
 * Lightweight, eval-free syntax heuristic for the lab terminal's `syntax`
 * command. Deliberately does NOT use `new Function`/`eval` (which would require
 * a CSP `unsafe-eval` allowance and execute learner-controlled code). It only
 * checks bracket balance and string termination — enough for a teaching hint.
 *
 * Returns null when nothing obvious is wrong, or a human-readable error string.
 */
export function checkSyntaxHeuristic(code: string): string | null {
  const pairs: Record<string, string> = { ")": "(", "]": "[", "}": "{" };
  const openers = new Set(["(", "[", "{"]);
  const stack: string[] = [];

  let inString: '"' | "'" | "`" | null = null;
  let inLineComment = false;
  let inBlockComment = false;

  for (let i = 0; i < code.length; i++) {
    const ch = code[i];
    const next = code[i + 1];

    if (inLineComment) {
      if (ch === "\n") inLineComment = false;
      continue;
    }
    if (inBlockComment) {
      if (ch === "*" && next === "/") {
        inBlockComment = false;
        i++;
      }
      continue;
    }
    if (inString) {
      if (ch === "\\") {
        i++; // skip escaped char
        continue;
      }
      if (ch === inString) inString = null;
      continue;
    }

    // not in string/comment
    if (ch === "/" && next === "/") {
      inLineComment = true;
      i++;
      continue;
    }
    if (ch === "/" && next === "*") {
      inBlockComment = true;
      i++;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      inString = ch;
      continue;
    }
    if (openers.has(ch)) {
      stack.push(ch);
      continue;
    }
    if (ch in pairs) {
      const last = stack.pop();
      if (last !== pairs[ch]) {
        return `Unbalanced or mismatched '${ch}'.`;
      }
    }
  }

  if (inString) return "Unterminated string literal.";
  if (inBlockComment) return "Unterminated block comment.";
  if (stack.length > 0) {
    return `Unclosed '${stack[stack.length - 1]}'.`;
  }
  return null;
}
