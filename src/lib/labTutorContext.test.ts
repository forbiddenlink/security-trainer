import { describe, it, expect } from "vitest";
import { buildLabTutorChallenge, getLabTutorCategory } from "./labTutorContext";

describe("labTutorContext", () => {
  it("maps known labs to specific categories", () => {
    expect(getLabTutorCategory("sqli-lab")).toBe("sql-injection");
    expect(getLabTutorCategory("xss-lab")).toBe("xss");
    expect(getLabTutorCategory("path-lab")).toBe("path-traversal");
    expect(getLabTutorCategory("cmdi-lab")).toBe("command-injection");
  });

  it("falls back to general for unknown labs", () => {
    expect(getLabTutorCategory("unknown-future-lab")).toBe("general");
  });

  it("builds a challenge with three static Socratic hints", () => {
    const challenge = buildLabTutorChallenge("sqli-lab", {
      initialCode: "const q = 'SELECT * FROM users WHERE id=' + id",
      solutionCode: "const q = 'SELECT * FROM users WHERE id=?'",
      instructions: "Fix the injection",
    });

    expect(challenge.id).toBe("sqli-lab");
    expect(challenge.category).toBe("sql-injection");
    expect(challenge.staticHints).toHaveLength(3);
    expect(challenge.vulnerableCode).toContain("SELECT");
    // Hints should be questions, not direct spoilers
    expect(challenge.staticHints[0].endsWith("?")).toBe(true);
  });
});
