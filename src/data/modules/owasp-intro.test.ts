import { describe, it, expect } from "vitest";
import { owaspIntro } from "./owasp-intro";

describe("owaspIntro lesson order", () => {
  it("opens on the hands-on lab, the first mission's promise", () => {
    expect(owaspIntro.lessons[0].type).toBe("lab");
    expect(owaspIntro.lessons[0].id).toBe("owasp-lab");
  });

  it("keeps the reading and the knowledge check after the lab", () => {
    expect(owaspIntro.lessons.map((l) => l.id)).toEqual([
      "owasp-lab",
      "owasp-1",
      "owasp-quiz-1",
    ]);
  });
});
