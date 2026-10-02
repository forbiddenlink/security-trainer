import { describe, it, expect } from "vitest";
import { MODULES } from "./modules";
import { getOwaspCategories } from "./owaspTop10";

describe("OWASP Top 10:2025 mapping", () => {
  it("only maps module ids that exist", () => {
    const ids = new Set(MODULES.map((m) => m.id));
    const mapped = MODULES.filter((m) => getOwaspCategories(m.id).length > 0);
    expect(mapped.length).toBe(23);
    mapped.forEach((m) => expect(ids.has(m.id)).toBe(true));
  });

  it("maps injection modules to A05", () => {
    expect(getOwaspCategories("sql-injection").map((c) => c.id)).toEqual([
      "A05",
    ]);
  });

  it("returns nothing for unmapped modules", () => {
    expect(getOwaspCategories("gdpr-fundamentals")).toEqual([]);
  });
});
