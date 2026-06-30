import { describe, it, expect } from "vitest";
import { MODULES } from "./modules";
import { LEARNING_PATHS } from "./learningPaths";

describe("LEARNING_PATHS", () => {
  const moduleIds = new Set(MODULES.map((m) => m.id));

  it("references only valid module IDs", () => {
    for (const path of LEARNING_PATHS) {
      for (const moduleId of path.modules) {
        expect(
          moduleIds.has(moduleId),
          `Path "${path.id}" references unknown module "${moduleId}"`,
        ).toBe(true);
      }
    }
  });

  it("has no duplicate module IDs within a path", () => {
    for (const path of LEARNING_PATHS) {
      const unique = new Set(path.modules);
      expect(unique.size, `Path "${path.id}" has duplicate modules`).toBe(
        path.modules.length,
      );
    }
  });

  it("includes every module in at least one path", () => {
    const covered = new Set(LEARNING_PATHS.flatMap((p) => p.modules));
    const uncovered = MODULES.map((m) => m.id).filter((id) => !covered.has(id));
    expect(
      uncovered,
      `Modules not in any path: ${uncovered.join(", ")}`,
    ).toEqual([]);
  });

  it("has unique path IDs", () => {
    const ids = LEARNING_PATHS.map((p) => p.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
