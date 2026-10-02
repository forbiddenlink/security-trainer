import { describe, it, expect } from "vitest";
import { getRank, RANKS } from "./rank";

describe("getRank", () => {
  it("starts every learner at the first rank", () => {
    const r = getRank(0, 0);
    expect(r.current).toEqual(RANKS[0]);
    expect(r.next).toEqual(RANKS[1]);
  });

  it("needs both the module count and the path count for a rank", () => {
    const needs = RANKS[2];
    expect(getRank(needs.modules, needs.paths - 1).current.name).not.toBe(
      needs.name,
    );
    expect(getRank(needs.modules, needs.paths).current.name).toBe(needs.name);
  });

  it("reports progress toward the next rank between 0 and 1", () => {
    const r = getRank(RANKS[1].modules + 1, 0);
    expect(r.progress).toBeGreaterThanOrEqual(0);
    expect(r.progress).toBeLessThanOrEqual(1);
  });

  it("has no next rank at the top", () => {
    const top = RANKS[RANKS.length - 1];
    const r = getRank(top.modules, top.paths);
    expect(r.current).toEqual(top);
    expect(r.next).toBeNull();
    expect(r.progress).toBe(1);
  });
});
