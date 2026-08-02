import { describe, it, expect } from "vitest";
import {
  LIVE_TARGETS,
  getTargetsForModule,
  getTargetsForCtfTags,
} from "./liveTargets";

describe("liveTargets", () => {
  it("exposes three lab stack targets", () => {
    expect(LIVE_TARGETS).toHaveLength(3);
    expect(LIVE_TARGETS.map((t) => t.hostPort).sort()).toEqual([
      3333, 3334, 3335,
    ]);
  });

  it("maps sql-injection to juice shop and dvwa", () => {
    const targets = getTargetsForModule("sql-injection");
    expect(targets.map((t) => t.id)).toEqual(
      expect.arrayContaining(["juice-shop", "dvwa"]),
    );
  });

  it("maps web CTF tags to juice shop", () => {
    const targets = getTargetsForCtfTags(["web", "cookie"]);
    expect(targets.some((t) => t.id === "juice-shop")).toBe(true);
  });
});
