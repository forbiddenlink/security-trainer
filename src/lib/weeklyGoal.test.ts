import { describe, it, expect } from "vitest";
import { addXpToDay, getWeeklyProgress, WEEKLY_TIERS } from "./weeklyGoal";

const NOW = new Date("2026-10-02T12:00:00Z");

describe("addXpToDay", () => {
  it("adds to today's bucket and keeps only the last 14 days", () => {
    const log = { "2026-09-10": 50, "2026-10-01": 20 };
    const next = addXpToDay(log, 30, NOW);
    expect(next["2026-10-02"]).toBe(30);
    expect(next["2026-10-01"]).toBe(20);
    expect(next["2026-09-10"]).toBeUndefined();
  });

  it("ignores zero and negative amounts", () => {
    expect(addXpToDay({}, 0, NOW)).toEqual({});
    expect(addXpToDay({}, -5, NOW)).toEqual({});
  });
});

describe("getWeeklyProgress", () => {
  it("sums the rolling 7 days and the 7 before them", () => {
    const log = {
      "2026-10-02": 100,
      "2026-09-26": 50, // 6 days ago, this week
      "2026-09-25": 70, // 7 days ago, last week
      "2026-09-19": 30, // 13 days ago, last week
    };
    const p = getWeeklyProgress(log, NOW);
    expect(p.thisWeek).toBe(150);
    expect(p.lastWeek).toBe(100);
  });

  it("names the next tier to reach and the tiers already cleared", () => {
    const p = getWeeklyProgress({ "2026-10-02": WEEKLY_TIERS[0].xp }, NOW);
    expect(p.reached?.name).toBe(WEEKLY_TIERS[0].name);
    expect(p.next?.name).toBe(WEEKLY_TIERS[1].name);
  });

  it("has no reached tier for an empty week", () => {
    const p = getWeeklyProgress({}, NOW);
    expect(p.reached).toBeNull();
    expect(p.next).toEqual(WEEKLY_TIERS[0]);
  });
});
