import { describe, expect, it } from "vitest";
import {
  SCAM_SCENARIOS,
  SCAM_LEVELS,
  type ScamScenario,
} from "../data/scamScenarios";
import { MODULES } from "../data/modules";
import {
  applyChoice,
  earnedBadges,
  emptyProgress,
  isLevelComplete,
  isLevelUnlocked,
  nextScenario,
  resetLevel,
  scenariosForLevel,
  templateVariety,
} from "./scamSurvival";

const safeId = (s: ScamScenario) =>
  s.choices.find((c) => c.outcome === "safe")!.id;
const riskyId = (s: ScamScenario) =>
  s.choices.find((c) => c.outcome === "risky")!.id;
const cautiousId = (s: ScamScenario) =>
  s.choices.find((c) => c.outcome === "over_cautious")!.id;

describe("scam scenario content", () => {
  it("has 5 levels with scenarios, and unique ids", () => {
    for (const l of [1, 2, 3, 4, 5]) {
      expect(scenariosForLevel(l).length).toBeGreaterThanOrEqual(3);
    }
    expect(new Set(SCAM_SCENARIOS.map((s) => s.id)).size).toBe(
      SCAM_SCENARIOS.length,
    );
  });

  it("every scenario has 3 to 4 choices with a safe, risky and over-cautious one", () => {
    for (const s of SCAM_SCENARIOS) {
      expect(s.choices.length).toBeGreaterThanOrEqual(3);
      expect(s.choices.length).toBeLessThanOrEqual(4);
      const outcomes = s.choices.map((c) => c.outcome);
      expect(outcomes).toContain("safe");
      expect(outcomes).toContain("risky");
      expect(outcomes).toContain("over_cautious");
      for (const c of s.choices) expect(c.feedback.length).toBeGreaterThan(10);
    }
  });

  it("level 4 scenarios are 3 to 4 message threads", () => {
    for (const s of scenariosForLevel(4)) {
      expect(s.scenario_type).toBe("thread");
      expect(s.messages.length).toBeGreaterThanOrEqual(3);
      expect(s.messages.length).toBeLessThanOrEqual(4);
    }
  });

  it("level 5 mixes legitimate and fraudulent messages", () => {
    const l5 = scenariosForLevel(5);
    expect(l5.some((s) => s.is_legitimate)).toBe(true);
    expect(l5.some((s) => !s.is_legitimate)).toBe(true);
  });

  it("fraudulent scenarios name red flags, legitimate ones need not", () => {
    for (const s of SCAM_SCENARIOS) {
      if (!s.is_legitimate) expect(s.red_flags.length).toBeGreaterThan(0);
    }
  });

  it("uses only placeholder domains and fictional phone numbers", () => {
    const text = JSON.stringify(SCAM_SCENARIOS);
    for (const m of text.matchAll(/https?:\/\/[^\s"]+/g)) {
      expect(m[0]).toMatch(/\.(example|test|invalid)\b/);
    }
    for (const m of text.matchAll(/\b\d{3}[-. ]\d{4}\b/g)) {
      expect(m[0]).toMatch(/^555[-. ]01\d\d$/);
    }
  });

  it("at least 70 percent of each level comes from different templates", () => {
    for (const l of [1, 2, 3, 4, 5]) {
      expect(templateVariety(l)).toBeGreaterThanOrEqual(0.7);
    }
  });

  it("level references point at real lessons", () => {
    for (const lv of SCAM_LEVELS) {
      const mod = MODULES.find((m) => m.id === lv.lesson.moduleId);
      expect(mod).toBeDefined();
      expect(mod!.lessons.some((x) => x.id === lv.lesson.lessonId)).toBe(true);
    }
  });
});

describe("scam level logic", () => {
  it("unlocks only level 1 at the start", () => {
    const p = emptyProgress();
    expect(isLevelUnlocked(p, 1)).toBe(true);
    expect(isLevelUnlocked(p, 2)).toBe(false);
  });

  it("a safe answer counts once and bumps the habit counter", () => {
    const s = scenariosForLevel(1)[0];
    const r1 = applyChoice(emptyProgress(), s.id, safeId(s));
    expect(r1.result.counted).toBe(true);
    expect(r1.progress.completed).toContain(s.id);
    expect(r1.progress.habits.pause).toBe(1);
    const r2 = applyChoice(r1.progress, s.id, safeId(s));
    expect(r2.result.counted).toBe(false);
    expect(r2.progress.habits.pause).toBe(1);
  });

  it("a first slip gets a reflection, never blocks, and can be retried", () => {
    const s = scenariosForLevel(1)[0];
    const r1 = applyChoice(emptyProgress(), s.id, riskyId(s));
    expect(r1.result.counted).toBe(false);
    expect(r1.result.reflection).toBe(true);
    expect(r1.progress.completed).not.toContain(s.id);
    const r2 = applyChoice(r1.progress, s.id, cautiousId(s));
    expect(r2.result.reflection).toBe(false);
    const r3 = applyChoice(r2.progress, s.id, safeId(s));
    expect(r3.result.counted).toBe(true);
    expect(r3.progress.slips["1"]).toBe(2);
  });

  it("practice mode changes nothing", () => {
    const s = scenariosForLevel(1)[0];
    const r = applyChoice(emptyProgress(), s.id, safeId(s), { practice: true });
    expect(r.progress).toEqual(emptyProgress());
    expect(r.result.counted).toBe(false);
  });

  it("completing a level unlocks the next and awards a habit badge at 3", () => {
    let p = emptyProgress();
    for (const s of scenariosForLevel(1))
      p = applyChoice(p, s.id, safeId(s)).progress;
    expect(isLevelComplete(p, 1)).toBe(true);
    expect(isLevelUnlocked(p, 2)).toBe(true);
    expect(earnedBadges(p).map((b) => b.tag)).toContain("pause");
    expect(nextScenario(p, 1)).toBeNull();
  });

  it("an unknown scenario or choice throws", () => {
    expect(() => applyChoice(emptyProgress(), "nope", "a")).toThrow();
    const s = scenariosForLevel(1)[0];
    expect(() => applyChoice(emptyProgress(), s.id, "zzz")).toThrow();
  });

  it("resetting a level clears its completions but keeps habit counts", () => {
    let p = emptyProgress();
    for (const s of scenariosForLevel(1))
      p = applyChoice(p, s.id, safeId(s)).progress;
    const before = p.habits.pause;
    p = resetLevel(p, 1);
    expect(isLevelComplete(p, 1)).toBe(false);
    expect(p.habits.pause).toBe(before);
    expect(p.slips["1"] ?? 0).toBe(0);
  });

  it("does not mutate the input progress", () => {
    const s = scenariosForLevel(1)[0];
    const p = emptyProgress();
    const snap = JSON.stringify(p);
    applyChoice(p, s.id, safeId(s));
    expect(JSON.stringify(p)).toBe(snap);
  });
});
