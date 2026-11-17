import {
  HABIT_BADGES,
  SCAM_LEVELS,
  SCAM_SCENARIOS,
  type HabitTag,
  type ScamChoice,
  type ScamScenario,
} from "../data/scamScenarios";

/**
 * Pure level logic for Scam Survival: counts, resets and forgiveness all live
 * here, not in the UI or in a prompt. Progress is plain JSON.
 */

export interface ScamProgress {
  /** Scenario ids answered safely the first time they counted. */
  completed: string[];
  /** Counters per good habit, from counted scenarios only. */
  habits: Record<HabitTag, number>;
  /** Slips (non-safe answers on uncompleted scenarios) per level. */
  slips: Record<string, number>;
}

export interface ChoiceResult {
  scenario: ScamScenario;
  choice: ScamChoice;
  /** True when this answer counted toward the level and habit counters. */
  counted: boolean;
  /** True on the first slip in a level: show a gentle reflection. */
  reflection: boolean;
  newBadges: string[];
  levelCompleted: boolean;
}

export function emptyProgress(): ScamProgress {
  return {
    completed: [],
    habits: { pause: 0, verify: 0, resist_escalation: 0, balanced: 0 },
    slips: {},
  };
}

export function getScenario(id: string): ScamScenario | undefined {
  return SCAM_SCENARIOS.find((s) => s.id === id);
}

/** Read saved data defensively: old or partial saves load without crashing. */
export function normalizeProgress(raw: unknown): ScamProgress {
  const base = emptyProgress();
  if (!raw || typeof raw !== "object") return base;
  const r = raw as Partial<ScamProgress>;
  if (Array.isArray(r.completed)) {
    base.completed = r.completed.filter(
      (id) => typeof id === "string" && getScenario(id),
    );
  }
  if (r.habits && typeof r.habits === "object") {
    for (const tag of Object.keys(base.habits) as HabitTag[]) {
      const v = r.habits[tag];
      if (typeof v === "number" && v >= 0) base.habits[tag] = Math.floor(v);
    }
  }
  if (r.slips && typeof r.slips === "object") {
    for (const [k, v] of Object.entries(r.slips)) {
      if (typeof v === "number" && v >= 0) base.slips[k] = Math.floor(v);
    }
  }
  return base;
}

export function scenariosForLevel(level: number): ScamScenario[] {
  return SCAM_SCENARIOS.filter((s) => s.level === level);
}

/** Share of a level's scenarios that use a distinct template. */
export function templateVariety(level: number): number {
  const list = scenariosForLevel(level);
  if (list.length === 0) return 1;
  return new Set(list.map((s) => s.template)).size / list.length;
}

export function isLevelComplete(p: ScamProgress, level: number): boolean {
  const list = scenariosForLevel(level);
  return list.length > 0 && list.every((s) => p.completed.includes(s.id));
}

export function isLevelUnlocked(p: ScamProgress, level: number): boolean {
  if (level <= 1) return true;
  return isLevelComplete(p, level - 1);
}

export function nextScenario(
  p: ScamProgress,
  level: number,
): ScamScenario | null {
  return (
    scenariosForLevel(level).find((s) => !p.completed.includes(s.id)) ?? null
  );
}

export function earnedBadges(p: ScamProgress) {
  return HABIT_BADGES.filter((b) => p.habits[b.tag] >= b.threshold);
}

export function applyChoice(
  prev: ScamProgress,
  scenarioId: string,
  choiceId: string,
  opts: { practice?: boolean } = {},
): { progress: ScamProgress; result: ChoiceResult } {
  const scenario = getScenario(scenarioId);
  if (!scenario) throw new Error(`Unknown scenario: ${scenarioId}`);
  const choice = scenario.choices.find((c) => c.id === choiceId);
  if (!choice) throw new Error(`Unknown choice: ${choiceId}`);

  const result: ChoiceResult = {
    scenario,
    choice,
    counted: false,
    reflection: false,
    newBadges: [],
    levelCompleted: false,
  };

  const alreadyDone = prev.completed.includes(scenarioId);
  // Practice and repeats show feedback but change nothing.
  if (opts.practice || alreadyDone) return { progress: prev, result };

  const progress: ScamProgress = {
    completed: [...prev.completed],
    habits: { ...prev.habits },
    slips: { ...prev.slips },
  };
  const levelKey = String(scenario.level);

  if (choice.outcome === "safe") {
    progress.completed.push(scenarioId);
    for (const tag of scenario.habit_tags) progress.habits[tag] += 1;
    result.counted = true;
    const before = new Set(earnedBadges(prev).map((b) => b.tag));
    result.newBadges = earnedBadges(progress)
      .filter((b) => !before.has(b.tag))
      .map((b) => b.name);
    result.levelCompleted = isLevelComplete(progress, scenario.level);
  } else {
    const slips = (progress.slips[levelKey] ?? 0) + 1;
    progress.slips[levelKey] = slips;
    result.reflection = slips === 1;
  }
  return { progress, result };
}

/** Replay a level from the start. Habit counters stay: they are lifetime. */
export function resetLevel(p: ScamProgress, level: number): ScamProgress {
  const ids = new Set(scenariosForLevel(level).map((s) => s.id));
  const slips = { ...p.slips };
  delete slips[String(level)];
  return {
    completed: p.completed.filter((id) => !ids.has(id)),
    habits: { ...p.habits },
    slips,
  };
}

export { SCAM_LEVELS };
