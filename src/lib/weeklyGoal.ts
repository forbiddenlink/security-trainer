/**
 * Weekly XP goal. XP is logged per UTC day (matching the store's other date
 * keys) and compared over a rolling 7 days, so there is no Monday reset to
 * miss. The store's `xp` field resets at each level-up, which is why it
 * cannot be reused for this.
 */
export type XpByDay = Record<string, number>;

export interface WeeklyTier {
  name: string;
  xp: number;
}

export const WEEKLY_TIERS: readonly WeeklyTier[] = [
  { name: "On duty", xp: 250 },
  { name: "Committed", xp: 600 },
  { name: "Relentless", xp: 1200 },
];

const DAY_MS = 86_400_000;
const KEEP_DAYS = 14;

const dayKey = (d: Date): string => d.toISOString().split("T")[0];

export function addXpToDay(
  log: XpByDay,
  amount: number,
  now: Date = new Date(),
): XpByDay {
  if (!(amount > 0)) return log;
  const today = dayKey(now);
  const oldest = dayKey(new Date(now.getTime() - (KEEP_DAYS - 1) * DAY_MS));
  const next: XpByDay = {};
  for (const [day, xp] of Object.entries(log)) {
    if (day >= oldest) next[day] = xp;
  }
  next[today] = (next[today] ?? 0) + amount;
  return next;
}

export interface WeeklyProgress {
  thisWeek: number;
  lastWeek: number;
  reached: WeeklyTier | null;
  next: WeeklyTier | null;
}

export function getWeeklyProgress(
  log: XpByDay,
  now: Date = new Date(),
): WeeklyProgress {
  let thisWeek = 0;
  let lastWeek = 0;
  for (let i = 0; i < KEEP_DAYS; i++) {
    const xp = log[dayKey(new Date(now.getTime() - i * DAY_MS))] ?? 0;
    if (i < 7) thisWeek += xp;
    else lastWeek += xp;
  }
  const reached =
    [...WEEKLY_TIERS].reverse().find((t) => thisWeek >= t.xp) ?? null;
  const next = WEEKLY_TIERS.find((t) => thisWeek < t.xp) ?? null;
  return { thisWeek, lastWeek, reached, next };
}
