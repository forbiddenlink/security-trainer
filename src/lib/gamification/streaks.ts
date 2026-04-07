/**
 * Streak System for Security Trainer
 *
 * Handles daily streak tracking, bonuses, and streak-related calculations.
 */

export interface StreakData {
  currentStreak: number;
  longestStreak: number;
  lastActivityDate: string | null;
  streakStartDate: string | null;
  totalDaysActive: number;
  weeklyActivity: boolean[];
}

export interface StreakBonus {
  multiplier: number;
  bonusXp: number;
  nextMilestone: number;
  milestoneReward: number;
}

export const STREAK_CONFIG = {
  maxMultiplier: 2.0,
  multiplierPerDay: 0.1,
  gracePeriodHours: 24,
  milestones: [3, 7, 14, 30, 60, 100, 365],
  milestoneRewards: {
    3: 50,
    7: 100,
    14: 200,
    30: 500,
    60: 1000,
    100: 2500,
    365: 10000,
  },
} as const;

function getDateString(date: Date = new Date()): string {
  return date.toISOString().split('T')[0];
}

function daysBetween(date1: string, date2: string): number {
  const d1 = new Date(date1);
  const d2 = new Date(date2);
  const diffTime = Math.abs(d2.getTime() - d1.getTime());
  return Math.floor(diffTime / (1000 * 60 * 60 * 24));
}

export function createInitialStreakData(): StreakData {
  return {
    currentStreak: 0,
    longestStreak: 0,
    lastActivityDate: null,
    streakStartDate: null,
    totalDaysActive: 0,
    weeklyActivity: [false, false, false, false, false, false, false],
  };
}

export function updateStreak(data: StreakData, activityDate: Date = new Date()): StreakData {
  const today = getDateString(activityDate);
  const newData = { ...data };

  // Already logged activity today
  if (data.lastActivityDate === today) {
    return data;
  }

  // First activity ever
  if (!data.lastActivityDate) {
    return {
      ...newData,
      currentStreak: 1,
      longestStreak: Math.max(1, data.longestStreak),
      lastActivityDate: today,
      streakStartDate: today,
      totalDaysActive: data.totalDaysActive + 1,
      weeklyActivity: updateWeeklyActivity(data.weeklyActivity, activityDate),
    };
  }

  const daysSinceLastActivity = daysBetween(data.lastActivityDate, today);

  if (daysSinceLastActivity === 1) {
    // Consecutive day - extend streak
    const newStreak = data.currentStreak + 1;
    return {
      ...newData,
      currentStreak: newStreak,
      longestStreak: Math.max(newStreak, data.longestStreak),
      lastActivityDate: today,
      totalDaysActive: data.totalDaysActive + 1,
      weeklyActivity: updateWeeklyActivity(data.weeklyActivity, activityDate),
    };
  } else if (daysSinceLastActivity > 1) {
    // Streak broken - reset
    return {
      ...newData,
      currentStreak: 1,
      lastActivityDate: today,
      streakStartDate: today,
      totalDaysActive: data.totalDaysActive + 1,
      weeklyActivity: updateWeeklyActivity(data.weeklyActivity, activityDate),
    };
  }

  return data;
}

function updateWeeklyActivity(current: boolean[], date: Date): boolean[] {
  const dayOfWeek = date.getDay();
  const updated = [...current];
  updated[dayOfWeek] = true;
  return updated;
}

export function resetWeeklyActivity(): boolean[] {
  return [false, false, false, false, false, false, false];
}

export function getStreakMultiplier(streak: number): number {
  const bonus = Math.min(streak * STREAK_CONFIG.multiplierPerDay, STREAK_CONFIG.maxMultiplier - 1);
  return 1 + bonus;
}

export function getStreakBonus(streak: number): StreakBonus {
  const multiplier = getStreakMultiplier(streak);

  // Find next milestone
  const nextMilestone = STREAK_CONFIG.milestones.find(m => m > streak) ?? 365;
  const milestoneReward = STREAK_CONFIG.milestoneRewards[nextMilestone as keyof typeof STREAK_CONFIG.milestoneRewards] ?? 0;

  // Calculate bonus XP percentage
  const bonusXp = Math.round((multiplier - 1) * 100);

  return {
    multiplier,
    bonusXp,
    nextMilestone,
    milestoneReward,
  };
}

export function isStreakAtRisk(data: StreakData): boolean {
  if (!data.lastActivityDate || data.currentStreak === 0) {
    return false;
  }

  const today = getDateString();
  const daysSinceActivity = daysBetween(data.lastActivityDate, today);

  // Streak is at risk if no activity today and there's an active streak
  return daysSinceActivity === 1 && data.currentStreak > 0;
}

export function getStreakStatus(data: StreakData): 'active' | 'at_risk' | 'broken' | 'none' {
  if (data.currentStreak === 0) {
    return 'none';
  }

  if (!data.lastActivityDate) {
    return 'none';
  }

  const today = getDateString();
  const daysSinceActivity = daysBetween(data.lastActivityDate, today);

  if (daysSinceActivity === 0) {
    return 'active';
  } else if (daysSinceActivity === 1) {
    return 'at_risk';
  } else {
    return 'broken';
  }
}

export function formatStreakMessage(streak: number): string {
  if (streak === 0) {
    return 'Start your streak today!';
  } else if (streak === 1) {
    return '1 day streak - Keep it going!';
  } else if (streak < 7) {
    return `${streak} day streak! ${7 - streak} more to reach a week!`;
  } else if (streak < 30) {
    return `${streak} day streak! Amazing progress!`;
  } else if (streak < 100) {
    return `${streak} day streak! You're unstoppable!`;
  } else {
    return `${streak} day streak! LEGENDARY!`;
  }
}

export function getStreakMilestoneProgress(streak: number): { current: number; target: number; progress: number } {
  const milestones = STREAK_CONFIG.milestones;
  const currentMilestone = milestones.filter(m => m <= streak).pop() ?? 0;
  const nextMilestone = milestones.find(m => m > streak) ?? milestones[milestones.length - 1];

  const progress = ((streak - currentMilestone) / (nextMilestone - currentMilestone)) * 100;

  return {
    current: currentMilestone,
    target: nextMilestone,
    progress: Math.min(progress, 100),
  };
}
