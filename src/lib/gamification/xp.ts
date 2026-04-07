/**
 * XP System for Security Trainer
 *
 * Handles experience points, levels, and XP calculations.
 */

export interface XPConfig {
  baseXpPerLesson: number;
  baseXpPerQuiz: number;
  baseXpPerLab: number;
  baseXpPerModule: number;
  baseXpPerLevel: number;
  maxLevel: number;
  difficultyMultipliers: Record<string, number>;
}

export const XP_CONFIG: XPConfig = {
  baseXpPerLesson: 25,
  baseXpPerQuiz: 50,
  baseXpPerLab: 75,
  baseXpPerModule: 200,
  baseXpPerLevel: 1000,
  maxLevel: 100,
  difficultyMultipliers: {
    beginner: 1.0,
    intermediate: 1.5,
    advanced: 2.0,
    expert: 2.5,
  },
};

export interface LevelInfo {
  level: number;
  currentXp: number;
  xpForNextLevel: number;
  totalXp: number;
  progress: number;
  title: string;
}

export const LEVEL_TITLES: Record<number, string> = {
  1: 'Recruit',
  5: 'Trainee',
  10: 'Agent',
  15: 'Field Agent',
  20: 'Senior Agent',
  25: 'Special Agent',
  30: 'Lead Agent',
  40: 'Supervisor',
  50: 'Director',
  60: 'Chief',
  75: 'Commander',
  90: 'Elite Operative',
  100: 'Legendary Master',
};

export function getLevelTitle(level: number): string {
  const thresholds = Object.keys(LEVEL_TITLES)
    .map(Number)
    .sort((a, b) => b - a);

  for (const threshold of thresholds) {
    if (level >= threshold) {
      return LEVEL_TITLES[threshold];
    }
  }
  return 'Recruit';
}

export function calculateLevel(totalXp: number): number {
  let level = 1;
  let xpNeeded = XP_CONFIG.baseXpPerLevel;

  while (totalXp >= xpNeeded && level < XP_CONFIG.maxLevel) {
    totalXp -= xpNeeded;
    level++;
    // Progressive XP curve: each level requires 5% more XP
    xpNeeded = Math.floor(XP_CONFIG.baseXpPerLevel * Math.pow(1.05, level - 1));
  }

  return level;
}

export function getXpForLevel(level: number): number {
  return Math.floor(XP_CONFIG.baseXpPerLevel * Math.pow(1.05, level - 1));
}

export function getTotalXpForLevel(level: number): number {
  let total = 0;
  for (let i = 1; i < level; i++) {
    total += getXpForLevel(i);
  }
  return total;
}

export function getLevelInfo(totalXp: number): LevelInfo {
  const level = calculateLevel(totalXp);
  const totalXpForCurrentLevel = getTotalXpForLevel(level);
  const xpForNextLevel = getXpForLevel(level);
  const currentXp = totalXp - totalXpForCurrentLevel;
  const progress = (currentXp / xpForNextLevel) * 100;

  return {
    level,
    currentXp,
    xpForNextLevel,
    totalXp,
    progress: Math.min(progress, 100),
    title: getLevelTitle(level),
  };
}

export function calculateXpReward(
  baseXp: number,
  options: {
    difficulty?: string;
    streakMultiplier?: number;
    bonusMultiplier?: number;
    isPerfect?: boolean;
  } = {}
): number {
  const {
    difficulty = 'beginner',
    streakMultiplier = 1,
    bonusMultiplier = 1,
    isPerfect = false,
  } = options;

  let xp = baseXp;

  // Apply difficulty multiplier
  const diffMultiplier = XP_CONFIG.difficultyMultipliers[difficulty.toLowerCase()] ?? 1;
  xp *= diffMultiplier;

  // Apply streak multiplier (capped at 2x)
  xp *= Math.min(streakMultiplier, 2);

  // Apply bonus multiplier
  xp *= bonusMultiplier;

  // Perfect completion bonus (+25%)
  if (isPerfect) {
    xp *= 1.25;
  }

  return Math.round(xp);
}

export function calculateLessonXp(
  lessonType: 'theory' | 'quiz' | 'lab',
  options: {
    difficulty?: string;
    streakMultiplier?: number;
    score?: number;
  } = {}
): number {
  const baseXp = {
    theory: XP_CONFIG.baseXpPerLesson,
    quiz: XP_CONFIG.baseXpPerQuiz,
    lab: XP_CONFIG.baseXpPerLab,
  }[lessonType];

  return calculateXpReward(baseXp, {
    ...options,
    isPerfect: options.score === 100,
  });
}

export function getXpToNextMilestone(totalXp: number): { milestone: number; xpNeeded: number } {
  const milestones = [100, 500, 1000, 2500, 5000, 10000, 25000, 50000, 100000];
  const nextMilestone = milestones.find(m => m > totalXp) ?? milestones[milestones.length - 1];
  return {
    milestone: nextMilestone,
    xpNeeded: nextMilestone - totalXp,
  };
}
