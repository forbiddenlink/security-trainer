/**
 * Game-related utility functions
 */

/** XP required per level */
export const XP_PER_LEVEL = 1000;

/**
 * Calculate XP needed to reach the next level
 */
export function getNextLevelXp(level: number): number {
  return level * XP_PER_LEVEL;
}

/**
 * Calculate progress percentage towards next level
 */
export function getLevelProgress(xp: number, level: number): number {
  const nextLevelXp = getNextLevelXp(level);
  return Math.min((xp / nextLevelXp) * 100, 100);
}

/**
 * Calculate XP remaining to next level
 */
export function getXpToNextLevel(xp: number, level: number): number {
  return getNextLevelXp(level) - xp;
}
