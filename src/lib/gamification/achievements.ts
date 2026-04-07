/**
 * Achievement Definitions for Security Trainer
 *
 * Defines all unlockable achievements with their requirements and rewards.
 */

export type AchievementCategory =
  | 'learning'
  | 'completion'
  | 'streak'
  | 'challenge'
  | 'mastery'
  | 'special';

export type AchievementRarity = 'common' | 'rare' | 'epic' | 'legendary';

export interface Achievement {
  id: string;
  name: string;
  description: string;
  category: AchievementCategory;
  rarity: AchievementRarity;
  xp: number;
  icon: string;
  requirement: {
    type: 'lessons' | 'modules' | 'streak' | 'score' | 'challenge' | 'special';
    value: number;
    condition?: string;
  };
  secret?: boolean;
}

export const ACHIEVEMENTS: Record<string, Achievement> = {
  // Learning Achievements
  first_lesson: {
    id: 'first_lesson',
    name: 'First Steps',
    description: 'Complete your first lesson',
    category: 'learning',
    rarity: 'common',
    xp: 10,
    icon: 'star',
    requirement: { type: 'lessons', value: 1 },
  },
  knowledge_seeker: {
    id: 'knowledge_seeker',
    name: 'Knowledge Seeker',
    description: 'Complete 10 lessons',
    category: 'learning',
    rarity: 'rare',
    xp: 50,
    icon: 'book',
    requirement: { type: 'lessons', value: 10 },
  },
  security_scholar: {
    id: 'security_scholar',
    name: 'Security Scholar',
    description: 'Complete 25 lessons',
    category: 'learning',
    rarity: 'epic',
    xp: 150,
    icon: 'graduation-cap',
    requirement: { type: 'lessons', value: 25 },
  },
  master_operative: {
    id: 'master_operative',
    name: 'Master Operative',
    description: 'Complete 50 lessons',
    category: 'learning',
    rarity: 'legendary',
    xp: 500,
    icon: 'award',
    requirement: { type: 'lessons', value: 50 },
  },

  // Completion Achievements
  first_module: {
    id: 'first_module',
    name: 'Module Cleared',
    description: 'Complete your first module',
    category: 'completion',
    rarity: 'common',
    xp: 25,
    icon: 'check-circle',
    requirement: { type: 'modules', value: 1 },
  },
  five_modules: {
    id: 'five_modules',
    name: 'Rising Agent',
    description: 'Complete 5 modules',
    category: 'completion',
    rarity: 'rare',
    xp: 100,
    icon: 'shield',
    requirement: { type: 'modules', value: 5 },
  },
  ten_modules: {
    id: 'ten_modules',
    name: 'Elite Defender',
    description: 'Complete 10 modules',
    category: 'completion',
    rarity: 'epic',
    xp: 300,
    icon: 'shield-check',
    requirement: { type: 'modules', value: 10 },
  },
  all_modules: {
    id: 'all_modules',
    name: 'Security Legend',
    description: 'Complete all available modules',
    category: 'completion',
    rarity: 'legendary',
    xp: 1000,
    icon: 'crown',
    requirement: { type: 'modules', value: 24 },
  },

  // Streak Achievements
  streak_3: {
    id: 'streak_3',
    name: 'Getting Started',
    description: 'Maintain a 3-day learning streak',
    category: 'streak',
    rarity: 'common',
    xp: 20,
    icon: 'flame',
    requirement: { type: 'streak', value: 3 },
  },
  streak_7: {
    id: 'streak_7',
    name: 'Week Warrior',
    description: 'Maintain a 7-day learning streak',
    category: 'streak',
    rarity: 'rare',
    xp: 50,
    icon: 'flame',
    requirement: { type: 'streak', value: 7 },
  },
  streak_14: {
    id: 'streak_14',
    name: 'Committed Agent',
    description: 'Maintain a 14-day learning streak',
    category: 'streak',
    rarity: 'epic',
    xp: 150,
    icon: 'flame',
    requirement: { type: 'streak', value: 14 },
  },
  streak_30: {
    id: 'streak_30',
    name: 'Unstoppable',
    description: 'Maintain a 30-day learning streak',
    category: 'streak',
    rarity: 'legendary',
    xp: 500,
    icon: 'flame',
    requirement: { type: 'streak', value: 30 },
  },

  // Challenge Achievements
  perfect_score: {
    id: 'perfect_score',
    name: 'Perfectionist',
    description: 'Score 100% on a quiz',
    category: 'challenge',
    rarity: 'rare',
    xp: 100,
    icon: 'target',
    requirement: { type: 'score', value: 100, condition: 'quiz' },
  },
  lab_master: {
    id: 'lab_master',
    name: 'Lab Master',
    description: 'Complete 10 hands-on labs',
    category: 'challenge',
    rarity: 'epic',
    xp: 200,
    icon: 'code',
    requirement: { type: 'challenge', value: 10, condition: 'lab' },
  },
  ctf_first: {
    id: 'ctf_first',
    name: 'First Flag',
    description: 'Capture your first CTF flag',
    category: 'challenge',
    rarity: 'rare',
    xp: 75,
    icon: 'flag',
    requirement: { type: 'challenge', value: 1, condition: 'ctf' },
  },
  ctf_hunter: {
    id: 'ctf_hunter',
    name: 'Flag Hunter',
    description: 'Capture 5 CTF flags',
    category: 'challenge',
    rarity: 'epic',
    xp: 250,
    icon: 'flag',
    requirement: { type: 'challenge', value: 5, condition: 'ctf' },
  },

  // Mastery Achievements
  xss_master: {
    id: 'xss_master',
    name: 'XSS Expert',
    description: 'Master all XSS-related content',
    category: 'mastery',
    rarity: 'epic',
    xp: 200,
    icon: 'zap',
    requirement: { type: 'special', value: 1, condition: 'xss_mastery' },
  },
  injection_master: {
    id: 'injection_master',
    name: 'Injection Specialist',
    description: 'Master all injection attack modules',
    category: 'mastery',
    rarity: 'epic',
    xp: 200,
    icon: 'database',
    requirement: { type: 'special', value: 1, condition: 'injection_mastery' },
  },
  auth_master: {
    id: 'auth_master',
    name: 'Authentication Guru',
    description: 'Master all authentication modules',
    category: 'mastery',
    rarity: 'epic',
    xp: 200,
    icon: 'lock',
    requirement: { type: 'special', value: 1, condition: 'auth_mastery' },
  },

  // Special Achievements
  daily_champion: {
    id: 'daily_champion',
    name: 'Daily Champion',
    description: 'Complete 10 daily challenges',
    category: 'special',
    rarity: 'rare',
    xp: 100,
    icon: 'calendar',
    requirement: { type: 'challenge', value: 10, condition: 'daily' },
  },
  speed_demon: {
    id: 'speed_demon',
    name: 'Speed Demon',
    description: 'Complete 3 lessons in one day',
    category: 'special',
    rarity: 'rare',
    xp: 75,
    icon: 'zap',
    requirement: { type: 'special', value: 3, condition: 'lessons_daily' },
  },
  night_owl: {
    id: 'night_owl',
    name: 'Night Owl',
    description: 'Complete a lesson after midnight',
    category: 'special',
    rarity: 'common',
    xp: 25,
    icon: 'moon',
    requirement: { type: 'special', value: 1, condition: 'night_lesson' },
    secret: true,
  },
  early_bird: {
    id: 'early_bird',
    name: 'Early Bird',
    description: 'Complete a lesson before 6 AM',
    category: 'special',
    rarity: 'common',
    xp: 25,
    icon: 'sun',
    requirement: { type: 'special', value: 1, condition: 'morning_lesson' },
    secret: true,
  },
};

export const RARITY_CONFIG: Record<AchievementRarity, { color: string; glow: string; multiplier: number }> = {
  common: {
    color: 'from-slate-400 to-slate-600',
    glow: 'shadow-slate-400/30',
    multiplier: 1,
  },
  rare: {
    color: 'from-blue-400 to-blue-600',
    glow: 'shadow-blue-400/30',
    multiplier: 1.5,
  },
  epic: {
    color: 'from-purple-400 to-pink-600',
    glow: 'shadow-purple-400/30',
    multiplier: 2,
  },
  legendary: {
    color: 'from-amber-400 to-orange-600',
    glow: 'shadow-amber-400/40',
    multiplier: 3,
  },
};

export function getAchievementById(id: string): Achievement | undefined {
  return ACHIEVEMENTS[id];
}

export function getAchievementsByCategory(category: AchievementCategory): Achievement[] {
  return Object.values(ACHIEVEMENTS).filter(a => a.category === category);
}

export function getVisibleAchievements(unlockedIds: string[]): Achievement[] {
  return Object.values(ACHIEVEMENTS).filter(
    a => !a.secret || unlockedIds.includes(a.id)
  );
}

export function calculateAchievementProgress(
  achievement: Achievement,
  stats: { lessons: number; modules: number; streak: number; [key: string]: number }
): number {
  const { type, value } = achievement.requirement;
  const current = stats[type] ?? 0;
  return Math.min((current / value) * 100, 100);
}
