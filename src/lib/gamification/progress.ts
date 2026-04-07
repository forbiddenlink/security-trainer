/**
 * Progress Tracking for Security Trainer
 *
 * Manages overall progress, completion tracking, and statistics.
 */

import type { Achievement } from './achievements';

export interface LearningProgress {
  lessonsCompleted: string[];
  modulesCompleted: string[];
  quizzesCompleted: string[];
  labsCompleted: string[];
  ctfChallengesCompleted: string[];
  dailyChallengesCompleted: number;
  totalTimeSpentMinutes: number;
  lastActivityDate: string | null;
}

export interface ProgressStats {
  totalLessons: number;
  completedLessons: number;
  lessonProgress: number;
  totalModules: number;
  completedModules: number;
  moduleProgress: number;
  averageQuizScore: number;
  perfectScores: number;
  totalXp: number;
  level: number;
  achievementsUnlocked: number;
  totalAchievements: number;
}

export interface ProgressMilestone {
  id: string;
  name: string;
  description: string;
  threshold: number;
  type: 'lessons' | 'modules' | 'xp' | 'achievements' | 'streak';
  reward: number;
  unlocked: boolean;
}

export const PROGRESS_MILESTONES: Omit<ProgressMilestone, 'unlocked'>[] = [
  // Lesson Milestones
  { id: 'lessons_5', name: 'Warming Up', description: 'Complete 5 lessons', threshold: 5, type: 'lessons', reward: 25 },
  { id: 'lessons_10', name: 'Getting Started', description: 'Complete 10 lessons', threshold: 10, type: 'lessons', reward: 50 },
  { id: 'lessons_25', name: 'Making Progress', description: 'Complete 25 lessons', threshold: 25, type: 'lessons', reward: 100 },
  { id: 'lessons_50', name: 'Halfway Hero', description: 'Complete 50 lessons', threshold: 50, type: 'lessons', reward: 200 },
  { id: 'lessons_100', name: 'Century Club', description: 'Complete 100 lessons', threshold: 100, type: 'lessons', reward: 500 },

  // Module Milestones
  { id: 'modules_1', name: 'First Module', description: 'Complete your first module', threshold: 1, type: 'modules', reward: 50 },
  { id: 'modules_5', name: 'Rising Star', description: 'Complete 5 modules', threshold: 5, type: 'modules', reward: 150 },
  { id: 'modules_10', name: 'Dedicated Learner', description: 'Complete 10 modules', threshold: 10, type: 'modules', reward: 300 },
  { id: 'modules_20', name: 'Almost There', description: 'Complete 20 modules', threshold: 20, type: 'modules', reward: 500 },

  // XP Milestones
  { id: 'xp_1000', name: 'First Thousand', description: 'Earn 1,000 XP', threshold: 1000, type: 'xp', reward: 100 },
  { id: 'xp_5000', name: 'XP Collector', description: 'Earn 5,000 XP', threshold: 5000, type: 'xp', reward: 250 },
  { id: 'xp_10000', name: 'XP Master', description: 'Earn 10,000 XP', threshold: 10000, type: 'xp', reward: 500 },
  { id: 'xp_50000', name: 'XP Legend', description: 'Earn 50,000 XP', threshold: 50000, type: 'xp', reward: 2000 },

  // Achievement Milestones
  { id: 'achievements_5', name: 'Badge Collector', description: 'Unlock 5 achievements', threshold: 5, type: 'achievements', reward: 75 },
  { id: 'achievements_10', name: 'Achievement Hunter', description: 'Unlock 10 achievements', threshold: 10, type: 'achievements', reward: 150 },
  { id: 'achievements_20', name: 'Trophy Master', description: 'Unlock 20 achievements', threshold: 20, type: 'achievements', reward: 400 },
];

export function createInitialProgress(): LearningProgress {
  return {
    lessonsCompleted: [],
    modulesCompleted: [],
    quizzesCompleted: [],
    labsCompleted: [],
    ctfChallengesCompleted: [],
    dailyChallengesCompleted: 0,
    totalTimeSpentMinutes: 0,
    lastActivityDate: null,
  };
}

export function calculateProgressStats(
  progress: LearningProgress,
  totalLessons: number,
  totalModules: number,
  totalXp: number,
  level: number,
  unlockedAchievements: string[],
  totalAchievements: number,
  quizScores: number[] = []
): ProgressStats {
  const lessonProgress = totalLessons > 0
    ? (progress.lessonsCompleted.length / totalLessons) * 100
    : 0;

  const moduleProgress = totalModules > 0
    ? (progress.modulesCompleted.length / totalModules) * 100
    : 0;

  const averageQuizScore = quizScores.length > 0
    ? quizScores.reduce((a, b) => a + b, 0) / quizScores.length
    : 0;

  const perfectScores = quizScores.filter(score => score === 100).length;

  return {
    totalLessons,
    completedLessons: progress.lessonsCompleted.length,
    lessonProgress: Math.round(lessonProgress * 10) / 10,
    totalModules,
    completedModules: progress.modulesCompleted.length,
    moduleProgress: Math.round(moduleProgress * 10) / 10,
    averageQuizScore: Math.round(averageQuizScore * 10) / 10,
    perfectScores,
    totalXp,
    level,
    achievementsUnlocked: unlockedAchievements.length,
    totalAchievements,
  };
}

export function getUnlockedMilestones(stats: ProgressStats): ProgressMilestone[] {
  return PROGRESS_MILESTONES.map(milestone => ({
    ...milestone,
    unlocked: getMilestoneValue(milestone.type, stats) >= milestone.threshold,
  }));
}

function getMilestoneValue(type: ProgressMilestone['type'], stats: ProgressStats): number {
  switch (type) {
    case 'lessons':
      return stats.completedLessons;
    case 'modules':
      return stats.completedModules;
    case 'xp':
      return stats.totalXp;
    case 'achievements':
      return stats.achievementsUnlocked;
    default:
      return 0;
  }
}

export function getNextMilestone(stats: ProgressStats): ProgressMilestone | null {
  const milestones = getUnlockedMilestones(stats);
  return milestones.find(m => !m.unlocked) ?? null;
}

export function recordLessonCompletion(
  progress: LearningProgress,
  lessonId: string,
  lessonType: 'theory' | 'quiz' | 'lab'
): LearningProgress {
  const updated = { ...progress };

  if (!updated.lessonsCompleted.includes(lessonId)) {
    updated.lessonsCompleted = [...updated.lessonsCompleted, lessonId];
  }

  if (lessonType === 'quiz' && !updated.quizzesCompleted.includes(lessonId)) {
    updated.quizzesCompleted = [...updated.quizzesCompleted, lessonId];
  }

  if (lessonType === 'lab' && !updated.labsCompleted.includes(lessonId)) {
    updated.labsCompleted = [...updated.labsCompleted, lessonId];
  }

  updated.lastActivityDate = new Date().toISOString().split('T')[0];

  return updated;
}

export function recordModuleCompletion(
  progress: LearningProgress,
  moduleId: string
): LearningProgress {
  if (progress.modulesCompleted.includes(moduleId)) {
    return progress;
  }

  return {
    ...progress,
    modulesCompleted: [...progress.modulesCompleted, moduleId],
    lastActivityDate: new Date().toISOString().split('T')[0],
  };
}

export function checkAchievementConditions(
  progress: LearningProgress,
  achievement: Achievement,
  additionalStats?: { streak: number; score?: number }
): boolean {
  const { type, value, condition } = achievement.requirement;

  switch (type) {
    case 'lessons':
      return progress.lessonsCompleted.length >= value;

    case 'modules':
      return progress.modulesCompleted.length >= value;

    case 'streak':
      return (additionalStats?.streak ?? 0) >= value;

    case 'score':
      return (additionalStats?.score ?? 0) >= value;

    case 'challenge':
      if (condition === 'ctf') {
        return progress.ctfChallengesCompleted.length >= value;
      }
      if (condition === 'lab') {
        return progress.labsCompleted.length >= value;
      }
      if (condition === 'daily') {
        return progress.dailyChallengesCompleted >= value;
      }
      return false;

    case 'special':
      // Special achievements require custom logic
      return false;

    default:
      return false;
  }
}

export function formatTimeSpent(minutes: number): string {
  if (minutes < 60) {
    return `${minutes}m`;
  }
  const hours = Math.floor(minutes / 60);
  const mins = minutes % 60;
  if (hours < 24) {
    return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
  }
  const days = Math.floor(hours / 24);
  const remainingHours = hours % 24;
  return remainingHours > 0 ? `${days}d ${remainingHours}h` : `${days}d`;
}

export function getWeeklyStats(progress: LearningProgress): {
  lessonsThisWeek: number;
  comparedToLastWeek: number;
} {
  const now = new Date();
  const startOfWeek = new Date(now);
  startOfWeek.setDate(now.getDate() - now.getDay());
  startOfWeek.setHours(0, 0, 0, 0);

  const startOfLastWeek = new Date(startOfWeek);
  startOfLastWeek.setDate(startOfLastWeek.getDate() - 7);

  // This is a simplified version - in production, you'd track completion dates
  // For now, return placeholder values
  return {
    lessonsThisWeek: progress.lessonsCompleted.length,
    comparedToLastWeek: 0,
  };
}
