import { create } from "zustand";
import { persist } from "zustand/middleware";
import type {
  UserState,
  AchievementNotification,
  LessonReview,
} from "../types";
import { MODULES } from "../data/modules";
import { getPathById } from "../data/learningPaths";
import { getBadgeById } from "../data/badges";
import { useAuthStore } from "./authStore";
import {
  createInitialReview,
  calculateNextReview,
  getLessonsDueForReview,
  getNextUpcomingReview,
  REVIEW_XP_REWARDS,
  type ReviewQuality,
} from "../utils/spacedRepetition";

// ============================================
// GAME CONFIGURATION CONSTANTS
// ============================================

/** XP multiplier applied based on module difficulty */
const DIFFICULTY_MULTIPLIERS: Record<string, number> = {
  Beginner: 1,
  Intermediate: 1.5,
  Advanced: 2,
};

/** Streak day milestones that trigger achievement notifications */
const STREAK_MILESTONES = [3, 7, 30];

/** Streak milestones that award a freeze token */
const STREAK_FREEZE_MILESTONES = [7, 30];

/** Maximum freeze tokens a user can hold */
const MAX_STREAK_FREEZES = 3;

/** Maps a module id to a module-specific badge awarded on completion */
const MODULE_BADGES: Record<string, string> = {
  "sql-injection": "sql-slayer",
  "xss-basics": "xss-terminator",
};

/** Level at which the "Master Operator" badge is awarded */
const MASTER_OPERATOR_LEVEL = 5;

/** Maximum streak days that contribute to XP bonus (70% max at 7 days) */
const MAX_STREAK_BONUS_DAYS = 7;

/** XP bonus percentage per streak day (10% = 0.1) */
const STREAK_BONUS_PER_DAY = 0.1;

/** XP required to level up = level * XP_PER_LEVEL */
const XP_PER_LEVEL = 1000;

/** Bonus XP awarded for completing daily challenge */
const DAILY_CHALLENGE_BONUS_XP = 50;

/** Milliseconds to debounce cloud sync operations */
const SYNC_DEBOUNCE_MS = 2000;

/** Maximum retry attempts for failed syncs */
const MAX_SYNC_RETRIES = 3;

/** Base delay for exponential backoff (ms) */
const SYNC_RETRY_BASE_DELAY = 1000;

// ============================================
// CLOUD SYNC
// ============================================

// Debounce helper for cloud sync
let syncTimeout: ReturnType<typeof setTimeout> | null = null;
let syncRetryCount = 0;

// Sync progress to cloud (debounced) with retry logic
const syncToCloud = async () => {
  const { user, syncProgressToCloud } = useAuthStore.getState();

  if (!user) return;

  const state = useGameStore.getState();

  try {
    // Update sync status to syncing
    useGameStore.setState({ syncStatus: "syncing" });

    await syncProgressToCloud({
      xp: state.xp,
      level: state.level,
      badges: state.badges,
      completedModules: state.completedModules,
      completedLessons: state.completedLessons,
      streakDays: state.streakDays,
      lastLoginDate: state.lastLoginDate,
      dailyChallengeId: state.dailyChallengeId,
      dailyChallengeDate: state.dailyChallengeDate,
      dailyChallengeCompleted: state.dailyChallengeCompleted,
    });

    // Success - reset retry count and update status
    syncRetryCount = 0;
    useGameStore.setState({ syncStatus: "synced", lastSyncError: null });
  } catch (error) {
    console.error("Cloud sync failed:", error);

    // Retry with exponential backoff
    if (syncRetryCount < MAX_SYNC_RETRIES) {
      syncRetryCount++;
      const delay = SYNC_RETRY_BASE_DELAY * Math.pow(2, syncRetryCount - 1);
      console.log(
        `Retrying sync in ${delay}ms (attempt ${syncRetryCount}/${MAX_SYNC_RETRIES})`,
      );
      setTimeout(syncToCloud, delay);
      useGameStore.setState({ syncStatus: "retrying" });
    } else {
      // Max retries reached
      syncRetryCount = 0;
      useGameStore.setState({
        syncStatus: "error",
        lastSyncError: error instanceof Error ? error.message : "Sync failed",
      });
    }
  }
};

const debouncedSyncToCloud = () => {
  if (syncTimeout) {
    clearTimeout(syncTimeout);
  }
  syncTimeout = setTimeout(syncToCloud, SYNC_DEBOUNCE_MS);
};

type SyncStatus = "idle" | "syncing" | "synced" | "retrying" | "error";

interface GameStore extends UserState {
  showLevelUpToast: boolean;
  achievementQueue: AchievementNotification[];
  syncStatus: SyncStatus;
  lastSyncError: string | null;
  addXp: (amount: number, moduleId?: string) => void;
  completeModule: (moduleId: string) => void;
  completeLesson: (lessonId: string, moduleId: string) => void;
  unlockBadge: (badgeId: string) => void;
  setCurrentModule: (moduleId: string | null) => void;
  checkStreak: () => void;
  resetProgress: () => void;
  dismissLevelUpToast: () => void;
  dismissAchievement: () => void;
  checkDailyChallenge: () => void;
  completeDailyChallenge: () => void;
  getDailyChallenge: () => {
    lessonId: string;
    moduleId: string;
    moduleTitle: string;
    lessonTitle: string;
  } | null;
  getStreakMultiplier: () => number;
  calculateXpWithMultipliers: (baseXp: number, moduleId?: string) => number;
  syncToCloud: () => void;
  // Spaced Repetition
  initializeLessonReview: (lessonId: string) => void;
  markLessonReviewed: (lessonId: string, quality: ReviewQuality) => void;
  getReviewsDue: () => LessonReview[];
  getNextReview: () => LessonReview | null;
  isLessonDueForReview: (lessonId: string) => boolean;
  // Learning Paths
  getPathProgress: (pathId: string) => { completed: number; total: number };
  isPathUnlocked: (pathId: string) => boolean;
  completePath: (pathId: string) => void;
  // CTF Challenges
  submitFlag: (
    challengeId: string,
    flag: string,
    challenge: {
      points: number;
      hints: { id: string; cost: number }[];
      flag: string;
    },
  ) => Promise<{ correct: boolean; pointsEarned: number }>;
  revealHint: (challengeId: string, hintId: string) => void;
  getCTFProgress: (challengeId: string) => {
    solved: boolean;
    hintsRevealed: string[];
    attempts: number;
    solvedAt?: string;
    pointsEarned?: number;
  } | null;
  isCTFSolved: (challengeId: string) => boolean;
  setUserRole: (role: string) => void;
}

const INITIAL_STATE: UserState = {
  xp: 0,
  level: 1,
  completedModules: [],
  completedLessons: [],
  badges: [],
  currentModuleId: null,
  streakDays: 0,
  lastLoginDate: null,
  dailyChallengeId: null,
  dailyChallengeDate: null,
  dailyChallengeCompleted: false,
  lessonReviews: {},
  completedPaths: [],
  ctfProgress: {},
  ctfTotalPoints: 0,
  userRole: null,
  activityLog: [],
  streakFreezeCount: 0,
};

// Helper to get today's date string
const getTodayString = () => new Date().toISOString().split("T")[0];

// Helper to generate a deterministic daily challenge based on date
const generateDailyChallenge = (
  dateString: string,
  completedLessons: string[],
): string | null => {
  // Get all uncompleted lessons
  const uncompletedLessons: { lessonId: string; moduleId: string }[] = [];

  for (const module of MODULES) {
    for (const lesson of module.lessons) {
      if (!completedLessons.includes(lesson.id)) {
        uncompletedLessons.push({ lessonId: lesson.id, moduleId: module.id });
      }
    }
  }

  if (uncompletedLessons.length === 0) return null;

  // Use date as seed for consistent daily selection
  const dateNum = parseInt(dateString.replace(/-/g, ""), 10);
  const index = dateNum % uncompletedLessons.length;

  return uncompletedLessons[index].lessonId;
};

export const useGameStore = create<GameStore>()(
  persist(
    (set, get) => ({
      ...INITIAL_STATE,
      showLevelUpToast: false,
      achievementQueue: [],
      syncStatus: "idle" as SyncStatus,
      lastSyncError: null,

      getStreakMultiplier: () => {
        const { streakDays } = get();
        const bonusDays = Math.min(streakDays, MAX_STREAK_BONUS_DAYS);
        return 1 + bonusDays * STREAK_BONUS_PER_DAY;
      },

      calculateXpWithMultipliers: (baseXp, moduleId) => {
        const { getStreakMultiplier } = get();

        // Get difficulty multiplier
        let difficultyMultiplier = 1;
        if (moduleId) {
          const module = MODULES.find((m) => m.id === moduleId);
          if (module) {
            difficultyMultiplier =
              DIFFICULTY_MULTIPLIERS[module.difficulty] || 1;
          }
        }

        // Apply streak multiplier
        const streakMultiplier = getStreakMultiplier();

        return Math.round(baseXp * difficultyMultiplier * streakMultiplier);
      },

      addXp: (amount, moduleId) => {
        const { xp, level, calculateXpWithMultipliers } = get();

        // Apply multipliers
        const finalAmount = calculateXpWithMultipliers(amount, moduleId);

        let currentXp = xp + finalAmount;
        let newLevel = level;
        let shouldShowToast = false;

        // Handle multiple level-ups if XP gain is large enough
        while (currentXp >= newLevel * XP_PER_LEVEL) {
          currentXp -= newLevel * XP_PER_LEVEL;
          newLevel++;
          shouldShowToast = true;
        }

        set({
          xp: currentXp,
          level: newLevel,
          showLevelUpToast: shouldShowToast,
        });

        // Award "Master Operator" badge on reaching the milestone level
        if (newLevel >= MASTER_OPERATOR_LEVEL) {
          get().unlockBadge("master-hacker");
        }

        debouncedSyncToCloud();
      },

      completeModule: (moduleId) => {
        const { completedModules, achievementQueue } = get();
        if (!completedModules.includes(moduleId)) {
          const module = MODULES.find((m) => m.id === moduleId);
          const moduleName = module?.title || "Module";

          // Add module completion notification
          const notification: AchievementNotification = {
            id: `module-${moduleId}-${Date.now()}`,
            type: "module_complete",
            title: "Module Complete!",
            message: `You completed "${moduleName}"`,
          };

          set({
            completedModules: [...completedModules, moduleId],
            achievementQueue: [...achievementQueue, notification],
          });

          // Award "first module complete" badge
          if (completedModules.length === 0) {
            get().unlockBadge("badge-completion");
          }
          // Award module-specific badge if one exists
          const moduleBadge = MODULE_BADGES[moduleId];
          if (moduleBadge) {
            get().unlockBadge(moduleBadge);
          }

          debouncedSyncToCloud();
        }
      },

      completeLesson: (lessonId, moduleId) => {
        const {
          completedLessons,
          dailyChallengeId,
          dailyChallengeCompleted,
          completeDailyChallenge,
          initializeLessonReview,
        } = get();

        if (!completedLessons.includes(lessonId)) {
          set({ completedLessons: [...completedLessons, lessonId] });

          // Initialize spaced repetition tracking for this lesson
          initializeLessonReview(lessonId);

          // Check if this was the daily challenge
          if (lessonId === dailyChallengeId && !dailyChallengeCompleted) {
            completeDailyChallenge();
          }

          // Check if all lessons in module are complete
          const module = MODULES.find((m) => m.id === moduleId);
          if (module) {
            const updatedCompletedLessons = [...completedLessons, lessonId];
            const allLessonsComplete = module.lessons.every((lesson) =>
              updatedCompletedLessons.includes(lesson.id),
            );
            if (allLessonsComplete) {
              get().completeModule(moduleId);
            }
          }
          debouncedSyncToCloud();
        }
      },

      unlockBadge: (badgeId) => {
        const { badges, achievementQueue } = get();
        if (!badges.includes(badgeId)) {
          // Get badge name from centralized badge registry
          const badge = getBadgeById(badgeId);
          const badgeName = badge?.name || badgeId;

          const notification: AchievementNotification = {
            id: `badge-${badgeId}-${Date.now()}`,
            type: "badge",
            title: "Badge Unlocked!",
            message: `You earned "${badgeName}"`,
          };

          set({
            badges: [...badges, badgeId],
            achievementQueue: [...achievementQueue, notification],
          });
          debouncedSyncToCloud();
        }
      },

      setCurrentModule: (moduleId) => set({ currentModuleId: moduleId }),

      checkStreak: () => {
        const {
          lastLoginDate,
          streakDays,
          achievementQueue,
          activityLog,
          streakFreezeCount,
        } = get();
        const today = getTodayString();

        // Award "Recruit" badge for starting a session (idempotent)
        get().unlockBadge("recruit");

        // Always ensure today is in the activity log (idempotent)
        if (!activityLog.includes(today)) {
          const updatedLog = [...activityLog, today].slice(-365);
          set({ activityLog: updatedLog });
        }

        if (lastLoginDate === today) return; // Already counted streak today

        const dateOffset = (n: number) => {
          const d = new Date();
          d.setDate(d.getDate() - n);
          return d.toISOString().split("T")[0];
        };
        const yesterday = dateOffset(1);
        const dayBefore = dateOffset(2);

        let newStreakDays: number;
        let newFreezeCount = streakFreezeCount;
        const notifications: AchievementNotification[] = [];

        if (lastLoginDate === yesterday) {
          newStreakDays = streakDays + 1;
        } else if (lastLoginDate === dayBefore && streakFreezeCount > 0) {
          // Missed exactly 1 day but have a freeze — auto-apply
          newStreakDays = streakDays + 1;
          newFreezeCount = streakFreezeCount - 1;
          notifications.push({
            id: `freeze-used-${Date.now()}`,
            type: "streak",
            title: "Streak Freeze Used!",
            message: `A freeze token saved your ${streakDays}-day streak! (${newFreezeCount} remaining)`,
          });
        } else {
          newStreakDays = 1; // Reset or start streak
        }

        // Milestone notification
        if (STREAK_MILESTONES.includes(newStreakDays)) {
          notifications.push({
            id: `streak-${newStreakDays}-${Date.now()}`,
            type: "streak",
            title: "Streak Milestone!",
            message: `${newStreakDays}-day streak! Keep it up!`,
          });
        }

        // Award freeze token at freeze milestones (cap at MAX_STREAK_FREEZES)
        if (
          STREAK_FREEZE_MILESTONES.includes(newStreakDays) &&
          newFreezeCount < MAX_STREAK_FREEZES
        ) {
          newFreezeCount++;
          notifications.push({
            id: `freeze-earned-${Date.now()}`,
            type: "streak",
            title: "Freeze Token Earned!",
            message: `${newStreakDays}-day streak — you earned a streak freeze! (${newFreezeCount} held)`,
          });
        }

        set({
          streakDays: newStreakDays,
          streakFreezeCount: newFreezeCount,
          lastLoginDate: today,
          achievementQueue: [...achievementQueue, ...notifications],
        });
        debouncedSyncToCloud();
      },

      checkDailyChallenge: () => {
        const { dailyChallengeDate, completedLessons } = get();
        const today = getTodayString();

        // If it's a new day, generate a new challenge
        if (dailyChallengeDate !== today) {
          const newChallengeId = generateDailyChallenge(
            today,
            completedLessons,
          );
          set({
            dailyChallengeId: newChallengeId,
            dailyChallengeDate: today,
            dailyChallengeCompleted: false,
          });
        }
      },

      completeDailyChallenge: () => {
        const { achievementQueue } = get();

        const notification: AchievementNotification = {
          id: `daily-${Date.now()}`,
          type: "daily_challenge",
          title: "Daily Challenge Complete!",
          message: `+${DAILY_CHALLENGE_BONUS_XP} bonus XP!`,
        };

        set({
          dailyChallengeCompleted: true,
          achievementQueue: [...achievementQueue, notification],
        });

        // Add bonus XP (without multipliers for the bonus itself)
        const { xp, level } = get();
        let currentXp = xp + DAILY_CHALLENGE_BONUS_XP;
        let newLevel = level;
        let shouldShowToast = false;

        while (currentXp >= newLevel * XP_PER_LEVEL) {
          currentXp -= newLevel * XP_PER_LEVEL;
          newLevel++;
          shouldShowToast = true;
        }

        set({
          xp: currentXp,
          level: newLevel,
          showLevelUpToast: shouldShowToast,
        });
        debouncedSyncToCloud();
      },

      getDailyChallenge: () => {
        const { checkDailyChallenge } = get();

        // Ensure we have a valid daily challenge
        checkDailyChallenge();

        const currentChallengeId = get().dailyChallengeId;
        if (!currentChallengeId) return null;

        // Find the lesson and module
        for (const module of MODULES) {
          for (const lesson of module.lessons) {
            if (lesson.id === currentChallengeId) {
              return {
                lessonId: lesson.id,
                moduleId: module.id,
                moduleTitle: module.title,
                lessonTitle: lesson.title,
              };
            }
          }
        }

        return null;
      },

      // ============================================
      // SPACED REPETITION
      // ============================================

      initializeLessonReview: (lessonId) => {
        const { lessonReviews } = get();
        // Only initialize if not already tracked
        if (!lessonReviews[lessonId]) {
          const newReview = createInitialReview(lessonId);
          set({
            lessonReviews: { ...lessonReviews, [lessonId]: newReview },
          });
          debouncedSyncToCloud();
        }
      },

      markLessonReviewed: (lessonId, quality) => {
        const { lessonReviews, achievementQueue, addXp } = get();
        const currentReview = lessonReviews[lessonId];

        if (!currentReview) return;

        // Calculate next review using SM-2
        const updatedReview = calculateNextReview(currentReview, quality);

        // Add review XP
        const xpReward = REVIEW_XP_REWARDS[quality];
        addXp(xpReward);

        // Add notification
        const notification: AchievementNotification = {
          id: `review-${lessonId}-${Date.now()}`,
          type: "review",
          title: "Intel Refreshed!",
          message: `+${xpReward} XP - Next review in ${updatedReview.interval} day${updatedReview.interval > 1 ? "s" : ""}`,
        };

        set({
          lessonReviews: { ...lessonReviews, [lessonId]: updatedReview },
          achievementQueue: [...achievementQueue, notification],
        });
        debouncedSyncToCloud();
      },

      getReviewsDue: () => {
        const { lessonReviews } = get();
        return getLessonsDueForReview(lessonReviews);
      },

      getNextReview: () => {
        const { lessonReviews } = get();
        return getNextUpcomingReview(lessonReviews);
      },

      isLessonDueForReview: (lessonId) => {
        const { lessonReviews } = get();
        const review = lessonReviews[lessonId];
        if (!review) return false;
        const today = new Date().toISOString().split("T")[0];
        return review.nextReviewDate <= today;
      },

      // ============================================
      // LEARNING PATHS
      // ============================================

      getPathProgress: (pathId) => {
        const { completedModules } = get();
        const path = getPathById(pathId);
        if (!path) return { completed: 0, total: 0 };

        const completed = path.modules.filter((moduleId) =>
          completedModules.includes(moduleId),
        ).length;

        return { completed, total: path.modules.length };
      },

      isPathUnlocked: (pathId) => {
        const { completedModules } = get();
        const path = getPathById(pathId);
        if (!path) return false;
        if (!path.requiredCompletions) return true;

        return completedModules.length >= path.requiredCompletions;
      },

      completePath: (pathId) => {
        const { completedPaths, achievementQueue, addXp } = get();
        if (completedPaths.includes(pathId)) return;

        const path = getPathById(pathId);
        if (!path) return;

        // Add certification notification
        const notification: AchievementNotification = {
          id: `path-${pathId}-${Date.now()}`,
          type: "badge",
          title: "Certification Earned!",
          message: `${path.codename} complete - ${path.title}`,
        };

        set({
          completedPaths: [...completedPaths, pathId],
          achievementQueue: [...achievementQueue, notification],
        });

        // Award certificate XP
        addXp(path.certificateXp);
        debouncedSyncToCloud();
      },

      setUserRole: (role) => set({ userRole: role }),

      resetProgress: () => {
        // Clear pending sync to prevent stale data sync after reset
        if (syncTimeout) {
          clearTimeout(syncTimeout);
          syncTimeout = null;
        }
        syncRetryCount = 0;
        set({ ...INITIAL_STATE });
        debouncedSyncToCloud();
      },

      dismissLevelUpToast: () => set({ showLevelUpToast: false }),

      dismissAchievement: () => {
        const { achievementQueue } = get();
        set({ achievementQueue: achievementQueue.slice(1) });
      },

      syncToCloud: () => {
        debouncedSyncToCloud();
      },

      // ============================================
      // CTF CHALLENGES
      // ============================================

      submitFlag: async (challengeId, flag, challenge) => {
        const { ctfProgress, ctfTotalPoints, achievementQueue, unlockBadge } =
          get();
        const existing = ctfProgress[challengeId];

        // Already solved - no points
        if (existing?.solved) {
          return { correct: false, pointsEarned: 0 };
        }

        // Hash the input flag and compare
        const { validateFlag } = await import("../lib/ctf");
        const isCorrect = await validateFlag(flag, challenge.flag);

        const hintsRevealed = existing?.hintsRevealed || [];
        const attempts = (existing?.attempts || 0) + 1;

        if (isCorrect) {
          // Calculate points after hint deductions
          const hintCost = challenge.hints
            .filter((h) => hintsRevealed.includes(h.id))
            .reduce((total, hint) => total + hint.cost, 0);
          const pointsEarned = Math.max(0, challenge.points - hintCost);

          const notification: AchievementNotification = {
            id: `ctf-${challengeId}-${Date.now()}`,
            type: "badge",
            title: "Flag Captured!",
            message: `+${pointsEarned} CTF points`,
          };

          set({
            ctfProgress: {
              ...ctfProgress,
              [challengeId]: {
                challengeId,
                solved: true,
                hintsRevealed,
                attempts,
                solvedAt: new Date().toISOString(),
                pointsEarned,
              },
            },
            ctfTotalPoints: ctfTotalPoints + pointsEarned,
            achievementQueue: [...achievementQueue, notification],
          });

          // Check for CTF badges
          const newTotal = ctfTotalPoints + pointsEarned;
          const solvedCount =
            Object.values(ctfProgress).filter((p) => p.solved).length + 1;

          if (solvedCount === 1) {
            unlockBadge("badge-ctf-first");
          }
          if (solvedCount >= 5) {
            unlockBadge("badge-ctf-hunter");
          }
          if (newTotal >= 500) {
            unlockBadge("badge-ctf-500");
          }

          // Also award XP based on CTF points (streak multiplier applies)
          get().addXp(pointsEarned);

          debouncedSyncToCloud();
          return { correct: true, pointsEarned };
        } else {
          // Wrong answer - record attempt
          set({
            ctfProgress: {
              ...ctfProgress,
              [challengeId]: {
                challengeId,
                solved: false,
                hintsRevealed,
                attempts,
              },
            },
          });

          return { correct: false, pointsEarned: 0 };
        }
      },

      revealHint: (challengeId, hintId) => {
        const { ctfProgress } = get();
        const existing = ctfProgress[challengeId];

        // Don't reveal if already solved
        if (existing?.solved) return;

        const hintsRevealed = existing?.hintsRevealed || [];
        if (hintsRevealed.includes(hintId)) return;

        set({
          ctfProgress: {
            ...ctfProgress,
            [challengeId]: {
              challengeId,
              solved: false,
              hintsRevealed: [...hintsRevealed, hintId],
              attempts: existing?.attempts || 0,
            },
          },
        });

        debouncedSyncToCloud();
      },

      getCTFProgress: (challengeId) => {
        const { ctfProgress } = get();
        return ctfProgress[challengeId] || null;
      },

      isCTFSolved: (challengeId) => {
        const { ctfProgress } = get();
        return ctfProgress[challengeId]?.solved ?? false;
      },
    }),
    {
      name: "security-trainer-storage",
      partialize: (state) => ({
        // Don't persist toast/notification state
        xp: state.xp,
        level: state.level,
        completedModules: state.completedModules,
        completedLessons: state.completedLessons,
        badges: state.badges,
        currentModuleId: state.currentModuleId,
        streakDays: state.streakDays,
        lastLoginDate: state.lastLoginDate,
        dailyChallengeId: state.dailyChallengeId,
        dailyChallengeDate: state.dailyChallengeDate,
        dailyChallengeCompleted: state.dailyChallengeCompleted,
        lessonReviews: state.lessonReviews,
        completedPaths: state.completedPaths,
        ctfProgress: state.ctfProgress,
        ctfTotalPoints: state.ctfTotalPoints,
        userRole: state.userRole,
        activityLog: state.activityLog,
        streakFreezeCount: state.streakFreezeCount,
      }),
    },
  ),
);
