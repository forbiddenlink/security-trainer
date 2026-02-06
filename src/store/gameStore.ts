import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { UserState, AchievementNotification } from '../types';
import { MODULES } from '../data/modules';

// XP Multipliers by difficulty
const DIFFICULTY_MULTIPLIERS: Record<string, number> = {
    'Beginner': 1,
    'Intermediate': 1.5,
    'Advanced': 2,
};

// Streak milestones that trigger notifications
const STREAK_MILESTONES = [3, 7, 30];

// Debounce helper for cloud sync
let syncTimeout: ReturnType<typeof setTimeout> | null = null;
const SYNC_DEBOUNCE_MS = 2000;

// Sync progress to cloud (debounced)
const syncToCloud = async () => {
    // Dynamic import to avoid circular dependency
    const { useAuthStore } = await import('./authStore');
    const { user, syncProgressToCloud } = useAuthStore.getState();

    if (!user) return;

    const state = useGameStore.getState();
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
};

const debouncedSyncToCloud = () => {
    if (syncTimeout) {
        clearTimeout(syncTimeout);
    }
    syncTimeout = setTimeout(syncToCloud, SYNC_DEBOUNCE_MS);
};

interface GameStore extends UserState {
    showLevelUpToast: boolean;
    achievementQueue: AchievementNotification[];
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
    getDailyChallenge: () => { lessonId: string; moduleId: string; moduleTitle: string; lessonTitle: string } | null;
    getStreakMultiplier: () => number;
    calculateXpWithMultipliers: (baseXp: number, moduleId?: string) => number;
    syncToCloud: () => void;
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
};

// Helper to get today's date string
const getTodayString = () => new Date().toISOString().split('T')[0];

// Helper to generate a deterministic daily challenge based on date
const generateDailyChallenge = (dateString: string, completedLessons: string[]): string | null => {
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
    const dateNum = parseInt(dateString.replace(/-/g, ''), 10);
    const index = dateNum % uncompletedLessons.length;

    return uncompletedLessons[index].lessonId;
};

export const useGameStore = create<GameStore>()(
    persist(
        (set, get) => ({
            ...INITIAL_STATE,
            showLevelUpToast: false,
            achievementQueue: [],

            getStreakMultiplier: () => {
                const { streakDays } = get();
                // +10% per day, max 7 days = +70%
                const bonusDays = Math.min(streakDays, 7);
                return 1 + (bonusDays * 0.1);
            },

            calculateXpWithMultipliers: (baseXp, moduleId) => {
                const { getStreakMultiplier } = get();

                // Get difficulty multiplier
                let difficultyMultiplier = 1;
                if (moduleId) {
                    const module = MODULES.find(m => m.id === moduleId);
                    if (module) {
                        difficultyMultiplier = DIFFICULTY_MULTIPLIERS[module.difficulty] || 1;
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
                while (currentXp >= newLevel * 1000) {
                    currentXp -= newLevel * 1000;
                    newLevel++;
                    shouldShowToast = true;
                }

                set({ xp: currentXp, level: newLevel, showLevelUpToast: shouldShowToast });
                debouncedSyncToCloud();
            },

            completeModule: (moduleId) => {
                const { completedModules, achievementQueue } = get();
                if (!completedModules.includes(moduleId)) {
                    const module = MODULES.find(m => m.id === moduleId);
                    const moduleName = module?.title || 'Module';

                    // Add module completion notification
                    const notification: AchievementNotification = {
                        id: `module-${moduleId}-${Date.now()}`,
                        type: 'module_complete',
                        title: 'Module Complete!',
                        message: `You completed "${moduleName}"`,
                    };

                    set({
                        completedModules: [...completedModules, moduleId],
                        achievementQueue: [...achievementQueue, notification],
                    });
                    debouncedSyncToCloud();
                }
            },

            completeLesson: (lessonId, moduleId) => {
                const { completedLessons, dailyChallengeId, dailyChallengeCompleted, completeDailyChallenge } = get();

                if (!completedLessons.includes(lessonId)) {
                    set({ completedLessons: [...completedLessons, lessonId] });

                    // Check if this was the daily challenge
                    if (lessonId === dailyChallengeId && !dailyChallengeCompleted) {
                        completeDailyChallenge();
                    }

                    // Check if all lessons in module are complete
                    const module = MODULES.find(m => m.id === moduleId);
                    if (module) {
                        const updatedCompletedLessons = [...completedLessons, lessonId];
                        const allLessonsComplete = module.lessons.every(
                            lesson => updatedCompletedLessons.includes(lesson.id)
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
                    // Badge names mapping
                    const badgeNames: Record<string, string> = {
                        'recruit': 'Recruit',
                        'sql-slayer': 'SQL Slayer',
                        'xss-terminator': 'XSS Terminator',
                        'badge-completion': 'Mission Complete',
                        'badge-elite': 'Elite Hacker',
                        'master-hacker': 'Master Operator',
                    };

                    const notification: AchievementNotification = {
                        id: `badge-${badgeId}-${Date.now()}`,
                        type: 'badge',
                        title: 'Badge Unlocked!',
                        message: `You earned "${badgeNames[badgeId] || badgeId}"`,
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
                const { lastLoginDate, streakDays, achievementQueue } = get();
                const today = getTodayString();

                if (lastLoginDate === today) return; // Already logged in today

                const matchDate = new Date();
                matchDate.setDate(matchDate.getDate() - 1);
                const yesterday = matchDate.toISOString().split('T')[0];

                let newStreakDays: number;
                const notifications: AchievementNotification[] = [];

                if (lastLoginDate === yesterday) {
                    newStreakDays = streakDays + 1;

                    // Check for streak milestones
                    if (STREAK_MILESTONES.includes(newStreakDays)) {
                        notifications.push({
                            id: `streak-${newStreakDays}-${Date.now()}`,
                            type: 'streak',
                            title: 'Streak Milestone!',
                            message: `${newStreakDays}-day streak! Keep it up!`,
                        });
                    }
                } else {
                    newStreakDays = 1; // Reset or start streak
                }

                set({
                    streakDays: newStreakDays,
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
                    const newChallengeId = generateDailyChallenge(today, completedLessons);
                    set({
                        dailyChallengeId: newChallengeId,
                        dailyChallengeDate: today,
                        dailyChallengeCompleted: false,
                    });
                }
            },

            completeDailyChallenge: () => {
                const { achievementQueue } = get();

                // Award bonus XP
                const DAILY_CHALLENGE_BONUS = 50;

                const notification: AchievementNotification = {
                    id: `daily-${Date.now()}`,
                    type: 'daily_challenge',
                    title: 'Daily Challenge Complete!',
                    message: `+${DAILY_CHALLENGE_BONUS} bonus XP!`,
                };

                set({
                    dailyChallengeCompleted: true,
                    achievementQueue: [...achievementQueue, notification],
                });

                // Add bonus XP (without multipliers for the bonus itself)
                const { xp, level } = get();
                let currentXp = xp + DAILY_CHALLENGE_BONUS;
                let newLevel = level;
                let shouldShowToast = false;

                while (currentXp >= newLevel * 1000) {
                    currentXp -= newLevel * 1000;
                    newLevel++;
                    shouldShowToast = true;
                }

                set({ xp: currentXp, level: newLevel, showLevelUpToast: shouldShowToast });
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

            resetProgress: () => {
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
        }),
        {
            name: 'security-trainer-storage',
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
            }),
        }
    )
);
