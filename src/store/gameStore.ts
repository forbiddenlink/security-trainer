import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { UserState } from '../types';

interface GameStore extends UserState {
    addXp: (amount: number) => void;
    completeModule: (moduleId: string) => void;
    unlockBadge: (badgeId: string) => void;
    setCurrentModule: (moduleId: string | null) => void;
    checkStreak: () => void;
    resetProgress: () => void;
}

const INITIAL_STATE: UserState = {
    xp: 0,
    level: 1,
    completedModules: [],
    badges: [],
    currentModuleId: null,
    streakDays: 0,
    lastLoginDate: null,
};

export const useGameStore = create<GameStore>()(
    persist(
        (set, get) => ({
            ...INITIAL_STATE,

            addXp: (amount) => {
                const { xp, level } = get();
                const newXp = xp + amount;
                // Simple leveling curve: Level * 1000 XP needed for next level
                const nextLevelThreshold = level * 1000;
                let newLevel = level;

                if (newXp >= nextLevelThreshold) {
                    newLevel = level + 1;
                }

                set({ xp: newXp, level: newLevel });
            },

            completeModule: (moduleId) => {
                const { completedModules } = get();
                if (!completedModules.includes(moduleId)) {
                    set({ completedModules: [...completedModules, moduleId] });
                }
            },

            unlockBadge: (badgeId) => {
                const { badges } = get();
                if (!badges.includes(badgeId)) {
                    set({ badges: [...badges, badgeId] });
                    // Maybe trigger a toast notification here in the UI
                }
            },

            setCurrentModule: (moduleId) => set({ currentModuleId: moduleId }),

            checkStreak: () => {
                const { lastLoginDate, streakDays } = get();
                const today = new Date().toISOString().split('T')[0];

                if (lastLoginDate === today) return; // Already logged in today

                const matchDate = new Date();
                matchDate.setDate(matchDate.getDate() - 1);
                const yesterday = matchDate.toISOString().split('T')[0];

                if (lastLoginDate === yesterday) {
                    set({ streakDays: streakDays + 1, lastLoginDate: today });
                } else {
                    set({ streakDays: 1, lastLoginDate: today }); // Reset or start streak
                }
            },

            resetProgress: () => set({ ...INITIAL_STATE }),
        }),
        {
            name: 'security-trainer-storage',
        }
    )
);
