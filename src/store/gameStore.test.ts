import { describe, it, expect, beforeEach } from 'vitest';
import { useGameStore } from './gameStore';

describe('gameStore', () => {
    beforeEach(() => {
        // Reset store to initial state before each test
        useGameStore.getState().resetProgress();
        // Also reset the toast state
        useGameStore.setState({ showLevelUpToast: false });
    });

    describe('addXp', () => {
        it('adds XP to the current total', () => {
            const { addXp } = useGameStore.getState();

            addXp(100);

            expect(useGameStore.getState().xp).toBe(100);
        });

        it('levels up when XP exceeds threshold (level * 1000)', () => {
            const { addXp } = useGameStore.getState();

            // At level 1, threshold is 1000 XP
            addXp(1000);

            const state = useGameStore.getState();
            expect(state.level).toBe(2);
            expect(state.xp).toBe(0); // XP resets after level up
        });

        it('handles multiple level-ups from large XP gain', () => {
            const { addXp } = useGameStore.getState();

            // At level 1, gaining 3000 XP should jump to level 4
            // Level 1 threshold: 1000, Level 2: 2000, Level 3: 3000
            // 3000 - 1000 = 2000, 2000 - 2000 = 0, level 3
            // Wait, let me recalculate:
            // Start: level 1, xp 0
            // Add 3000: xp = 3000
            // 3000 >= 1*1000? Yes, xp = 3000-1000 = 2000, level = 2
            // 2000 >= 2*1000? Yes, xp = 2000-2000 = 0, level = 3
            // 0 >= 3*1000? No, done
            addXp(3000);

            const state = useGameStore.getState();
            expect(state.level).toBe(3);
            expect(state.xp).toBe(0);
        });

        it('shows level up toast when leveling up', () => {
            const { addXp } = useGameStore.getState();

            addXp(1000);

            expect(useGameStore.getState().showLevelUpToast).toBe(true);
        });

        it('does not show toast when not leveling up', () => {
            const { addXp } = useGameStore.getState();

            addXp(500);

            expect(useGameStore.getState().showLevelUpToast).toBe(false);
        });

        it('carries over excess XP after level up', () => {
            const { addXp } = useGameStore.getState();

            // At level 1, threshold is 1000
            // Adding 1500 should level up and leave 500 XP
            addXp(1500);

            const state = useGameStore.getState();
            expect(state.level).toBe(2);
            expect(state.xp).toBe(500);
        });
    });

    describe('completeModule', () => {
        it('adds module to completed list', () => {
            const { completeModule } = useGameStore.getState();

            completeModule('sql-injection');

            expect(useGameStore.getState().completedModules).toContain('sql-injection');
        });

        it('does not add duplicate modules', () => {
            const { completeModule } = useGameStore.getState();

            completeModule('sql-injection');
            completeModule('sql-injection');

            expect(useGameStore.getState().completedModules.filter(m => m === 'sql-injection')).toHaveLength(1);
        });
    });

    describe('unlockBadge', () => {
        it('adds badge to unlocked list', () => {
            const { unlockBadge } = useGameStore.getState();

            unlockBadge('badge-elite');

            expect(useGameStore.getState().badges).toContain('badge-elite');
        });

        it('does not add duplicate badges', () => {
            const { unlockBadge } = useGameStore.getState();

            unlockBadge('badge-elite');
            unlockBadge('badge-elite');

            expect(useGameStore.getState().badges.filter(b => b === 'badge-elite')).toHaveLength(1);
        });
    });

    describe('dismissLevelUpToast', () => {
        it('sets showLevelUpToast to false', () => {
            useGameStore.setState({ showLevelUpToast: true });

            useGameStore.getState().dismissLevelUpToast();

            expect(useGameStore.getState().showLevelUpToast).toBe(false);
        });
    });

    describe('resetProgress', () => {
        it('resets all progress to initial state', () => {
            const store = useGameStore.getState();
            store.addXp(5000);
            store.completeModule('test-module');
            store.unlockBadge('test-badge');

            store.resetProgress();

            const state = useGameStore.getState();
            expect(state.xp).toBe(0);
            expect(state.level).toBe(1);
            expect(state.completedModules).toHaveLength(0);
            expect(state.badges).toHaveLength(0);
        });
    });
});
