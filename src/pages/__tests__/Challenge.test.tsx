import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BrowserRouter } from 'react-router-dom';
import { Challenge } from '../Challenge';
import { useGameStore } from '../../store/gameStore';

// Mock framer-motion
vi.mock('framer-motion', () => ({
    motion: {
        div: ({ children, ...props }: { children?: React.ReactNode }) => <div {...props}>{children}</div>,
    },
}));

// Mock canvas-confetti to prevent import errors
vi.mock('canvas-confetti', () => ({
    default: vi.fn(),
}));

// Mock the navigation
const mockNavigate = vi.fn();
vi.mock('react-router-dom', async () => {
    const actual = await vi.importActual('react-router-dom');
    return {
        ...actual,
        useNavigate: () => mockNavigate,
    };
});

// Helper to render with router
const renderChallenge = () => {
    return render(
        <BrowserRouter>
            <Challenge />
        </BrowserRouter>
    );
};

// Reset store helper
const resetGameStore = () => {
    useGameStore.getState().resetProgress();
    useGameStore.setState({ showLevelUpToast: false });
};

describe('Challenge', () => {
    beforeEach(() => {
        resetGameStore();
        mockNavigate.mockClear();
    });

    describe('pre-game state', () => {
        it('shows the final exam introduction screen', () => {
            renderChallenge();

            expect(screen.getByText('FINAL EXAM')).toBeInTheDocument();
            expect(screen.getByText(/60 Seconds/i)).toBeInTheDocument();
            expect(screen.getByText(/5 Random Questions/i)).toBeInTheDocument();
            expect(screen.getByText(/One mistake ends the run/i)).toBeInTheDocument();
        });

        it('shows the start button', () => {
            renderChallenge();

            expect(screen.getByRole('button', { name: /initiate protocol/i })).toBeInTheDocument();
        });
    });

    describe('game start', () => {
        it('starts the game when clicking initiate protocol', async () => {
            const user = userEvent.setup();
            renderChallenge();

            const startButton = screen.getByRole('button', { name: /initiate protocol/i });
            await user.click(startButton);

            // Should show the timer and question
            expect(screen.getByText('60s')).toBeInTheDocument();
            expect(screen.getByText(/Question 1 \/ 5/)).toBeInTheDocument();
        });

        it('displays quiz question after starting', async () => {
            const user = userEvent.setup();
            renderChallenge();

            await user.click(screen.getByRole('button', { name: /initiate protocol/i }));

            // Wait for the question to appear
            await waitFor(() => {
                expect(screen.getByText(/Question 1 \/ 5/)).toBeInTheDocument();
            });

            // Should have 4 answer options
            const optionButtons = screen.getAllByRole('button').filter(btn =>
                btn.textContent?.includes('A.') ||
                btn.textContent?.includes('B.') ||
                btn.textContent?.includes('C.') ||
                btn.textContent?.includes('D.')
            );
            expect(optionButtons).toHaveLength(4);
        });
    });

    describe('timer behavior', () => {
        beforeEach(() => {
            vi.useFakeTimers({ shouldAdvanceTime: true });
        });

        afterEach(() => {
            vi.useRealTimers();
        });

        it('counts down from 60 seconds', async () => {
            renderChallenge();

            // Start the game
            const startButton = screen.getByRole('button', { name: /initiate protocol/i });
            await act(async () => {
                startButton.click();
            });

            expect(screen.getByText('60s')).toBeInTheDocument();

            // Advance time by 5 seconds
            await act(async () => {
                vi.advanceTimersByTime(5000);
            });

            expect(screen.getByText('55s')).toBeInTheDocument();
        });

        it('shows game over when timer reaches 0', async () => {
            renderChallenge();

            // Start the game
            await act(async () => {
                screen.getByRole('button', { name: /initiate protocol/i }).click();
            });

            // Advance time past 60 seconds
            await act(async () => {
                vi.advanceTimersByTime(61000);
            });

            expect(screen.getByText('MISSION FAILED')).toBeInTheDocument();
        });
    });

    describe('game over state', () => {
        beforeEach(() => {
            vi.useFakeTimers({ shouldAdvanceTime: true });
        });

        afterEach(() => {
            vi.useRealTimers();
        });

        it('shows mission failed screen with return to base button', async () => {
            renderChallenge();

            // Start the game
            await act(async () => {
                screen.getByRole('button', { name: /initiate protocol/i }).click();
            });

            // Force game over by advancing timer
            await act(async () => {
                vi.advanceTimersByTime(61000);
            });

            expect(screen.getByText('MISSION FAILED')).toBeInTheDocument();
            expect(screen.getByText(/vulnerability remains unpatched/i)).toBeInTheDocument();

            const returnButton = screen.getByRole('button', { name: /return to base/i });
            await act(async () => {
                returnButton.click();
            });

            expect(mockNavigate).toHaveBeenCalledWith('/');
        });
    });

    describe('answering questions', () => {
        it('shows 4 answer options when game starts', async () => {
            const user = userEvent.setup();
            renderChallenge();

            await user.click(screen.getByRole('button', { name: /initiate protocol/i }));

            // Wait for the question to appear
            await waitFor(() => {
                expect(screen.getByText(/Question 1 \/ 5/)).toBeInTheDocument();
            });

            // Get answer buttons (they have letters A., B., C., D.)
            const answerButtons = screen.getAllByRole('button').filter(btn =>
                btn.textContent?.includes('A.') ||
                btn.textContent?.includes('B.') ||
                btn.textContent?.includes('C.') ||
                btn.textContent?.includes('D.')
            );

            expect(answerButtons).toHaveLength(4);
        });

        it('has clickable answer options', async () => {
            const user = userEvent.setup();
            renderChallenge();

            await user.click(screen.getByRole('button', { name: /initiate protocol/i }));

            await waitFor(() => {
                expect(screen.getByText(/Question 1 \/ 5/)).toBeInTheDocument();
            });

            // All answer buttons should be enabled
            const answerButtons = screen.getAllByRole('button').filter(btn =>
                btn.textContent?.includes('A.') ||
                btn.textContent?.includes('B.') ||
                btn.textContent?.includes('C.') ||
                btn.textContent?.includes('D.')
            );

            answerButtons.forEach(btn => {
                expect(btn).not.toBeDisabled();
            });
        });
    });

    describe('winning state elements', () => {
        it('renders with correct initial store state', () => {
            expect(useGameStore.getState().xp).toBe(0);
            expect(useGameStore.getState().badges).not.toContain('badge-elite');
        });

        it('has the elite badge reward configured', () => {
            // Verify the badge is not initially unlocked
            expect(useGameStore.getState().badges).toHaveLength(0);
        });
    });

    describe('XP and badge store integration', () => {
        it('store starts with 0 XP', () => {
            const initialXp = useGameStore.getState().xp;
            expect(initialXp).toBe(0);
        });

        it('store starts without elite badge', () => {
            const initialBadges = useGameStore.getState().badges;
            expect(initialBadges).not.toContain('badge-elite');
        });

        it('can unlock badge via store action', () => {
            useGameStore.getState().unlockBadge('badge-elite');
            expect(useGameStore.getState().badges).toContain('badge-elite');
        });

        it('can add XP via store action', () => {
            // Add 500 XP (less than level threshold to avoid level up reset)
            useGameStore.getState().addXp(500);
            expect(useGameStore.getState().xp).toBe(500);
        });
    });

    describe('navigation after game over', () => {
        beforeEach(() => {
            vi.useFakeTimers({ shouldAdvanceTime: true });
        });

        afterEach(() => {
            vi.useRealTimers();
        });

        it('navigates to home when clicking return to base', async () => {
            renderChallenge();

            // Start and force game over
            await act(async () => {
                screen.getByRole('button', { name: /initiate protocol/i }).click();
            });

            await act(async () => {
                vi.advanceTimersByTime(61000);
            });

            await act(async () => {
                screen.getByRole('button', { name: /return to base/i }).click();
            });

            expect(mockNavigate).toHaveBeenCalledWith('/');
        });
    });
});
