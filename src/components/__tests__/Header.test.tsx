import { describe, it, expect, beforeEach, vi } from 'vitest';
import { screen } from '@testing-library/react';
import { renderWithRouter, resetGameStore, setupGameStore } from '../../test/testUtils';
import { Header } from '../Header';

// Mock framer-motion
vi.mock('framer-motion', () => ({
    motion: {
        div: ({ children, ...props }: { children?: React.ReactNode }) => <div {...props}>{children}</div>,
        span: ({ children, ...props }: { children?: React.ReactNode }) => <span {...props}>{children}</span>,
        button: ({ children, ...props }: { children?: React.ReactNode }) => <button {...props}>{children}</button>,
    },
    AnimatePresence: ({ children }: { children?: React.ReactNode }) => <>{children}</>,
}));

describe('Header', () => {
    beforeEach(() => {
        resetGameStore();
    });

    describe('level display', () => {
        it('shows the current level', () => {
            setupGameStore({ level: 3 });

            renderWithRouter(<Header />);

            expect(screen.getByText('Level 3')).toBeInTheDocument();
        });

        it('shows level 1 by default', () => {
            renderWithRouter(<Header />);

            expect(screen.getByText('Level 1')).toBeInTheDocument();
        });
    });

    describe('XP display', () => {
        it('shows XP progress on hover', () => {
            setupGameStore({ xp: 500, level: 1 });

            renderWithRouter(<Header />);

            // The XP text shows "current / required"
            expect(screen.getByText('500 / 1000 XP')).toBeInTheDocument();
        });

        it('calculates next level XP correctly', () => {
            // At level 2, next level is at 2000 XP
            setupGameStore({ xp: 1500, level: 2 });

            renderWithRouter(<Header />);

            expect(screen.getByText('1500 / 2000 XP')).toBeInTheDocument();
        });
    });

    describe('streak display', () => {
        it('shows streak indicator when streak is active', () => {
            setupGameStore({ streakDays: 3, lastLoginDate: new Date().toISOString().split('T')[0] });

            renderWithRouter(<Header />);

            // Streak days should be displayed
            expect(screen.getByText('3')).toBeInTheDocument();
            // Bonus percentage should be shown (+10% per day, max 7)
            expect(screen.getByText('+30%')).toBeInTheDocument();
        });

        it('shows streak count of 1 for first day login', () => {
            // When a user logs in for the first time or after losing streak,
            // checkStreak() sets streakDays to 1
            setupGameStore({ streakDays: 0, lastLoginDate: null });

            renderWithRouter(<Header />);

            // checkStreak runs on mount and sets streak to 1
            expect(screen.getByText('1')).toBeInTheDocument();
            expect(screen.getByText('+10%')).toBeInTheDocument();
        });
    });

    describe('header elements', () => {
        it('displays Mission Control title', () => {
            renderWithRouter(<Header />);

            expect(screen.getByText('Mission Control')).toBeInTheDocument();
        });

        it('has a notification bell button', () => {
            renderWithRouter(<Header />);

            // The bell is rendered but as an icon - check for button
            const buttons = screen.getAllByRole('button');
            expect(buttons.length).toBeGreaterThan(0);
        });

        it('renders user avatar element', () => {
            const { container } = renderWithRouter(<Header />);

            // Check for the avatar div with gradient background
            const avatar = container.querySelector('.rounded-full.bg-gradient-to-br');
            expect(avatar).toBeInTheDocument();
        });
    });

    describe('progress bar', () => {
        it('renders a progress bar for level progress', () => {
            setupGameStore({ xp: 500, level: 1 });

            const { container } = renderWithRouter(<Header />);

            // Check for progress bar container
            const progressBar = container.querySelector('.rounded-full.overflow-hidden');
            expect(progressBar).toBeInTheDocument();
        });
    });
});
