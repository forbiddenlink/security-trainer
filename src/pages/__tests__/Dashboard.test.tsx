import { describe, it, expect, beforeEach, vi } from 'vitest';
import { screen } from '@testing-library/react';
import { renderWithRouter, resetGameStore, setupGameStore } from '../../test/testUtils';
import { Dashboard } from '../Dashboard';

// Mock framer-motion to avoid animation issues in tests
vi.mock('framer-motion', () => ({
    motion: {
        div: ({ children, ...props }: { children?: React.ReactNode }) => <div {...props}>{children}</div>,
    },
}));

describe('Dashboard', () => {
    beforeEach(() => {
        resetGameStore();
    });

    describe('rendering', () => {
        it('renders the welcome message', () => {
            renderWithRouter(<Dashboard />);

            expect(screen.getByText('Welcome back, Agent.')).toBeInTheDocument();
        });

        it('displays the current XP', () => {
            setupGameStore({ xp: 500 });

            renderWithRouter(<Dashboard />);

            expect(screen.getByText('500 XP')).toBeInTheDocument();
        });

        it('displays the current level', () => {
            setupGameStore({ level: 3 });

            renderWithRouter(<Dashboard />);

            expect(screen.getByText('Level 3')).toBeInTheDocument();
        });

        it('calculates XP needed for next level correctly', () => {
            // At level 2 with 500 XP, need 2000 total, so 1500 remaining
            setupGameStore({ level: 2, xp: 500 });

            renderWithRouter(<Dashboard />);

            expect(screen.getByText('1500 XP to next level')).toBeInTheDocument();
        });

        it('displays number of completed modules', () => {
            setupGameStore({ completedModules: ['owasp-intro', 'sql-injection'] });

            renderWithRouter(<Dashboard />);

            expect(screen.getByText('2')).toBeInTheDocument();
        });
    });

    describe('current module display', () => {
        it('shows "No Active Mission" when no module is set', () => {
            setupGameStore({ currentModuleId: null });

            renderWithRouter(<Dashboard />);

            expect(screen.getByText('No Active Mission')).toBeInTheDocument();
        });

        it('shows current module title when a module is active', () => {
            setupGameStore({ currentModuleId: 'owasp-intro' });

            renderWithRouter(<Dashboard />);

            expect(screen.getByText('Introduction to OWASP')).toBeInTheDocument();
        });
    });

    describe('navigation links', () => {
        it('has a link to resume training', () => {
            renderWithRouter(<Dashboard />);

            const resumeLink = screen.getByRole('link', { name: /resume training/i });
            expect(resumeLink).toHaveAttribute('href', '/modules');
        });

        it('has a link to view all achievements', () => {
            renderWithRouter(<Dashboard />);

            const viewAllLink = screen.getByRole('link', { name: /view all/i });
            expect(viewAllLink).toHaveAttribute('href', '/profile');
        });
    });

    describe('badges section', () => {
        it('renders the badges section with heading', () => {
            renderWithRouter(<Dashboard />);

            expect(screen.getByText('Achievements')).toBeInTheDocument();
        });
    });

    describe('stat cards', () => {
        it('displays the Current Score card', () => {
            renderWithRouter(<Dashboard />);

            expect(screen.getByText('Current Score')).toBeInTheDocument();
        });

        it('displays the Modules Completed card', () => {
            renderWithRouter(<Dashboard />);

            expect(screen.getByText('Modules Completed')).toBeInTheDocument();
        });

        it('displays the Active Mission card', () => {
            renderWithRouter(<Dashboard />);

            expect(screen.getByText('Active Mission')).toBeInTheDocument();
        });
    });
});
