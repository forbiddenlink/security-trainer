import { describe, it, expect, beforeEach, vi } from 'vitest';
import { screen } from '@testing-library/react';
import { renderWithRouter, resetGameStore, setupGameStore } from '../../test/testUtils';
import { Header } from '../Header';

// Mock framer-motion
vi.mock('framer-motion', () => ({
    motion: {
        div: ({ children, ...props }: { children?: React.ReactNode }) => <div {...props}>{children}</div>,
    },
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

    describe('streak/energy display', () => {
        it('shows energy based on XP', () => {
            setupGameStore({ xp: 350 });

            renderWithRouter(<Header />);

            // Energy is Math.floor(xp / 100)
            expect(screen.getByText('3')).toBeInTheDocument();
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
