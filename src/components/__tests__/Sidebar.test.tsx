import { describe, it, expect } from 'vitest';
import { screen } from '@testing-library/react';
import { renderWithRouter, userEvent } from '../../test/testUtils';
import { Sidebar } from '../Sidebar';

describe('Sidebar', () => {
    describe('branding', () => {
        it('displays the SecTrainer logo text', () => {
            renderWithRouter(<Sidebar />);

            expect(screen.getByText('SecTrainer')).toBeInTheDocument();
        });
    });

    describe('navigation links', () => {
        it('has a link to Dashboard', () => {
            renderWithRouter(<Sidebar />);

            const dashboardLink = screen.getByRole('link', { name: /dashboard/i });
            expect(dashboardLink).toHaveAttribute('href', '/');
        });

        it('has a link to Modules', () => {
            renderWithRouter(<Sidebar />);

            const modulesLink = screen.getByRole('link', { name: /modules/i });
            expect(modulesLink).toHaveAttribute('href', '/modules');
        });

        it('has a link to Profile', () => {
            renderWithRouter(<Sidebar />);

            const profileLink = screen.getByRole('link', { name: /profile/i });
            expect(profileLink).toHaveAttribute('href', '/profile');
        });

        it('has a link to Final Exam', () => {
            renderWithRouter(<Sidebar />);

            const examLink = screen.getByRole('link', { name: /final exam/i });
            expect(examLink).toHaveAttribute('href', '/challenge');
        });

        it('has a link to Leaderboard', () => {
            renderWithRouter(<Sidebar />);

            const leaderboardLink = screen.getByRole('link', { name: /leaderboard/i });
            expect(leaderboardLink).toHaveAttribute('href', '/leaderboard');
        });

        it('renders all five navigation items', () => {
            renderWithRouter(<Sidebar />);

            const navLinks = screen.getAllByRole('link');
            expect(navLinks).toHaveLength(5);
        });
    });

    describe('navigation labels', () => {
        it('shows Dashboard label', () => {
            renderWithRouter(<Sidebar />);

            expect(screen.getByText('Dashboard')).toBeInTheDocument();
        });

        it('shows Modules label', () => {
            renderWithRouter(<Sidebar />);

            expect(screen.getByText('Modules')).toBeInTheDocument();
        });

        it('shows Profile label', () => {
            renderWithRouter(<Sidebar />);

            expect(screen.getByText('Profile')).toBeInTheDocument();
        });

        it('shows Leaderboard label', () => {
            renderWithRouter(<Sidebar />);

            expect(screen.getByText('Leaderboard')).toBeInTheDocument();
        });

        it('shows Final Exam label', () => {
            renderWithRouter(<Sidebar />);

            expect(screen.getByText('Final Exam')).toBeInTheDocument();
        });
    });

    describe('footer information', () => {
        it('displays Security Clearance label', () => {
            renderWithRouter(<Sidebar />);

            expect(screen.getByText(/Security Clearance:/i)).toBeInTheDocument();
        });

        it('displays Classified status', () => {
            renderWithRouter(<Sidebar />);

            expect(screen.getByText('Classified')).toBeInTheDocument();
        });

        it('displays system version', () => {
            renderWithRouter(<Sidebar />);

            expect(screen.getByText('System v1.0.0')).toBeInTheDocument();
        });
    });

    describe('active link styling', () => {
        it('applies active styles to current route', async () => {
            // By default with BrowserRouter, we're at "/"
            renderWithRouter(<Sidebar />);

            const dashboardLink = screen.getByRole('link', { name: /dashboard/i });
            // Check that it has the active class
            expect(dashboardLink).toHaveClass('bg-primary/10');
        });
    });

    describe('link navigation', () => {
        it('can navigate between links', async () => {
            const user = userEvent.setup();
            renderWithRouter(<Sidebar />);

            const modulesLink = screen.getByRole('link', { name: /modules/i });
            await user.click(modulesLink);

            // After navigation, the modules link should be present
            expect(screen.getByRole('link', { name: /modules/i })).toBeInTheDocument();
        });
    });
});
