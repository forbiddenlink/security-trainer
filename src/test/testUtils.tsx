/* eslint-disable react-refresh/only-export-components */
import React, { type ReactElement } from 'react';
import { render, type RenderOptions } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import { useGameStore } from '../store/gameStore';

// Wrapper component for tests that need routing
const AllTheProviders = ({ children }: { children: React.ReactNode }) => {
    return <BrowserRouter>{children}</BrowserRouter>;
};

// Custom render with providers
export const renderWithRouter = (
    ui: ReactElement,
    options?: Omit<RenderOptions, 'wrapper'>
) => render(ui, { wrapper: AllTheProviders, ...options });

// Helper to reset store state for tests
export const resetGameStore = () => {
    useGameStore.getState().resetProgress();
    useGameStore.setState({ showLevelUpToast: false });
};

// Helper to set up store with specific state
export const setupGameStore = (state: Partial<{
    xp: number;
    level: number;
    completedModules: string[];
    badges: string[];
    currentModuleId: string | null;
    streakDays: number;
    lastLoginDate: string | null;
}>) => {
    resetGameStore();
    useGameStore.setState(state);
};

// Re-export everything from testing-library
export * from '@testing-library/react';
export { default as userEvent } from '@testing-library/user-event';
