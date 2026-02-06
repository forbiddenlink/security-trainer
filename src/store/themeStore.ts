import { create } from 'zustand';
import { persist } from 'zustand/middleware';

type Theme = 'light' | 'dark' | 'system';

interface ThemeStore {
    theme: Theme;
    resolvedTheme: 'light' | 'dark';
    setTheme: (theme: Theme) => void;
    initializeTheme: () => void;
}

// Get system preference
const getSystemTheme = (): 'light' | 'dark' => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return 'dark';
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
};

// Apply theme to document
const applyTheme = (resolvedTheme: 'light' | 'dark') => {
    const root = document.documentElement;

    if (resolvedTheme === 'dark') {
        root.classList.add('dark');
        root.classList.remove('light');
    } else {
        root.classList.add('light');
        root.classList.remove('dark');
    }
};

export const useThemeStore = create<ThemeStore>()(
    persist(
        (set, get) => ({
            theme: 'system',
            resolvedTheme: getSystemTheme(),

            setTheme: (theme: Theme) => {
                const resolvedTheme = theme === 'system' ? getSystemTheme() : theme;
                applyTheme(resolvedTheme);
                set({ theme, resolvedTheme });
            },

            initializeTheme: () => {
                const { theme } = get();
                const resolvedTheme = theme === 'system' ? getSystemTheme() : theme;
                applyTheme(resolvedTheme);
                set({ resolvedTheme });

                // Listen for system preference changes
                if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
                    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');

                    const handleChange = (e: MediaQueryListEvent) => {
                        const { theme } = get();
                        if (theme === 'system') {
                            const newResolvedTheme = e.matches ? 'dark' : 'light';
                            applyTheme(newResolvedTheme);
                            set({ resolvedTheme: newResolvedTheme });
                        }
                    };

                    mediaQuery.addEventListener('change', handleChange);
                }
            },
        }),
        {
            name: 'security-trainer-theme',
            partialize: (state) => ({
                theme: state.theme,
            }),
        }
    )
);
