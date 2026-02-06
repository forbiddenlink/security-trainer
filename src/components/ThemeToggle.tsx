import React from 'react';
import { Sun, Moon, Monitor } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { useThemeStore } from '../store/themeStore';

export const ThemeToggle: React.FC = () => {
    const { theme, setTheme } = useThemeStore();

    const cycleTheme = () => {
        const themes: Array<'light' | 'dark' | 'system'> = ['light', 'dark', 'system'];
        const currentIndex = themes.indexOf(theme);
        const nextIndex = (currentIndex + 1) % themes.length;
        setTheme(themes[nextIndex]);
    };

    const getIcon = () => {
        switch (theme) {
            case 'light':
                return <Sun className="w-5 h-5" />;
            case 'dark':
                return <Moon className="w-5 h-5" />;
            case 'system':
                return <Monitor className="w-5 h-5" />;
        }
    };

    const getLabel = () => {
        switch (theme) {
            case 'light':
                return 'Light mode. Click to switch to dark mode.';
            case 'dark':
                return 'Dark mode. Click to switch to system preference.';
            case 'system':
                return 'System preference. Click to switch to light mode.';
        }
    };

    return (
        <button
            onClick={cycleTheme}
            className="relative p-2 rounded-full hover:bg-muted/50 transition-colors text-muted-foreground hover:text-foreground"
            aria-label={getLabel()}
            title={`Theme: ${theme}`}
        >
            <AnimatePresence mode="wait">
                <motion.div
                    key={theme}
                    initial={{ scale: 0.5, opacity: 0, rotate: -90 }}
                    animate={{ scale: 1, opacity: 1, rotate: 0 }}
                    exit={{ scale: 0.5, opacity: 0, rotate: 90 }}
                    transition={{ duration: 0.2 }}
                >
                    {getIcon()}
                </motion.div>
            </AnimatePresence>
        </button>
    );
};
