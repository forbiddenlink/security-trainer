import React, { useEffect, useRef, useState } from 'react';
import { useGameStore } from '../store/gameStore';
import { useAuthStore } from '../store/authStore';
import { Bell, Trophy, LogIn, LogOut, ChevronDown } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { StreakIndicator } from './StreakIndicator';
import { ThemeToggle } from './ThemeToggle';
import { isSupabaseConfigured } from '../lib/supabase';

export const Header: React.FC = () => {
    const { xp, level, checkStreak, checkDailyChallenge } = useGameStore();
    const { user, profile, loading, openAuthModal, signOut, initialize } = useAuthStore();
    const [showUserMenu, setShowUserMenu] = useState(false);
    const menuRef = useRef<HTMLDivElement>(null);

    // Initialize auth on mount
    useEffect(() => {
        if (isSupabaseConfigured()) {
            initialize();
        }
    }, [initialize]);

    // Check streak and daily challenge on mount
    useEffect(() => {
        checkStreak();
        checkDailyChallenge();
    }, [checkStreak, checkDailyChallenge]);

    // Close menu on outside click
    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
                setShowUserMenu(false);
            }
        };

        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    const nextLevelXp = level * 1000;
    const progress = Math.min((xp / nextLevelXp) * 100, 100);

    const displayName = profile?.display_name || user?.email?.split('@')[0] || 'Agent';
    const avatarInitial = displayName[0]?.toUpperCase() || 'A';

    return (
        <header className="h-16 bg-card/50 backdrop-blur-sm border-b border-border flex items-center justify-between px-6 sticky top-0 z-10 transition-all" role="banner">
            <div className="flex items-center gap-4">
                {/* Breadcrumbs or Page Title could go here */}
                <h1 className="text-lg font-semibold text-foreground">Mission Control</h1>
            </div>

            <div className="flex items-center gap-6" aria-label="User stats">
                {/* Level Indicator */}
                <div className="flex flex-col items-end mr-2 group cursor-help" aria-live="polite">
                    <div className="flex items-center gap-2 text-sm font-medium text-foreground">
                        <Trophy className="w-4 h-4 text-yellow-500" aria-hidden="true" />
                        <span>Level {level}</span>
                    </div>
                    <div
                        className="w-32 h-2 bg-muted rounded-full mt-1 overflow-hidden relative"
                        role="progressbar"
                        aria-valuenow={xp}
                        aria-valuemin={0}
                        aria-valuemax={nextLevelXp}
                        aria-label={`${xp} of ${nextLevelXp} XP to next level`}
                    >
                        <motion.div
                            className="h-full bg-gradient-to-r from-primary to-purple-500"
                            initial={{ width: 0 }}
                            animate={{ width: `${progress}%` }}
                            transition={{ duration: 1, ease: "easeOut" }}
                        />
                    </div>
                    <span className="text-[10px] text-muted-foreground absolute top-12 opacity-0 group-hover:opacity-100 transition-opacity" aria-hidden="true">
                        {xp} / {nextLevelXp} XP
                    </span>
                    <span className="sr-only">{xp} of {nextLevelXp} XP to next level</span>
                </div>

                {/* Streak Indicator */}
                <StreakIndicator />

                {/* Theme Toggle */}
                <ThemeToggle />

                <button
                    className="relative p-2 rounded-full hover:bg-muted/50 transition-colors"
                    aria-label="Notifications (1 unread)"
                >
                    <Bell className="w-5 h-5 text-muted-foreground" aria-hidden="true" />
                    <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-destructive rounded-full border border-card" aria-hidden="true" />
                </button>

                {/* Auth Section */}
                {isSupabaseConfigured() ? (
                    loading ? (
                        <div className="w-8 h-8 rounded-full bg-muted animate-pulse" />
                    ) : user ? (
                        <div className="relative" ref={menuRef}>
                            <button
                                onClick={() => setShowUserMenu(!showUserMenu)}
                                className="flex items-center gap-2 p-1 pr-2 rounded-full hover:bg-muted/50 transition-colors"
                                aria-label="User menu"
                                aria-expanded={showUserMenu}
                            >
                                {profile?.avatar_url ? (
                                    <img
                                        src={profile.avatar_url}
                                        alt=""
                                        className="w-8 h-8 rounded-full object-cover border border-primary/20"
                                    />
                                ) : (
                                    <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-500 to-cyan-500 border border-primary/20 shadow-lg shadow-primary/20 flex items-center justify-center text-white text-sm font-bold">
                                        {avatarInitial}
                                    </div>
                                )}
                                <ChevronDown className="w-4 h-4 text-muted-foreground" />
                            </button>

                            <AnimatePresence>
                                {showUserMenu && (
                                    <motion.div
                                        initial={{ opacity: 0, y: 8, scale: 0.95 }}
                                        animate={{ opacity: 1, y: 0, scale: 1 }}
                                        exit={{ opacity: 0, y: 8, scale: 0.95 }}
                                        className="absolute right-0 mt-2 w-56 bg-card border border-border rounded-xl shadow-lg overflow-hidden"
                                    >
                                        <div className="p-3 border-b border-border">
                                            <p className="font-medium text-foreground truncate">{displayName}</p>
                                            <p className="text-sm text-muted-foreground truncate">{user.email}</p>
                                        </div>
                                        <div className="p-2">
                                            <button
                                                onClick={() => {
                                                    setShowUserMenu(false);
                                                    signOut();
                                                }}
                                                className="w-full flex items-center gap-2 px-3 py-2 text-sm text-muted-foreground hover:bg-muted rounded-lg transition-colors"
                                            >
                                                <LogOut className="w-4 h-4" />
                                                Sign Out
                                            </button>
                                        </div>
                                    </motion.div>
                                )}
                            </AnimatePresence>
                        </div>
                    ) : (
                        <button
                            onClick={() => openAuthModal('login')}
                            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg font-medium hover:bg-primary/90 transition-colors"
                        >
                            <LogIn className="w-4 h-4" />
                            <span className="hidden sm:inline">Sign In</span>
                        </button>
                    )
                ) : (
                    <div
                        className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-500 to-cyan-500 border border-primary/20 shadow-lg shadow-primary/20"
                        role="img"
                        aria-label="User avatar"
                    />
                )}
            </div>
        </header>
    );
};
