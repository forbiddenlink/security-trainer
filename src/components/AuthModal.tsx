import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Mail, Lock, User, AlertCircle, Loader2 } from 'lucide-react';
import { useAuthStore } from '../store/authStore';
import { useGameStore } from '../store/gameStore';
import { isSupabaseConfigured } from '../lib/supabase';

export const AuthModal: React.FC = () => {
    const {
        isAuthModalOpen,
        authModalMode,
        loading,
        error,
        closeAuthModal,
        signIn,
        signUp,
        signInWithGoogle,
        clearError,
        loadProgressFromCloud,
    } = useAuthStore();

    const gameStore = useGameStore();

    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [displayName, setDisplayName] = useState('');
    const [showMergeOption, setShowMergeOption] = useState(false);

    const hasLocalProgress = gameStore.xp > 0 || gameStore.completedLessons.length > 0;

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        clearError();

        let result;
        if (authModalMode === 'signup') {
            result = await signUp(email, password, displayName);
        } else {
            result = await signIn(email, password);
        }

        if (!result.error) {
            // Check if we need to merge progress
            if (hasLocalProgress && authModalMode === 'login') {
                const cloudProfile = await loadProgressFromCloud();
                if (cloudProfile && cloudProfile.xp > 0) {
                    setShowMergeOption(true);
                    return;
                }
            }

            // Sync local progress to cloud
            await syncLocalProgressToCloud();
            handleClose();
        }
    };

    const handleGoogleSignIn = async () => {
        clearError();
        await signInWithGoogle();
    };

    const syncLocalProgressToCloud = async () => {
        const { syncProgressToCloud } = useAuthStore.getState();
        await syncProgressToCloud({
            xp: gameStore.xp,
            level: gameStore.level,
            badges: gameStore.badges,
            completedModules: gameStore.completedModules,
            completedLessons: gameStore.completedLessons,
            streakDays: gameStore.streakDays,
            lastLoginDate: gameStore.lastLoginDate,
            dailyChallengeId: gameStore.dailyChallengeId,
            dailyChallengeDate: gameStore.dailyChallengeDate,
            dailyChallengeCompleted: gameStore.dailyChallengeCompleted,
        });
    };

    const handleMergeChoice = async (keepCloud: boolean) => {
        if (keepCloud) {
            // Load cloud progress into local store
            const cloudProfile = useAuthStore.getState().profile;
            if (cloudProfile) {
                // Reset local and apply cloud progress
                gameStore.resetProgress();
                // We need to apply cloud progress to local store
                // This is done via direct store update since we're merging
                useGameStore.setState({
                    xp: cloudProfile.xp,
                    level: cloudProfile.level,
                    badges: cloudProfile.badges,
                    completedModules: cloudProfile.completed_modules,
                    completedLessons: cloudProfile.completed_lessons,
                    streakDays: cloudProfile.streak_days,
                    lastLoginDate: cloudProfile.last_login_date,
                    dailyChallengeId: cloudProfile.daily_challenge_id,
                    dailyChallengeDate: cloudProfile.daily_challenge_date,
                    dailyChallengeCompleted: cloudProfile.daily_challenge_completed,
                });
            }
        } else {
            // Keep local and sync to cloud
            await syncLocalProgressToCloud();
        }
        setShowMergeOption(false);
        handleClose();
    };

    const handleClose = () => {
        setEmail('');
        setPassword('');
        setDisplayName('');
        setShowMergeOption(false);
        clearError();
        closeAuthModal();
    };

    if (!isSupabaseConfigured()) {
        return null;
    }

    return (
        <AnimatePresence>
            {isAuthModalOpen && (
                <>
                    {/* Backdrop */}
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50"
                        onClick={handleClose}
                        aria-hidden="true"
                    />

                    {/* Modal */}
                    <motion.div
                        initial={{ opacity: 0, scale: 0.95, y: 20 }}
                        animate={{ opacity: 1, scale: 1, y: 0 }}
                        exit={{ opacity: 0, scale: 0.95, y: 20 }}
                        className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-md bg-card border border-border rounded-2xl shadow-2xl z-50 overflow-hidden"
                        role="dialog"
                        aria-modal="true"
                        aria-labelledby="auth-modal-title"
                    >
                        {/* Header */}
                        <div className="relative p-6 border-b border-border bg-gradient-to-r from-primary/10 to-purple-500/10">
                            <button
                                onClick={handleClose}
                                className="absolute top-4 right-4 p-2 rounded-full hover:bg-muted transition-colors"
                                aria-label="Close modal"
                            >
                                <X className="w-5 h-5 text-muted-foreground" />
                            </button>
                            <h2 id="auth-modal-title" className="text-2xl font-bold text-foreground">
                                {showMergeOption
                                    ? 'Sync Progress'
                                    : authModalMode === 'login'
                                        ? 'Welcome Back, Agent'
                                        : 'Join the Mission'}
                            </h2>
                            <p className="text-muted-foreground mt-1">
                                {showMergeOption
                                    ? 'We found existing progress. Choose which to keep.'
                                    : authModalMode === 'login'
                                        ? 'Sign in to sync your progress'
                                        : 'Create an account to save your progress'}
                            </p>
                        </div>

                        {/* Content */}
                        <div className="p-6">
                            {showMergeOption ? (
                                <div className="space-y-4">
                                    <div className="p-4 bg-muted/50 rounded-lg">
                                        <h3 className="font-semibold mb-2">Cloud Progress</h3>
                                        <p className="text-sm text-muted-foreground">
                                            XP: {useAuthStore.getState().profile?.xp || 0} |
                                            Level: {useAuthStore.getState().profile?.level || 1}
                                        </p>
                                    </div>
                                    <div className="p-4 bg-muted/50 rounded-lg">
                                        <h3 className="font-semibold mb-2">Local Progress</h3>
                                        <p className="text-sm text-muted-foreground">
                                            XP: {gameStore.xp} | Level: {gameStore.level}
                                        </p>
                                    </div>
                                    <div className="flex gap-3 mt-6">
                                        <button
                                            onClick={() => handleMergeChoice(true)}
                                            className="flex-1 py-3 px-4 bg-muted hover:bg-muted/80 rounded-lg font-medium transition-colors"
                                        >
                                            Keep Cloud
                                        </button>
                                        <button
                                            onClick={() => handleMergeChoice(false)}
                                            className="flex-1 py-3 px-4 bg-primary text-primary-foreground hover:bg-primary/90 rounded-lg font-medium transition-colors"
                                        >
                                            Keep Local
                                        </button>
                                    </div>
                                </div>
                            ) : (
                                <>
                                    {error && (
                                        <div className="mb-4 p-3 bg-destructive/10 border border-destructive/20 rounded-lg flex items-center gap-2 text-destructive">
                                            <AlertCircle className="w-5 h-5 flex-shrink-0" />
                                            <span className="text-sm">{error}</span>
                                        </div>
                                    )}

                                    <form onSubmit={handleSubmit} className="space-y-4">
                                        {authModalMode === 'signup' && (
                                            <div>
                                                <label htmlFor="displayName" className="block text-sm font-medium text-foreground mb-1.5">
                                                    Display Name
                                                </label>
                                                <div className="relative">
                                                    <User className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                                                    <input
                                                        id="displayName"
                                                        type="text"
                                                        value={displayName}
                                                        onChange={(e) => setDisplayName(e.target.value)}
                                                        placeholder="Agent Smith"
                                                        className="w-full pl-10 pr-4 py-3 bg-muted border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-colors"
                                                    />
                                                </div>
                                            </div>
                                        )}

                                        <div>
                                            <label htmlFor="email" className="block text-sm font-medium text-foreground mb-1.5">
                                                Email
                                            </label>
                                            <div className="relative">
                                                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                                                <input
                                                    id="email"
                                                    type="email"
                                                    value={email}
                                                    onChange={(e) => setEmail(e.target.value)}
                                                    placeholder="agent@example.com"
                                                    required
                                                    className="w-full pl-10 pr-4 py-3 bg-muted border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-colors"
                                                />
                                            </div>
                                        </div>

                                        <div>
                                            <label htmlFor="password" className="block text-sm font-medium text-foreground mb-1.5">
                                                Password
                                            </label>
                                            <div className="relative">
                                                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
                                                <input
                                                    id="password"
                                                    type="password"
                                                    value={password}
                                                    onChange={(e) => setPassword(e.target.value)}
                                                    placeholder="Enter your password"
                                                    required
                                                    minLength={6}
                                                    className="w-full pl-10 pr-4 py-3 bg-muted border border-border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-colors"
                                                />
                                            </div>
                                        </div>

                                        <button
                                            type="submit"
                                            disabled={loading}
                                            className="w-full py-3 bg-primary text-primary-foreground font-semibold rounded-lg hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                                        >
                                            {loading && <Loader2 className="w-5 h-5 animate-spin" />}
                                            {authModalMode === 'login' ? 'Sign In' : 'Create Account'}
                                        </button>
                                    </form>

                                    <div className="relative my-6">
                                        <div className="absolute inset-0 flex items-center">
                                            <div className="w-full border-t border-border" />
                                        </div>
                                        <div className="relative flex justify-center text-xs uppercase">
                                            <span className="bg-card px-2 text-muted-foreground">Or continue with</span>
                                        </div>
                                    </div>

                                    <button
                                        onClick={handleGoogleSignIn}
                                        disabled={loading}
                                        className="w-full py-3 bg-muted border border-border font-medium rounded-lg hover:bg-muted/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                                    >
                                        <svg className="w-5 h-5" viewBox="0 0 24 24">
                                            <path
                                                fill="currentColor"
                                                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                                            />
                                            <path
                                                fill="currentColor"
                                                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                                            />
                                            <path
                                                fill="currentColor"
                                                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                                            />
                                            <path
                                                fill="currentColor"
                                                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                                            />
                                        </svg>
                                        Google
                                    </button>

                                    <p className="mt-6 text-center text-sm text-muted-foreground">
                                        {authModalMode === 'login' ? (
                                            <>
                                                Don't have an account?{' '}
                                                <button
                                                    onClick={() => {
                                                        clearError();
                                                        useAuthStore.setState({ authModalMode: 'signup' });
                                                    }}
                                                    className="text-primary hover:underline font-medium"
                                                >
                                                    Sign up
                                                </button>
                                            </>
                                        ) : (
                                            <>
                                                Already have an account?{' '}
                                                <button
                                                    onClick={() => {
                                                        clearError();
                                                        useAuthStore.setState({ authModalMode: 'login' });
                                                    }}
                                                    className="text-primary hover:underline font-medium"
                                                >
                                                    Sign in
                                                </button>
                                            </>
                                        )}
                                    </p>
                                </>
                            )}
                        </div>
                    </motion.div>
                </>
            )}
        </AnimatePresence>
    );
};
