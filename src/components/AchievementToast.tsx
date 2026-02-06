import React, { useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Award, Flame, CheckCircle, Star, X } from 'lucide-react';
import { useGameStore } from '../store/gameStore';
import type { AchievementNotification } from '../types';

const getIconForType = (type: AchievementNotification['type']) => {
    switch (type) {
        case 'badge':
            return <Award className="w-10 h-10 text-purple-500" />;
        case 'streak':
            return <Flame className="w-10 h-10 text-orange-500" />;
        case 'module_complete':
            return <CheckCircle className="w-10 h-10 text-emerald-500" />;
        case 'daily_challenge':
            return <Star className="w-10 h-10 text-yellow-500" />;
        default:
            return <Award className="w-10 h-10 text-primary" />;
    }
};

const getGradientForType = (type: AchievementNotification['type']) => {
    switch (type) {
        case 'badge':
            return 'from-purple-500 to-pink-500';
        case 'streak':
            return 'from-orange-500 to-red-500';
        case 'module_complete':
            return 'from-emerald-500 to-cyan-500';
        case 'daily_challenge':
            return 'from-yellow-500 to-amber-500';
        default:
            return 'from-primary to-purple-500';
    }
};

export const AchievementToast: React.FC = () => {
    const { achievementQueue, dismissAchievement } = useGameStore();
    const currentAchievement = achievementQueue[0];

    // Auto-dismiss after 4 seconds
    useEffect(() => {
        if (!currentAchievement) return;

        const timer = setTimeout(() => {
            dismissAchievement();
        }, 4000);

        return () => clearTimeout(timer);
    }, [currentAchievement, dismissAchievement]);

    return (
        <AnimatePresence>
            {currentAchievement && (
                <motion.div
                    key={currentAchievement.id}
                    initial={{ opacity: 0, x: 50, scale: 0.8 }}
                    animate={{ opacity: 1, x: 0, scale: 1 }}
                    exit={{ opacity: 0, x: 50, scale: 0.8 }}
                    className={`fixed bottom-24 right-8 z-50 bg-gradient-to-r ${getGradientForType(currentAchievement.type)} p-1 rounded-xl shadow-2xl`}
                    role="alert"
                    aria-live="polite"
                >
                    <div className="bg-background rounded-lg p-5 flex items-center gap-4 min-w-[280px]">
                        <button
                            onClick={dismissAchievement}
                            className="absolute top-2 right-2 text-muted-foreground hover:text-foreground"
                            aria-label="Dismiss notification"
                        >
                            <X className="w-4 h-4" aria-hidden="true" />
                        </button>

                        <div className="p-3 bg-muted/50 rounded-full">
                            {getIconForType(currentAchievement.type)}
                        </div>

                        <div>
                            <h3 className={`text-lg font-bold bg-gradient-to-r ${getGradientForType(currentAchievement.type)} bg-clip-text text-transparent`}>
                                {currentAchievement.title}
                            </h3>
                            <p className="text-sm text-muted-foreground">
                                {currentAchievement.message}
                            </p>
                        </div>
                    </div>
                </motion.div>
            )}
        </AnimatePresence>
    );
};
