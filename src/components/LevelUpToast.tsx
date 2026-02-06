import React, { useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Trophy, X } from 'lucide-react';
import { useGameStore } from '../store/gameStore';

export const LevelUpToast: React.FC = () => {
    const { level, showLevelUpToast, dismissLevelUpToast } = useGameStore();

    // Auto-dismiss toast after 5 seconds
    useEffect(() => {
        if (!showLevelUpToast) return;

        const timer = setTimeout(() => {
            dismissLevelUpToast();
        }, 5000);

        return () => clearTimeout(timer);
    }, [showLevelUpToast, dismissLevelUpToast]);

    return (
        <AnimatePresence>
            {showLevelUpToast && (
                <motion.div
                    initial={{ opacity: 0, y: 50, scale: 0.8 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: 50, scale: 0.8 }}
                    className="fixed bottom-8 right-8 z-50 bg-gradient-to-r from-yellow-500 to-amber-600 p-1 rounded-xl shadow-2xl shadow-amber-500/20"
                    role="alertdialog"
                    aria-labelledby="levelup-title"
                    aria-describedby="levelup-description"
                    aria-live="polite"
                >
                    <div className="bg-background rounded-lg p-6 flex flex-col items-center gap-2 min-w-[300px]">
                        <button
                            onClick={dismissLevelUpToast}
                            className="absolute top-2 right-2 text-muted-foreground hover:text-foreground"
                            aria-label="Dismiss level up notification"
                        >
                            <X className="w-4 h-4" aria-hidden="true" />
                        </button>

                        <div className="p-4 bg-amber-500/10 rounded-full mb-2 animate-bounce" aria-hidden="true">
                            <Trophy className="w-12 h-12 text-amber-500" />
                        </div>
                        <h3 id="levelup-title" className="text-2xl font-bold bg-gradient-to-r from-amber-500 to-yellow-400 bg-clip-text text-transparent">
                            Level Up!
                        </h3>
                        <p id="levelup-description" className="text-center text-muted-foreground">
                            You are now a <span className="text-foreground font-bold">Level {level}</span> Operator.
                        </p>
                    </div>
                </motion.div>
            )}
        </AnimatePresence>
    );
};
