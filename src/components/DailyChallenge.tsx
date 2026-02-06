import React, { useState, useEffect, useMemo } from 'react';
import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Star, Clock, CheckCircle, ArrowRight } from 'lucide-react';
import { useGameStore } from '../store/gameStore';

export const DailyChallenge: React.FC = () => {
    const { getDailyChallenge, dailyChallengeCompleted } = useGameStore();
    const [timeRemaining, setTimeRemaining] = useState('');

    const challenge = useMemo(() => getDailyChallenge(), [getDailyChallenge]);

    // Calculate time until midnight
    useEffect(() => {
        const updateTimer = () => {
            const now = new Date();
            const midnight = new Date();
            midnight.setHours(24, 0, 0, 0);

            const diff = midnight.getTime() - now.getTime();

            const hours = Math.floor(diff / (1000 * 60 * 60));
            const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
            const seconds = Math.floor((diff % (1000 * 60)) / 1000);

            setTimeRemaining(
                `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`
            );
        };

        updateTimer();
        const interval = setInterval(updateTimer, 1000);

        return () => clearInterval(interval);
    }, []);

    if (!challenge) {
        return (
            <div className="bg-card border border-border rounded-xl p-6 shadow-sm">
                <div className="flex items-center gap-3 mb-4">
                    <div className="p-2 bg-yellow-500/10 text-yellow-500 rounded-lg">
                        <Star className="w-6 h-6" />
                    </div>
                    <h3 className="text-lg font-bold">Daily Challenge</h3>
                </div>
                <p className="text-muted-foreground">
                    All lessons completed! Check back tomorrow for a new challenge.
                </p>
            </div>
        );
    }

    return (
        <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className={`relative overflow-hidden rounded-xl border ${
                dailyChallengeCompleted
                    ? 'bg-emerald-500/10 border-emerald-500/30'
                    : 'bg-gradient-to-br from-yellow-500/10 to-amber-500/10 border-yellow-500/30'
            } p-6 shadow-sm`}
        >
            {/* Decorative glow */}
            {!dailyChallengeCompleted && (
                <div className="absolute -top-10 -right-10 w-32 h-32 bg-yellow-500/20 blur-3xl rounded-full pointer-events-none" />
            )}

            <div className="relative z-10">
                <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-lg ${
                            dailyChallengeCompleted
                                ? 'bg-emerald-500/10 text-emerald-500'
                                : 'bg-yellow-500/10 text-yellow-500'
                        }`}>
                            {dailyChallengeCompleted ? (
                                <CheckCircle className="w-6 h-6" />
                            ) : (
                                <Star className="w-6 h-6" />
                            )}
                        </div>
                        <div>
                            <h3 className="text-lg font-bold">Daily Challenge</h3>
                            <p className="text-xs text-muted-foreground">
                                {dailyChallengeCompleted ? 'Completed!' : '+50 Bonus XP'}
                            </p>
                        </div>
                    </div>

                    {!dailyChallengeCompleted && (
                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                            <Clock className="w-4 h-4" />
                            <span className="font-mono">{timeRemaining}</span>
                        </div>
                    )}
                </div>

                <div className="bg-background/50 rounded-lg p-4 mb-4">
                    <p className="text-sm text-muted-foreground mb-1">
                        {challenge.moduleTitle}
                    </p>
                    <p className="font-semibold">{challenge.lessonTitle}</p>
                </div>

                {dailyChallengeCompleted ? (
                    <div className="flex items-center justify-center gap-2 py-3 px-4 bg-emerald-500/20 text-emerald-500 rounded-lg font-medium">
                        <CheckCircle className="w-5 h-5" />
                        Challenge Complete!
                    </div>
                ) : (
                    <Link
                        to={`/modules/${challenge.moduleId}/${challenge.lessonId}`}
                        className="group flex items-center justify-center gap-2 py-3 px-4 bg-yellow-500 hover:bg-yellow-600 text-black rounded-lg font-bold transition-all hover:scale-[1.02]"
                    >
                        Start Challenge
                        <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                    </Link>
                )}
            </div>
        </motion.div>
    );
};
