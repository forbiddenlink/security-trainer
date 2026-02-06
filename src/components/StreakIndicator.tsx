import React from 'react';
import { motion } from 'framer-motion';
import { Flame } from 'lucide-react';
import { useGameStore } from '../store/gameStore';

export const StreakIndicator: React.FC = () => {
    const { streakDays, getStreakMultiplier } = useGameStore();
    const multiplier = getStreakMultiplier();
    const bonusPercent = Math.round((multiplier - 1) * 100);

    // Only show if streak is active (at least 1 day)
    if (streakDays < 1) {
        return null;
    }

    return (
        <div
            className="flex items-center gap-2 px-3 py-1.5 bg-gradient-to-r from-orange-500/20 to-red-500/20 rounded-full border border-orange-500/30 cursor-help"
            title={`${streakDays}-day streak! +${bonusPercent}% XP bonus`}
        >
            <motion.div
                animate={{
                    scale: [1, 1.2, 1],
                    rotate: [0, -5, 5, 0],
                }}
                transition={{
                    duration: 1.5,
                    repeat: Infinity,
                    repeatType: 'loop',
                }}
            >
                <Flame className="w-5 h-5 text-orange-500 fill-orange-500" aria-hidden="true" />
            </motion.div>
            <span className="font-bold text-orange-500">{streakDays}</span>
            {bonusPercent > 0 && (
                <span className="text-xs text-orange-400 font-medium">
                    +{bonusPercent}%
                </span>
            )}
            <span className="sr-only">
                {streakDays}-day streak with {bonusPercent}% XP bonus
            </span>
        </div>
    );
};
