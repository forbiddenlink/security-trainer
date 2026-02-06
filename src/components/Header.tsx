import React from 'react';
import { useGameStore } from '../store/gameStore';
import { Bell, Trophy, Zap } from 'lucide-react';
import { motion } from 'framer-motion';

export const Header: React.FC = () => {
    const { xp, level } = useGameStore();
    const nextLevelXp = level * 1000;
    const progress = Math.min((xp / nextLevelXp) * 100, 100);

    return (
        <header className="h-16 bg-card/50 backdrop-blur-sm border-b border-border flex items-center justify-between px-6 sticky top-0 z-10 transition-all">
            <div className="flex items-center gap-4">
                {/* Breadcrumbs or Page Title could go here */}
                <h2 className="text-lg font-semibold text-foreground">Mission Control</h2>
            </div>

            <div className="flex items-center gap-6">
                {/* Level Indicator */}
                <div className="flex flex-col items-end mr-2 group cursor-help">
                    <div className="flex items-center gap-2 text-sm font-medium text-foreground">
                        <Trophy className="w-4 h-4 text-yellow-500" />
                        <span>Level {level}</span>
                    </div>
                    <div className="w-32 h-2 bg-muted rounded-full mt-1 overflow-hidden relative">
                        <motion.div
                            className="h-full bg-gradient-to-r from-primary to-purple-500"
                            initial={{ width: 0 }}
                            animate={{ width: `${progress}%` }}
                            transition={{ duration: 1, ease: "easeOut" }}
                        />
                    </div>
                    <span className="text-[10px] text-muted-foreground absolute top-12 opacity-0 group-hover:opacity-100 transition-opacity">
                        {xp} / {nextLevelXp} XP
                    </span>
                </div>

                {/* Streak / Energy (Optional gamification element) */}
                <div className="flex items-center gap-1 text-amber-400 font-bold">
                    <Zap className="w-5 h-5 fill-current" />
                    <span>{Math.floor(xp / 100)}</span>
                </div>

                <button className="relative p-2 rounded-full hover:bg-muted/50 transition-colors">
                    <Bell className="w-5 h-5 text-muted-foreground" />
                    <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-destructive rounded-full border border-card" />
                </button>

                <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-500 to-cyan-500 border border-primary/20 shadow-lg shadow-primary/20" />
            </div>
        </header>
    );
};
