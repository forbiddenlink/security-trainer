import React, { useEffect } from 'react';
import { useGameStore } from '../store/gameStore';
import { BadgeList } from '../components/BadgeList';
import { User, Shield, Zap, Calendar, Award } from 'lucide-react';
import { motion } from 'framer-motion';
import { Certificate } from '../components/Certificate';

export const Profile: React.FC = () => {
    const { xp, level, streakDays, completedModules, checkStreak } = useGameStore();

    useEffect(() => {
        checkStreak();
    }, [checkStreak]);

    const nextLevelXp = level * 1000;
    const progress = Math.min((xp / nextLevelXp) * 100, 100);

    return (
        <div className="max-w-4xl mx-auto space-y-8 animate-in fade-in duration-500">
            <div className="flex flex-col md:flex-row gap-8 items-center md:items-start">
                {/* Avatar Card */}
                <div className="bg-card border border-border p-8 rounded-2xl flex flex-col items-center gap-4 min-w-[250px] shadow-lg">
                    <div className="w-32 h-32 rounded-full bg-gradient-to-br from-primary to-purple-500 p-1">
                        <div className="w-full h-full rounded-full bg-card flex items-center justify-center overflow-hidden">
                            <User className="w-16 h-16 text-muted-foreground" />
                        </div>
                    </div>
                    <div className="text-center">
                        <h2 className="text-2xl font-bold">Agent Zero</h2>
                        <p className="text-primary font-mono text-sm uppercase tracking-widest mt-1">Level {level} Operator</p>
                    </div>
                    <div className="w-full h-px bg-border my-2" />
                    <div className="grid grid-cols-2 gap-4 w-full text-center">
                        <div>
                            <p className="text-2xl font-bold text-foreground">{streakDays}</p>
                            <p className="text-xs text-muted-foreground uppercase tracking-wider">Day Streak</p>
                        </div>
                        <div>
                            <p className="text-2xl font-bold text-foreground">{completedModules.length}</p>
                            <p className="text-xs text-muted-foreground uppercase tracking-wider">Missions</p>
                        </div>
                    </div>
                </div>

                {/* Stats & Progress */}
                <div className="flex-1 space-y-6 w-full">
                    <div className="bg-card border border-border p-8 rounded-2xl shadow-sm">
                        <h3 className="font-bold text-lg mb-6 flex items-center gap-2">
                            <Shield className="w-5 h-5 text-primary" /> Security Clearance Progress
                        </h3>

                        <div className="space-y-2 mb-2">
                            <div className="flex justify-between text-sm">
                                <span>Current XP</span>
                                <span className="text-muted-foreground">{xp} / {nextLevelXp} XP</span>
                            </div>
                            <div className="h-4 bg-muted rounded-full overflow-hidden relative">
                                <motion.div
                                    initial={{ width: 0 }}
                                    animate={{ width: `${progress}%` }}
                                    transition={{ duration: 1, ease: 'easeOut' }}
                                    className="h-full bg-gradient-to-r from-blue-500 to-indigo-500"
                                />
                            </div>
                            <p className="text-xs text-muted-foreground text-right">
                                {nextLevelXp - xp} XP needed for Level {level + 1}
                            </p>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div className="bg-card border border-border p-6 rounded-xl flex items-center gap-4">
                            <div className="p-3 bg-amber-500/10 text-amber-500 rounded-lg">
                                <Zap className="w-6 h-6" />
                            </div>
                            <div>
                                <p className="text-lg font-bold">High/Low</p>
                                <p className="text-sm text-muted-foreground">Activity Rate</p>
                            </div>
                        </div>
                        <div className="bg-card border border-border p-6 rounded-xl flex items-center gap-4">
                            <div className="p-3 bg-emerald-500/10 text-emerald-500 rounded-lg">
                                <Calendar className="w-6 h-6" />
                            </div>
                            <div>
                                <p className="text-lg font-bold">Active</p>
                                <p className="text-sm text-muted-foreground">Status</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Badges Showcase */}
            <div className="bg-card border border-border rounded-2xl p-8">
                <h3 className="font-bold text-lg mb-6 flex items-center gap-2">
                    <Award className="w-5 h-5 text-purple-500" /> Service Ribbons & Badges
                </h3>
                <BadgeList />
            </div>

            {/* Certificate Area */}
            <div className="bg-card border border-border rounded-2xl p-8">
                <Certificate />
            </div>
        </div>
    );
};
