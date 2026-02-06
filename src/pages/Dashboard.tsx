import React, { useMemo } from 'react';
import { useGameStore } from '../store/gameStore';
import { BadgeList } from '../components/BadgeList';
import { MODULES } from '../data/modules';
import { ArrowRight, Activity, BookOpen, CheckCircle } from 'lucide-react';
import { Link } from 'react-router-dom';

export const Dashboard: React.FC = () => {
    const { xp, level, completedModules, currentModuleId } = useGameStore();
    const currentModule = useMemo(
        () => MODULES.find(m => m.id === currentModuleId),
        [currentModuleId]
    );
    const nextLevelXp = level * 1000;
    const progress = Math.min((xp / nextLevelXp) * 100, 100);

    return (
        <div className="space-y-8 max-w-6xl mx-auto animate-in fade-in duration-500">
            {/* Welcome Banner */}
            <section className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-primary/20 to-purple-500/20 border border-primary/20 p-8">
                <div className="relative z-10 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
                    <div>
                        <h1 className="text-4xl font-bold tracking-tight mb-2">
                            Welcome back, Agent.
                        </h1>
                        <p className="text-muted-foreground text-lg">
                            Your security clearance is currently <span className="text-primary font-bold">Level {level}</span>.
                        </p>
                    </div>
                    <Link
                        to="/modules"
                        className="group flex items-center gap-2 bg-primary text-primary-foreground px-6 py-3 rounded-lg font-bold shadow-lg shadow-primary/25 hover:bg-primary/90 hover:scale-105 transition-all"
                    >
                        Resume Training
                        <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
                    </Link>
                </div>

                {/* Decorative background element */}
                <div className="absolute top-0 right-0 -mt-16 -mr-16 w-64 h-64 bg-primary/20 blur-3xl rounded-full pointer-events-none" />
            </section>

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <div className="bg-card border border-border rounded-xl p-6 shadow-sm hover:border-primary/50 transition-colors">
                    <div className="flex items-center gap-4 mb-4">
                        <div className="p-3 bg-blue-500/10 text-blue-500 rounded-lg">
                            <Activity className="w-6 h-6" />
                        </div>
                        <div>
                            <p className="text-sm text-muted-foreground font-medium">Current Score</p>
                            <h3 className="text-2xl font-bold">{xp} XP</h3>
                        </div>
                    </div>

                    <div className="w-full h-2 bg-muted rounded-full overflow-hidden">
                        <div className="h-full bg-blue-500" style={{ width: `${progress}%` }} />
                    </div>
                    <p className="text-xs text-muted-foreground mt-2 text-right">{nextLevelXp - xp} XP to next level</p>
                </div>

                <div className="bg-card border border-border rounded-xl p-6 shadow-sm hover:border-emerald-500/50 transition-colors">
                    <div className="flex items-center gap-4">
                        <div className="p-3 bg-emerald-500/10 text-emerald-500 rounded-lg">
                            <CheckCircle className="w-6 h-6" />
                        </div>
                        <div>
                            <p className="text-sm text-muted-foreground font-medium">Modules Completed</p>
                            <h3 className="text-2xl font-bold">{completedModules.length}</h3>
                        </div>
                    </div>
                </div>

                <div className="bg-card border border-border rounded-xl p-6 shadow-sm hover:border-purple-500/50 transition-colors">
                    <div className="flex items-center gap-4">
                        <div className="p-3 bg-purple-500/10 text-purple-500 rounded-lg">
                            <BookOpen className="w-6 h-6" />
                        </div>
                        <div>
                            <p className="text-sm text-muted-foreground font-medium">Active Mission</p>
                            <h3 className="text-lg font-bold truncate">{currentModule?.title || 'No Active Mission'}</h3>
                        </div>
                    </div>
                </div>
            </div>

            {/* Badges Section */}
            <section>
                <div className="flex items-center justify-between mb-6">
                    <h2 className="text-2xl font-bold">Achievements</h2>
                    <Link to="/profile" className="text-sm text-primary hover:underline">View All</Link>
                </div>
                <BadgeList />
            </section>
        </div>
    );
};
