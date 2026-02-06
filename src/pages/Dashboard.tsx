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
        <div className="space-y-8 max-w-6xl mx-auto animate-in fade-in duration-500" role="main">
            {/* Welcome Banner */}
            <section className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-primary/20 to-purple-500/20 border border-primary/20 p-8" aria-label="Welcome section">
                <div className="relative z-10 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
                    <div>
                        <h2 className="text-4xl font-bold tracking-tight mb-2">
                            Welcome back, Agent.
                        </h2>
                        <p className="text-muted-foreground text-lg">
                            Your security clearance is currently <span className="text-primary font-bold">Level {level}</span>.
                        </p>
                    </div>
                    <Link
                        to="/modules"
                        className="group flex items-center gap-2 bg-primary text-primary-foreground px-6 py-3 rounded-lg font-bold shadow-lg shadow-primary/25 hover:bg-primary/90 hover:scale-105 transition-all"
                        aria-label="Resume training modules"
                    >
                        Resume Training
                        <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" aria-hidden="true" />
                    </Link>
                </div>

                {/* Decorative background element */}
                <div className="absolute top-0 right-0 -mt-16 -mr-16 w-64 h-64 bg-primary/20 blur-3xl rounded-full pointer-events-none" aria-hidden="true" />
            </section>

            {/* Stats Grid */}
            <section className="grid grid-cols-1 md:grid-cols-3 gap-6" aria-label="Statistics">
                <div className="bg-card border border-border rounded-xl p-6 shadow-sm hover:border-primary/50 transition-colors">
                    <div className="flex items-center gap-4 mb-4">
                        <div className="p-3 bg-blue-500/10 text-blue-500 rounded-lg" aria-hidden="true">
                            <Activity className="w-6 h-6" />
                        </div>
                        <div>
                            <p className="text-sm text-muted-foreground font-medium" id="score-label">Current Score</p>
                            <h3 className="text-2xl font-bold" aria-labelledby="score-label">{xp} XP</h3>
                        </div>
                    </div>

                    <div
                        className="w-full h-2 bg-muted rounded-full overflow-hidden"
                        role="progressbar"
                        aria-valuenow={xp}
                        aria-valuemin={0}
                        aria-valuemax={nextLevelXp}
                        aria-label={`XP progress: ${xp} of ${nextLevelXp}`}
                    >
                        <div className="h-full bg-blue-500" style={{ width: `${progress}%` }} />
                    </div>
                    <p className="text-xs text-muted-foreground mt-2 text-right">{nextLevelXp - xp} XP to next level</p>
                </div>

                <div className="bg-card border border-border rounded-xl p-6 shadow-sm hover:border-emerald-500/50 transition-colors">
                    <div className="flex items-center gap-4">
                        <div className="p-3 bg-emerald-500/10 text-emerald-500 rounded-lg" aria-hidden="true">
                            <CheckCircle className="w-6 h-6" />
                        </div>
                        <div>
                            <p className="text-sm text-muted-foreground font-medium" id="modules-label">Modules Completed</p>
                            <h3 className="text-2xl font-bold" aria-labelledby="modules-label">{completedModules.length}</h3>
                        </div>
                    </div>
                </div>

                <div className="bg-card border border-border rounded-xl p-6 shadow-sm hover:border-purple-500/50 transition-colors">
                    <div className="flex items-center gap-4">
                        <div className="p-3 bg-purple-500/10 text-purple-500 rounded-lg" aria-hidden="true">
                            <BookOpen className="w-6 h-6" />
                        </div>
                        <div>
                            <p className="text-sm text-muted-foreground font-medium" id="mission-label">Active Mission</p>
                            <h3 className="text-lg font-bold truncate" aria-labelledby="mission-label">{currentModule?.title || 'No Active Mission'}</h3>
                        </div>
                    </div>
                </div>
            </section>

            {/* Badges Section */}
            <section aria-labelledby="achievements-heading">
                <div className="flex items-center justify-between mb-6">
                    <h2 id="achievements-heading" className="text-2xl font-bold">Achievements</h2>
                    <Link to="/profile" className="text-sm text-primary hover:underline" aria-label="View all achievements on profile page">View All</Link>
                </div>
                <BadgeList />
            </section>
        </div>
    );
};
