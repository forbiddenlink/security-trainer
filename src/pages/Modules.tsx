import React from 'react';
import { MODULES } from '../data/modules';
import { Link } from 'react-router-dom';
import { Shield, Lock, CheckCircle } from 'lucide-react';
import { useGameStore } from '../store/gameStore';
import { clsx } from 'clsx';

export const Modules: React.FC = () => {
    const { completedModules } = useGameStore();

    return (
        <div className="space-y-6 max-w-5xl mx-auto animate-in fade-in duration-500">
            <div className="flex flex-col gap-2">
                <h1 className="text-3xl font-bold">Training Modules</h1>
                <p className="text-muted-foreground">Select a mission to upgrade your security clearance.</p>
            </div>

            <div className="grid gap-6">
                {MODULES.map((module) => {
                    const isCompleted = completedModules.includes(module.id);
                    const isLocked = module.locked; // Logic could be expanded based on level

                    return (
                        <div
                            key={module.id}
                            className={clsx(
                                "group relative overflow-hidden rounded-xl border p-6 transition-all hover:shadow-lg",
                                isLocked ? "bg-muted/10 border-border opacity-70" : "bg-card border-border hover:border-primary/50"
                            )}
                        >
                            <div className="flex flex-col md:flex-row gap-6 justify-between items-start md:items-center relative z-10">
                                <div className="flex gap-4">
                                    <div className={clsx(
                                        "p-4 rounded-xl",
                                        isCompleted ? "bg-emerald-500/10 text-emerald-500" : "bg-blue-500/10 text-blue-500"
                                    )}>
                                        <Shield className="w-8 h-8" />
                                    </div>
                                    <div>
                                        <div className="flex items-center gap-3 mb-1">
                                            <h3 className="text-xl font-bold">{module.title}</h3>
                                            {isCompleted && (
                                                <span className="flex items-center gap-1 text-xs font-bold text-emerald-500 bg-emerald-500/10 px-2 py-0.5 rounded-full">
                                                    <CheckCircle className="w-3 h-3" /> Completed
                                                </span>
                                            )}
                                            <span className={clsx(
                                                "text-xs px-2 py-0.5 rounded-full border",
                                                module.difficulty === 'Beginner' ? "border-green-500/30 text-green-500" :
                                                    module.difficulty === 'Intermediate' ? "border-yellow-500/30 text-yellow-500" :
                                                        "border-red-500/30 text-red-500"
                                            )}>
                                                {module.difficulty}
                                            </span>
                                        </div>
                                        <p className="text-muted-foreground max-w-xl">{module.description}</p>
                                    </div>
                                </div>

                                <div className="flex items-center gap-6">
                                    <div className="text-right hidden md:block">
                                        <p className="text-xs text-muted-foreground uppercase tracking-wider font-bold">Reward</p>
                                        <p className="font-mono text-primary font-bold">{module.xpReward} XP</p>
                                    </div>

                                    {isLocked ? (
                                        <button disabled className="flex items-center gap-2 px-6 py-3 rounded-lg bg-muted text-muted-foreground font-bold cursor-not-allowed">
                                            <Lock className="w-4 h-4" /> Locked
                                        </button>
                                    ) : (
                                        <Link
                                            to={`/modules/${module.id}`}
                                            className={clsx(
                                                "flex items-center gap-2 px-6 py-3 rounded-lg font-bold transition-all",
                                                isCompleted
                                                    ? "bg-muted hover:bg-muted/80 text-foreground"
                                                    : "bg-primary text-primary-foreground hover:bg-primary/90 shadow-lg shadow-primary/20"
                                            )}
                                        >
                                            {isCompleted ? 'Review' : 'Start Mission'}
                                        </Link>
                                    )}
                                </div>
                            </div>
                        </div>
                    );
                })}
            </div>
        </div>
    );
};
