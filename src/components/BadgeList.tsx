import React from 'react';
import { useGameStore } from '../store/gameStore';
import { Award, Lock } from 'lucide-react';
import { clsx } from 'clsx';
import type { Badge } from '../types';

// Mock data for badges - in a real app this might come from a central config
const ALL_BADGES: Badge[] = [
    { id: 'recruit', name: 'Recruit', description: 'Joined the agency', icon: 'Award', condition: 'Start your first session' },
    { id: 'sql-slayer', name: 'SQL Slayer', description: 'Defeated the SQL Injection beast', icon: 'Database', condition: 'Complete SQL Injection Module' },
    { id: 'xss-terminator', name: 'XSS Terminator', description: 'Cleaned up the scripts', icon: 'Code', condition: 'Complete XSS Module' },
    {
        id: 'badge-completion',
        name: 'Mission Complete',
        description: 'Finished your first training module.',
        icon: 'Flag',
        condition: 'Complete 1 module'
    },
    {
        id: 'badge-elite',
        name: 'Elite Hacker',
        description: 'Passed the Final Exam with 100% accuracy.',
        icon: 'Skull',
        condition: 'Perfect score in Challenge Mode'
    },
    { id: 'master-hacker', name: 'Master Operator', description: 'Reached Level 5', icon: 'Crown', condition: 'Reach Level 5' },
];

export const BadgeList: React.FC = () => {
    const { badges } = useGameStore();

    return (
        <ul className="grid grid-cols-2 md:grid-cols-4 gap-4" role="list" aria-label="Achievement badges">
            {ALL_BADGES.map((badge) => {
                const isUnlocked = badges.includes(badge.id);
                return (
                    <li
                        key={badge.id}
                        className={clsx(
                            "relative group p-4 rounded-xl border transition-all duration-300",
                            isUnlocked
                                ? "bg-primary/10 border-primary/50 shadow-[0_0_15px_-3px_rgba(59,130,246,0.3)]"
                                : "bg-muted/20 border-border opacity-60"
                        )}
                        aria-label={`${badge.name}: ${isUnlocked ? 'Unlocked' : 'Locked'} - ${badge.description}`}
                    >
                        <div className="flex flex-col items-center text-center gap-3">
                            <div
                                className={clsx(
                                    "p-3 rounded-full lg:mb-2 transition-transform group-hover:scale-110",
                                    isUnlocked ? "bg-primary/20 text-primary" : "bg-muted text-muted-foreground"
                                )}
                                aria-hidden="true"
                            >
                                {isUnlocked ? <Award className="w-8 h-8" /> : <Lock className="w-8 h-8" />}
                            </div>
                            <div>
                                <h3 className="font-bold text-sm tracking-wide mb-1">{badge.name}</h3>
                                <p className="text-xs text-muted-foreground">{badge.description}</p>
                                <span className="sr-only">{isUnlocked ? 'Unlocked' : `Locked - ${badge.condition}`}</span>
                            </div>
                        </div>
                    </li>
                );
            })}
        </ul>
    )
}
