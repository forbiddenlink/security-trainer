import type { Badge } from '../types';

export const BADGES: Badge[] = [
    {
        id: 'recruit',
        name: 'Recruit',
        description: 'Joined the agency',
        icon: 'Award',
        condition: 'Start your first session'
    },
    {
        id: 'sql-slayer',
        name: 'SQL Slayer',
        description: 'Defeated the SQL Injection beast',
        icon: 'Database',
        condition: 'Complete SQL Injection Module'
    },
    {
        id: 'xss-terminator',
        name: 'XSS Terminator',
        description: 'Cleaned up the scripts',
        icon: 'Code',
        condition: 'Complete XSS Module'
    },
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
    {
        id: 'master-hacker',
        name: 'Master Operator',
        description: 'Reached Level 5',
        icon: 'Crown',
        condition: 'Reach Level 5'
    },
    // CTF Badges
    {
        id: 'badge-ctf-first',
        name: 'Flag Hunter',
        description: 'Captured your first CTF flag',
        icon: 'Flag',
        condition: 'Solve 1 CTF challenge'
    },
    {
        id: 'badge-ctf-hunter',
        name: 'Flag Collector',
        description: 'A seasoned CTF competitor',
        icon: 'Target',
        condition: 'Solve 5 CTF challenges'
    },
    {
        id: 'badge-ctf-500',
        name: 'CTF Champion',
        description: 'Earned 500+ CTF points',
        icon: 'Trophy',
        condition: 'Earn 500 CTF points'
    },
];

// Helper to get badge by ID
export function getBadgeById(id: string): Badge | undefined {
    return BADGES.find(badge => badge.id === id);
}

// Helper to check if badge ID is valid
export function isValidBadgeId(id: string): boolean {
    return BADGES.some(badge => badge.id === id);
}
