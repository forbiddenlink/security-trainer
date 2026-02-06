import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, BookOpen, User, ShieldAlert, ShieldCheck, Trophy } from 'lucide-react';
import { clsx } from 'clsx';

export const Sidebar: React.FC = () => {
    const navItems = [
        { label: 'Dashboard', path: '/', icon: LayoutDashboard },
        { label: 'Modules', path: '/modules', icon: BookOpen },
        { label: 'Leaderboard', path: '/leaderboard', icon: Trophy },
        { label: 'Profile', path: '/profile', icon: User },
        { label: 'Final Exam', path: '/challenge', icon: ShieldAlert },
    ];

    return (
        <aside className="w-64 bg-card border-r border-border min-h-screen flex flex-col" aria-label="Main navigation">
            <div className="p-6 flex items-center gap-2 border-b border-border">
                <ShieldCheck className="w-8 h-8 text-primary" aria-hidden="true" />
                <span className="font-bold text-xl tracking-tight text-foreground">
                    SecTrainer
                </span>
            </div>

            <nav className="flex-1 p-4 space-y-2" aria-label="Primary">
                {navItems.map((item) => (
                    <NavLink
                        key={item.path}
                        to={item.path}
                        className={({ isActive }) =>
                            clsx(
                                'flex items-center gap-3 px-4 py-3 rounded-lg transition-colors duration-200',
                                isActive
                                    ? 'bg-primary/10 text-primary border-r-2 border-primary'
                                    : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                            )
                        }
                    >
                        {({ isActive }) => (
                            <>
                                <item.icon className="w-5 h-5" aria-hidden="true" />
                                <span className="font-medium">{item.label}</span>
                                {isActive && <span className="sr-only">(current page)</span>}
                            </>
                        )}
                    </NavLink>
                ))}
            </nav>

            <div className="p-4 m-4 bg-muted/30 rounded-lg text-xs text-muted-foreground border border-border" aria-label="System information">
                <p>Security Clearance: <span className="text-primary font-bold">Classified</span></p>
                <p className="mt-1">System v1.0.0</p>
            </div>
        </aside>
    );
};
