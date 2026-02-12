import React from 'react';
import { NavLink } from 'react-router-dom';
import { LayoutDashboard, BookOpen, User, ShieldAlert, Trophy, ShieldCheck } from 'lucide-react';
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
        <aside className="w-64 bg-card border-r border-border min-h-screen flex flex-col shadow-2xl relative z-10" aria-label="Main navigation">
            <div className="p-6 flex items-center gap-3 border-b border-border/50 bg-muted/20">
                <div className="relative">
                    <div className="absolute inset-0 bg-primary/20 blur-lg rounded-full animate-pulse" />
                    <ShieldCheck className="w-8 h-8 text-primary relative z-10" aria-hidden="true" />
                </div>
                <span className="font-bold text-xl tracking-tight text-foreground flex flex-col leading-none">
                    <span>SecTrainer</span>
                    <span className="text-[10px] text-primary uppercase tracking-widest opacity-80">v1.0.0</span>
                </span>
            </div>

            <nav className="flex-1 p-4 space-y-2" aria-label="Primary">
                {navItems.map((item) => (
                    <NavLink
                        key={item.path}
                        to={item.path}
                        className={({ isActive }) =>
                            clsx(
                                'flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-300 relative overflow-hidden group',
                                isActive
                                    ? 'bg-primary/10 text-primary shadow-[0_0_15px_rgba(0,255,157,0.1)] border-r-2 border-primary'
                                    : 'text-muted-foreground hover:bg-muted/50 hover:text-foreground hover:pl-5'
                            )
                        }
                    >
                        {({ isActive }) => (
                            <>
                                {isActive && (
                                    <div className="absolute inset-0 bg-linear-to-r from-primary/5 to-transparent opacity-50" />
                                )}
                                <item.icon className={clsx("w-5 h-5 transition-transform duration-300", isActive ? "scale-110" : "group-hover:scale-110")} aria-hidden="true" />
                                <span className="font-medium relative z-10">{item.label}</span>
                                {isActive && <span className="sr-only">(current page)</span>}
                            </>
                        )}
                    </NavLink>
                ))}
            </nav>

            <div className="p-4 m-4 bg-black/40 rounded-lg text-xs border border-primary/20 relative overflow-hidden group" aria-label="System information">
                 {/* Scanline effect for this box */}
                <div className="absolute inset-0 opacity-10 pointer-events-none bg-[linear-gradient(transparent_50%,rgba(0,0,0,0.5)_50%)] bg-size-[100%_4px]" />
                
                <div className="flex justify-between items-center mb-2">
                    <span className="text-muted-foreground">Status</span>
                    <span className="flex h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
                </div>
                <p className="font-mono text-muted-foreground">Clearance: <span className="text-primary font-bold shadow-cyan-500/50">Classified</span></p>
                <div className="mt-2 h-1 bg-muted rounded-full overflow-hidden">
                    <div className="h-full bg-primary w-[75%] animate-[pulse_2s_infinite]" />
                </div>
            </div>
        </aside>
    );
};
