import React, { memo } from "react";
import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  BookOpen,
  User,
  ShieldAlert,
  Trophy,
  ShieldCheck,
  GraduationCap,
  Flag,
  RefreshCw,
} from "lucide-react";
import { clsx } from "clsx";
import { useGameStore } from "../store/gameStore";
import { Progress } from "./ui";

const NAV_ITEMS = [
  { label: "Dashboard", path: "/", icon: LayoutDashboard },
  { label: "Modules", path: "/modules", icon: BookOpen },
  { label: "Paths", path: "/paths", icon: GraduationCap },
  { label: "CTF Challenges", path: "/ctf", icon: Flag },
  { label: "Intel Review", path: "/reviews", icon: RefreshCw },
  { label: "Leaderboard", path: "/leaderboard", icon: Trophy },
  { label: "Profile", path: "/profile", icon: User },
  { label: "Final Exam", path: "/challenge", icon: ShieldAlert },
] as const;

interface SidebarProps {
  onNavigate?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = memo(({ onNavigate }) => {
  const { xp, level } = useGameStore();
  const nextLevelXp = level * 1000;
  const clearancePct = Math.min(100, Math.round((xp / nextLevelXp) * 100));

  return (
    <aside
      className="w-64 min-h-screen flex flex-col border-r border-border/70 bg-card/90 backdrop-blur relative z-10"
      aria-label="Main navigation"
    >
      <div className="px-5 py-5 flex items-center gap-3 border-b border-border/70">
        <div className="h-9 w-9 rounded-[var(--radius-sm)] bg-primary/12 border border-primary/25 flex items-center justify-center">
          <ShieldCheck className="w-5 h-5 text-primary" aria-hidden="true" />
        </div>
        <span className="font-semibold text-xl tracking-tight text-foreground flex flex-col leading-none">
          <span>SecTrainer</span>
          <span className="text-caption text-muted-foreground">v1.0.0</span>
        </span>
      </div>

      <nav className="flex-1 px-3 py-4 space-y-1.5" aria-label="Primary">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            onClick={onNavigate}
            className={({ isActive }) =>
              clsx(
                "group relative flex h-10 items-center gap-3 rounded-[var(--radius-sm)] px-3.5 text-body-sm font-medium transition-colors",
                isActive
                  ? "bg-primary/8 text-primary"
                  : "text-muted-foreground hover:bg-muted/40 hover:text-foreground",
              )
            }
          >
            {({ isActive }) => (
              <>
                <item.icon className="w-4 h-4" aria-hidden="true" />
                <span>{item.label}</span>
                {isActive && <span className="sr-only">(current page)</span>}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      <div className="m-3 mt-0 ui-card" aria-label="System information">
        <div className="flex justify-between items-center mb-2.5">
          <span className="ui-label">Status</span>
          <span
            className="flex h-2 w-2 rounded-full bg-accent"
            aria-label="Online"
          />
        </div>
        <p className="text-mono text-muted-foreground tracking-tight">
          Clearance:{" "}
          <span className="text-primary font-semibold">Level {level}</span>
        </p>
        <Progress
          className="mt-2.5"
          value={xp}
          min={0}
          max={nextLevelXp}
          aria-label={`${clearancePct}% to next clearance level`}
          indicatorClassName="bg-primary"
        />
        <p className="text-caption text-muted-foreground mt-1.5 normal-case tracking-normal">
          {xp} / {nextLevelXp} XP
        </p>
      </div>
    </aside>
  );
});

Sidebar.displayName = "Sidebar";
