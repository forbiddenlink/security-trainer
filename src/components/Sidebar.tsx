import React, { memo } from "react";
import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  BookOpen,
  User,
  ShieldAlert,
  Trophy,
  GraduationCap,
  Flag,
  RefreshCw,
} from "lucide-react";
import { clsx } from "clsx";
import { useGameStore } from "../store/gameStore";
import { Progress } from "./ui";
import { RangeMark } from "./RangeMark";

const NAV_GROUPS = [
  {
    label: "Learn",
    items: [
      { label: "Dashboard", path: "/", icon: LayoutDashboard },
      { label: "Modules", path: "/modules", icon: BookOpen },
      { label: "Paths", path: "/paths", icon: GraduationCap },
    ],
  },
  {
    label: "Practice",
    items: [
      { label: "CTF Challenges", path: "/ctf", icon: Flag },
      { label: "Intel Review", path: "/reviews", icon: RefreshCw },
      { label: "Final Exam", path: "/challenge", icon: ShieldAlert },
    ],
  },
  {
    label: "Record",
    items: [
      { label: "Leaderboard", path: "/leaderboard", icon: Trophy },
      { label: "Profile", path: "/profile", icon: User },
    ],
  },
] as const;

interface SidebarProps {
  onNavigate?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = memo(({ onNavigate }) => {
  const xp = useGameStore((s) => s.xp);
  const level = useGameStore((s) => s.level);
  const nextLevelXp = level * 1000;
  const clearancePct = Math.min(100, Math.round((xp / nextLevelXp) * 100));
  let index = 0;

  return (
    <aside
      className="w-64 h-dvh lg:h-screen lg:sticky lg:top-0 flex flex-col border-r border-border bg-background relative z-10"
      aria-label="Main navigation"
    >
      <NavLink
        to="/"
        onClick={onNavigate}
        className="h-16 px-5 flex items-center gap-3 border-b border-border shrink-0"
        aria-label="SecTrainer home"
      >
        <RangeMark className="w-7 h-7 text-foreground" />
        <span className="flex flex-col leading-none">
          <span className="font-display text-[1.35rem] font-extrabold tracking-[-0.02em] [font-stretch:75%]">
            SecTrainer
          </span>
          <span className="ui-label mt-1 !tracking-[0.18em]">Signal range</span>
        </span>
      </NavLink>

      <nav
        className="flex-1 overflow-y-auto px-3 py-5 space-y-6"
        aria-label="Primary"
      >
        {NAV_GROUPS.map((group) => (
          <div key={group.label}>
            <p className="ui-label px-2 mb-2">{group.label}</p>
            <ul className="space-y-0.5">
              {group.items.map((item) => {
                index += 1;
                const num = String(index).padStart(2, "0");
                return (
                  <li key={item.path}>
                    <NavLink
                      to={item.path}
                      end={item.path === "/"}
                      onClick={onNavigate}
                      className={({ isActive }) =>
                        clsx(
                          "group relative flex h-10 items-center gap-3 rounded-[var(--radius-sm)] px-2.5 text-body-sm font-medium",
                          isActive
                            ? "bg-muted text-foreground"
                            : "text-muted-foreground hover:text-foreground hover:bg-muted/60",
                        )
                      }
                    >
                      {({ isActive }) => (
                        <>
                          <span
                            className={clsx(
                              "absolute left-0 top-2 bottom-2 w-[3px] rounded-r-sm",
                              isActive ? "bg-primary" : "bg-transparent",
                            )}
                            aria-hidden="true"
                          />
                          <item.icon
                            className="w-4 h-4 shrink-0"
                            aria-hidden="true"
                          />
                          <span className="flex-1 truncate">{item.label}</span>
                          <span
                            className={clsx(
                              "font-mono text-[10px] tabular-nums",
                              isActive
                                ? "text-foreground"
                                : "text-muted-foreground/70",
                            )}
                            aria-hidden="true"
                          >
                            {num}
                          </span>
                          {isActive && (
                            <span className="sr-only">(current page)</span>
                          )}
                        </>
                      )}
                    </NavLink>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      <div
        className="border-t border-border px-5 py-4 shrink-0"
        aria-label="Clearance status"
      >
        <div className="flex items-baseline justify-between">
          <span className="ui-label">Clearance</span>
          <span className="font-mono text-caption tabular-nums text-muted-foreground">
            {clearancePct}%
          </span>
        </div>
        <p className="mt-1 font-display text-h3 font-extrabold [font-stretch:75%] leading-none">
          Level {level}
        </p>
        <Progress
          className="mt-3"
          value={xp}
          min={0}
          max={nextLevelXp}
          aria-label={`${clearancePct}% to next clearance level`}
        />
        <p className="mt-2 font-mono text-[11px] tabular-nums text-muted-foreground">
          {xp.toLocaleString()} / {nextLevelXp.toLocaleString()} XP
        </p>
      </div>
    </aside>
  );
});

Sidebar.displayName = "Sidebar";
