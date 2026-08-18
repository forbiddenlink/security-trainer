import React, { useMemo } from "react";
import { Lock, ArrowRight } from "lucide-react";
import { Link } from "react-router-dom";
import { BADGES } from "../data/badges";
import { useGameStore } from "../store/gameStore";
import { Card } from "./ui";

/**
 * Shows the next unearned badge with progress toward unlocking it.
 * Drives anticipation — a key engagement mechanism from HackTheBox/TryHackMe.
 */
export const NextBadgePreview: React.FC = () => {
  const badges = useGameStore((s) => s.badges);
  const completedModules = useGameStore((s) => s.completedModules);
  const level = useGameStore((s) => s.level);
  const ctfProgress = useGameStore((s) => s.ctfProgress);

  const ctfSolvedCount = useMemo(
    () => Object.values(ctfProgress).filter((p) => p.solved).length,
    [ctfProgress],
  );

  const nextBadge = useMemo(() => {
    const priority = [
      {
        id: "badge-completion",
        progress: Math.min(1, completedModules.length),
        total: 1,
        hint: "Complete your first module",
      },
      {
        id: "sql-slayer",
        progress: completedModules.includes("sql-injection") ? 1 : 0,
        total: 1,
        hint: "Complete SQL Injection module",
      },
      {
        id: "xss-terminator",
        progress: completedModules.includes("xss") ? 1 : 0,
        total: 1,
        hint: "Complete XSS module",
      },
      {
        id: "badge-ctf-first",
        progress: Math.min(1, ctfSolvedCount),
        total: 1,
        hint: "Solve your first CTF challenge",
      },
      {
        id: "badge-ctf-hunter",
        progress: Math.min(5, ctfSolvedCount),
        total: 5,
        hint: "Solve 5 CTF challenges",
      },
      {
        id: "master-hacker",
        progress: Math.min(5, level),
        total: 5,
        hint: "Reach Level 5",
      },
      {
        id: "badge-elite",
        progress: 0,
        total: 1,
        hint: "Pass the Final Exam with perfect accuracy",
      },
    ];

    const entry = priority.find(
      (e) => !badges.includes(e.id) && BADGES.some((b) => b.id === e.id),
    );
    if (!entry) return null;
    const badge = BADGES.find((b) => b.id === entry.id);
    return badge ? { badge, ...entry } : null;
  }, [badges, completedModules, level, ctfSolvedCount]);

  // All badges earned
  if (!nextBadge) return null;

  const { badge, progress, total, hint } = nextBadge;
  const pct = total > 0 ? Math.round((progress / total) * 100) : 0;
  const radius = 20;
  const circ = 2 * Math.PI * radius;
  const dash = circ - (pct / 100) * circ;

  return (
    <Card
      className="ui-card-md flex items-center gap-4"
      aria-label="Next badge to unlock"
    >
      {/* Circular progress ring with locked badge icon */}
      <div className="relative shrink-0 w-14 h-14" aria-hidden="true">
        <svg viewBox="0 0 48 48" className="w-14 h-14 -rotate-90">
          <circle
            cx="24"
            cy="24"
            r={radius}
            fill="none"
            stroke="currentColor"
            strokeWidth="3"
            className="text-border/50"
          />
          <circle
            cx="24"
            cy="24"
            r={radius}
            fill="none"
            stroke="currentColor"
            strokeWidth="3"
            strokeLinecap="round"
            strokeDasharray={circ}
            strokeDashoffset={dash}
            className="text-primary transition-[stroke-dashoffset] duration-700"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <Lock className="w-4 h-4 text-muted-foreground" />
        </div>
      </div>

      {/* Badge info */}
      <div className="flex-1 min-w-0">
        <p className="range-readout mb-0.5">NEXT UNLOCK</p>
        <p className="font-semibold text-foreground truncate">{badge.name}</p>
        <p className="text-body-sm text-muted-foreground truncate">{hint}</p>
        {total > 1 && (
          <p className="text-caption text-primary mt-0.5">
            {progress}/{total} · {pct}%
          </p>
        )}
      </div>

      <Link
        to="/profile"
        className="shrink-0 p-2 rounded-[var(--radius-sm)] text-muted-foreground hover:text-foreground hover:bg-muted/50 transition-colors"
        aria-label="View all badges on profile"
      >
        <ArrowRight className="w-4 h-4" />
      </Link>
    </Card>
  );
};
