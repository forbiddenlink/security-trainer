import React from "react";
import { Flame } from "lucide-react";
import { useGameStore } from "../store/gameStore";

export const StreakIndicator: React.FC = () => {
  const streakDays = useGameStore((s) => s.streakDays);
  const getStreakMultiplier = useGameStore((s) => s.getStreakMultiplier);
  const bonusPercent = Math.round((getStreakMultiplier() - 1) * 100);

  // Only show if streak is active (at least 1 day)
  if (streakDays < 1) {
    return null;
  }

  return (
    <div
      className="hidden md:flex items-center gap-2 px-3 h-10 rounded-[var(--radius-sm)] border border-border font-mono text-caption tabular-nums"
      title={`${streakDays}-day streak, +${bonusPercent}% XP bonus`}
    >
      <Flame className="w-4 h-4 text-warning" aria-hidden="true" />
      <span className="font-semibold text-foreground" aria-hidden="true">
        {streakDays}d
      </span>
      {bonusPercent > 0 && (
        <span className="text-muted-foreground" aria-hidden="true">
          +{bonusPercent}%
        </span>
      )}
      <span className="sr-only">
        {streakDays}-day streak with {bonusPercent}% XP bonus
      </span>
    </div>
  );
};
