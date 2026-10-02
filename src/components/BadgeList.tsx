import React, { memo, useMemo } from "react";
import { useGameStore } from "../store/gameStore";
import { BADGES } from "../data/badges";
import { Award, Lock } from "lucide-react";
import { clsx } from "clsx";

/**
 * Badge display grid - memoized to prevent unnecessary re-renders
 * Uses Zustand selector to only re-render when badges array changes
 */
export const BadgeList: React.FC = memo(() => {
  // Use selector to only subscribe to badges changes
  const badges = useGameStore((state) => state.badges);

  // Memoize badge unlock status calculations
  const badgeStatuses = useMemo(
    () =>
      BADGES.map((badge) => ({
        ...badge,
        isUnlocked: badges.includes(badge.id),
      })),
    [badges],
  );

  return (
    <ul
      className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-2"
      role="list"
      aria-label="Achievement badges"
    >
      {badgeStatuses.map((badge) => {
        const isUnlocked = badge.isUnlocked;
        return (
          <li
            key={badge.id}
            className={clsx(
              "flex items-center gap-3 p-3 rounded-[var(--radius-md)] border",
              isUnlocked
                ? "bg-primary/10 border-primary/50"
                : "border-border opacity-65",
            )}
            aria-label={`${badge.name}: ${isUnlocked ? "Unlocked" : "Locked"} - ${badge.description}`}
          >
            <div
              className={clsx(
                "grid h-10 w-10 shrink-0 place-items-center rounded-[var(--radius-sm)]",
                isUnlocked
                  ? "bg-signal text-signal-ink"
                  : "border border-dashed border-border text-muted-foreground",
              )}
              aria-hidden="true"
            >
              {isUnlocked ? (
                <Award className="w-5 h-5" />
              ) : (
                <Lock className="w-4 h-4" />
              )}
            </div>
            <div className="min-w-0">
              <h3 className="font-body text-body-sm font-semibold leading-tight [font-stretch:100%] tracking-normal">
                {badge.name}
              </h3>
              <p className="text-[13px] leading-snug text-muted-foreground">
                {badge.description}
              </p>
              <span className="sr-only">
                {isUnlocked ? "Unlocked" : `Locked - ${badge.condition}`}
              </span>
            </div>
          </li>
        );
      })}
    </ul>
  );
});

BadgeList.displayName = "BadgeList";
