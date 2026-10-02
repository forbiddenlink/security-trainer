import React from "react";
import { useGameStore } from "../store/gameStore";
import { getWeeklyProgress, WEEKLY_TIERS } from "../lib/weeklyGoal";

/** Rolling 7-day XP against three goal tiers, compared with last week. */
export const WeeklyGoal: React.FC = () => {
  const xpByDay = useGameStore((s) => s.xpByDay);
  const { thisWeek, lastWeek, reached, next } = getWeeklyProgress(
    xpByDay ?? {},
  );
  const top = WEEKLY_TIERS[WEEKLY_TIERS.length - 1].xp;
  const pct = Math.min(100, (thisWeek / top) * 100);
  const delta = thisWeek - lastWeek;

  return (
    <div className="ui-card ui-card-md">
      <div className="flex flex-wrap items-baseline justify-between gap-x-6 gap-y-1">
        <div>
          <p className="ui-label">Weekly goal · last 7 days</p>
          <p className="mt-2 text-h3 tabular-nums">
            {thisWeek.toLocaleString()} XP
            {reached && (
              <span className="ml-3 font-mono text-caption uppercase tracking-[0.12em] text-muted-foreground">
                {reached.name}
              </span>
            )}
          </p>
        </div>
        <p className="font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground tabular-nums">
          {next
            ? `${(next.xp - thisWeek).toLocaleString()} XP to ${next.name}`
            : "Top tier cleared"}
          {lastWeek > 0 && (
            <>
              {" · "}
              {delta >= 0 ? "+" : "−"}
              {Math.abs(delta).toLocaleString()} vs prior week
            </>
          )}
        </p>
      </div>
      {/* biome-ignore lint/a11y/useSemanticElements: native <meter> cannot carry the tier tick marks */}
      <div
        className="relative mt-5 h-2 bg-muted"
        role="meter"
        aria-label="Weekly XP"
        aria-valuemin={0}
        aria-valuemax={top}
        aria-valuenow={Math.min(thisWeek, top)}
        aria-valuetext={`${thisWeek} XP this week${reached ? `, ${reached.name} tier` : ""}`}
      >
        <div className="h-full bg-primary" style={{ width: `${pct}%` }} />
        {WEEKLY_TIERS.slice(0, -1).map((t) => (
          <span
            key={t.name}
            className="absolute top-[-3px] h-[14px] w-px bg-foreground/60"
            style={{ left: `${(t.xp / top) * 100}%` }}
            aria-hidden="true"
          />
        ))}
      </div>
      <ol className="relative mt-2 h-4 font-mono text-[10px] uppercase tracking-[0.1em] text-muted-foreground tabular-nums">
        {WEEKLY_TIERS.map((t, i) => {
          const last = i === WEEKLY_TIERS.length - 1;
          return (
            <li
              key={t.name}
              className={`absolute top-0 whitespace-nowrap ${last ? "right-0" : "-translate-x-1/2"} ${thisWeek >= t.xp ? "text-foreground" : ""}`}
              style={last ? undefined : { left: `${(t.xp / top) * 100}%` }}
            >
              <span className="hidden sm:inline">{t.name} </span>
              {t.xp}
            </li>
          );
        })}
      </ol>
    </div>
  );
};
