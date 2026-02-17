import React, { useMemo } from "react";
import { cn } from "../lib/cn";
import { useGameStore } from "../store/gameStore";
import { BadgeList } from "../components/BadgeList";
import { DailyChallenge } from "../components/DailyChallenge";
import { MODULES } from "../data/modules";
import { Card, Progress } from "../components/ui";
import {
  ArrowRight,
  Activity,
  BookOpen,
  CheckCircle,
  Flame,
} from "lucide-react";
import { Link } from "react-router-dom";

export const Dashboard: React.FC = () => {
  const {
    xp,
    level,
    completedModules,
    currentModuleId,
    streakDays,
    getStreakMultiplier,
  } = useGameStore();
  const currentModule = useMemo(
    () => MODULES.find((m) => m.id === currentModuleId),
    [currentModuleId],
  );
  const nextLevelXp = level * 1000;
  const streakMultiplier = getStreakMultiplier();
  const bonusPercent = Math.round((streakMultiplier - 1) * 100);

  return (
    <div
      className="space-y-10 max-w-6xl mx-auto animate-in fade-in duration-500"
      role="main"
    >
      <section
        className="ui-card ui-card-elevated relative overflow-hidden p-6 md:p-8"
        aria-label="Welcome section"
      >
        <div className="absolute inset-0 pointer-events-none bg-linear-to-r from-primary/6 via-transparent to-accent/6" />
        <div className="relative z-10 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
          <div>
            <p className="ui-chip mb-3">Mission Status</p>
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight mb-2">
              Welcome back, Agent.
            </h2>
            <p className="text-muted-foreground text-base md:text-lg">
              Current Clearance Level:{" "}
              <span className="text-primary font-semibold">Level {level}</span>.
            </p>
          </div>
          <Link
            to="/modules"
            className={cn(
              "group inline-flex h-10 items-center justify-center gap-2 rounded-[var(--radius-sm)] bg-primary px-5 font-semibold text-primary-foreground transition-colors hover:bg-primary/90",
              "shadow-[var(--shadow-2)]",
            )}
            aria-label="Resume training modules"
          >
            Resume Training
            <ArrowRight
              className="w-4 h-4 group-hover:translate-x-0.5 transition-transform"
              aria-hidden="true"
            />
          </Link>
        </div>
      </section>

      <section
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6"
        aria-label="Statistics"
      >
        <Card className="p-6 hover:border-primary/45">
          <div className="flex items-center gap-4 mb-4">
            <div
              className="h-10 w-10 grid place-items-center rounded-[var(--radius-sm)] bg-primary/10 text-primary"
              aria-hidden="true"
            >
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <p
                className="text-xs uppercase tracking-[0.08em] text-muted-foreground font-semibold"
                id="score-label"
              >
                Current Score
              </p>
              <h3
                className="text-[1.75rem] leading-[1.1] font-semibold tracking-tight"
                aria-labelledby="score-label"
              >
                {xp} XP
              </h3>
            </div>
          </div>

          <Progress
            value={xp}
            min={0}
            max={nextLevelXp}
            aria-label={`XP progress: ${xp} of ${nextLevelXp}`}
            indicatorClassName="bg-primary"
          />
          <p className="text-xs text-muted-foreground mt-2">
            {nextLevelXp - xp} XP to next level
          </p>
        </Card>

        <Card className="p-6 hover:border-accent/45">
          <div className="flex items-center gap-4">
            <div
              className="h-10 w-10 grid place-items-center rounded-[var(--radius-sm)] bg-accent/10 text-accent"
              aria-hidden="true"
            >
              <CheckCircle className="w-5 h-5" />
            </div>
            <div>
              <p
                className="text-xs uppercase tracking-[0.08em] text-muted-foreground font-semibold"
                id="modules-label"
              >
                Modules Completed
              </p>
              <h3
                className="text-[1.75rem] leading-[1.1] font-semibold tracking-tight"
                aria-labelledby="modules-label"
              >
                {completedModules.length}
              </h3>
            </div>
          </div>
        </Card>

        <Card className="p-6 hover:border-primary/45">
          <div className="flex items-center gap-4">
            <div
              className="h-10 w-10 grid place-items-center rounded-[var(--radius-sm)] bg-primary/10 text-primary"
              aria-hidden="true"
            >
              <BookOpen className="w-5 h-5" />
            </div>
            <div>
              <p
                className="text-xs uppercase tracking-[0.08em] text-muted-foreground font-semibold"
                id="mission-label"
              >
                Active Mission
              </p>
              <h3
                className="text-lg leading-[1.2] font-semibold truncate"
                aria-labelledby="mission-label"
              >
                {currentModule?.title || "No Active Mission"}
              </h3>
            </div>
          </div>
        </Card>

        <Card className="p-6 hover:border-warning/45">
          <div className="flex items-center gap-4">
            <div
              className="h-10 w-10 grid place-items-center rounded-[var(--radius-sm)] bg-warning/10 text-warning"
              aria-hidden="true"
            >
              <Flame className="w-5 h-5" />
            </div>
            <div>
              <p
                className="text-xs uppercase tracking-[0.08em] text-muted-foreground font-semibold"
                id="streak-label"
              >
                Current Streak
              </p>
              <h3
                className="text-[1.75rem] leading-[1.1] font-semibold tracking-tight"
                aria-labelledby="streak-label"
              >
                {streakDays} day{streakDays !== 1 ? "s" : ""}
                {bonusPercent > 0 && (
                  <span className="text-sm text-warning ml-2">
                    +{bonusPercent}% XP
                  </span>
                )}
              </h3>
            </div>
          </div>
        </Card>
      </section>

      <section aria-labelledby="daily-challenge-heading">
        <h2
          id="daily-challenge-heading"
          className="text-[1.75rem] font-semibold tracking-tight mb-4"
        >
          Daily Challenge
        </h2>
        <DailyChallenge />
      </section>

      <section aria-labelledby="achievements-heading">
        <div className="flex items-center justify-between mb-6">
          <h2
            id="achievements-heading"
            className="text-[1.75rem] font-semibold tracking-tight"
          >
            Achievements
          </h2>
          <Link
            to="/profile"
            className="text-sm text-primary hover:text-primary/85"
            aria-label="View all achievements on profile page"
          >
            View All
          </Link>
        </div>
        <BadgeList />
      </section>
    </div>
  );
};
