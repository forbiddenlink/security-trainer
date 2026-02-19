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
        className="ui-card ui-card-lg ui-card-elevated relative overflow-hidden"
        aria-label="Welcome section"
      >
        <div className="absolute inset-0 pointer-events-none bg-linear-to-r from-primary/6 via-transparent to-accent/6" />
        <div className="relative z-10 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
          <div>
            <p className="ui-chip mb-3">Mission Status</p>
            <h2 className="text-h1 mb-2">Welcome back, Agent.</h2>
            <p className="text-muted-foreground text-body-sm md:text-body">
              Current Clearance Level:{" "}
              <span className="text-primary font-semibold">Level {level}</span>.
            </p>
          </div>
          <Link
            to="/modules"
            className={cn(
              "group inline-flex h-10 items-center justify-center gap-2 rounded-[var(--radius-sm)] bg-primary px-5 font-semibold text-primary-foreground transition-colors hover:bg-primary-hover",
              "shadow-[var(--shadow-lg)]",
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
        {/* XP Card - Hero stat with progress */}
        <Card className="ui-card-md ui-card-interactive md:col-span-2 lg:col-span-1">
          <div className="flex items-center gap-4 mb-4">
            <div
              className="ui-icon-box bg-primary/12 text-primary"
              aria-hidden="true"
            >
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <p className="ui-label" id="score-label">
                Current Score
              </p>
              <h3 className="ui-stat-value" aria-labelledby="score-label">
                {xp}{" "}
                <span className="text-body-sm text-muted-foreground font-normal">
                  XP
                </span>
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
          <p className="text-body-sm text-muted-foreground mt-2">
            {nextLevelXp - xp} XP to next level
          </p>
        </Card>

        {/* Modules Completed */}
        <Card className="ui-card-md ui-card-interactive">
          <div className="flex items-center gap-4">
            <div
              className="ui-icon-box bg-accent/12 text-accent"
              aria-hidden="true"
            >
              <CheckCircle className="w-5 h-5" />
            </div>
            <div>
              <p className="ui-label" id="modules-label">
                Modules Completed
              </p>
              <h3 className="ui-stat-value" aria-labelledby="modules-label">
                {completedModules.length}
              </h3>
            </div>
          </div>
        </Card>

        {/* Active Mission */}
        <Card className="ui-card-md ui-card-interactive">
          <div className="flex items-center gap-4">
            <div
              className="ui-icon-box bg-primary/12 text-primary"
              aria-hidden="true"
            >
              <BookOpen className="w-5 h-5" />
            </div>
            <div>
              <p className="ui-label" id="mission-label">
                Active Mission
              </p>
              <h3
                className="text-h4 truncate max-w-[180px]"
                aria-labelledby="mission-label"
              >
                {currentModule?.title || "No Active Mission"}
              </h3>
            </div>
          </div>
        </Card>

        {/* Streak Card - Highlighted with gradient */}
        <Card className="ui-card-md ui-card-interactive relative overflow-hidden">
          <div className="absolute inset-0 bg-gradient-to-br from-warning/8 to-transparent pointer-events-none" />
          <div className="relative z-10 flex items-center gap-4">
            <div
              className="ui-icon-box bg-warning/12 text-warning"
              aria-hidden="true"
            >
              <Flame className="w-5 h-5" />
            </div>
            <div>
              <p className="ui-label" id="streak-label">
                Current Streak
              </p>
              <h3
                className="ui-stat-value flex items-baseline gap-2"
                aria-labelledby="streak-label"
              >
                {streakDays}{" "}
                <span className="text-body-sm text-muted-foreground font-normal">
                  day{streakDays !== 1 ? "s" : ""}
                </span>
                {bonusPercent > 0 && (
                  <span className="ui-chip text-warning border-warning/30 bg-warning/10 ml-1">
                    +{bonusPercent}%
                  </span>
                )}
              </h3>
            </div>
          </div>
        </Card>
      </section>

      <section aria-labelledby="daily-challenge-heading">
        <h2 id="daily-challenge-heading" className="text-h2 mb-4">
          Daily Challenge
        </h2>
        <DailyChallenge />
      </section>

      <section aria-labelledby="achievements-heading">
        <div className="flex items-center justify-between mb-6">
          <h2 id="achievements-heading" className="text-h2">
            Achievements
          </h2>
          <Link
            to="/profile"
            className="text-body-sm text-primary hover:text-primary-hover transition-colors"
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
