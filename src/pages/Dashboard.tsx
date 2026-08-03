import React, { useMemo } from "react";
import { useGameStore } from "../store/gameStore";
import { BadgeList } from "../components/BadgeList";
import { DailyChallenge } from "../components/DailyChallenge";
import { IntelRefresher } from "../components/IntelRefresher";
import { RoleSelector } from "../components/RoleSelector";
import { LiveLabTargets } from "../components/LiveLabTargets";
import { MODULES } from "../data/modules";
import { Card, Progress } from "../components/ui";
import { ArrowRight } from "lucide-react";
import { Link } from "react-router-dom";

export const Dashboard: React.FC = () => {
  const {
    xp,
    level,
    completedModules,
    currentModuleId,
    streakDays,
    getStreakMultiplier,
    userRole,
  } = useGameStore();
  const currentModule = useMemo(
    () => MODULES.find((m) => m.id === currentModuleId),
    [currentModuleId],
  );
  const nextLevelXp = level * 1000;
  const streakMultiplier = getStreakMultiplier();
  const bonusPercent = Math.round((streakMultiplier - 1) * 100);

  const isNewVisitor = xp === 0 && completedModules.length === 0;

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      {isNewVisitor && (
        <section className="ui-card ui-card-lg" aria-label="What SecTrainer is">
          <p className="ui-chip mb-3">New here?</p>
          <h1 className="text-h1 mb-2">Learn web security by doing.</h1>
          <p className="text-muted-foreground max-w-2xl text-body-sm md:text-body">
            SecTrainer is a free, hands-on trainer for web security —{" "}
            {MODULES.length}+ modules across the OWASP Top 10, injection, auth
            flaws, cloud, and compliance, with in-browser code labs, quizzes,
            and CTF challenges. No signup required; your progress saves in this
            browser. Pick a track below to begin.
          </p>
        </section>
      )}
      {!userRole && xp === 0 && completedModules.length === 0 ? (
        <RoleSelector />
      ) : (
        <section
          className="ui-card ui-card-lg ops-briefing range-panel range-ticks relative overflow-hidden"
          aria-label="Welcome section"
        >
          <div className="relative z-10 flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
            <div>
              <div className="flex items-center gap-2 mb-3">
                <span className="range-dot" aria-hidden="true" />
                <span className="range-readout">Range Status // Online</span>
              </div>
              <h1 className="text-h1 mb-2">Welcome back, Agent.</h1>
              <p className="text-muted-foreground text-body-sm md:text-body max-w-lg">
                Current Clearance Level:{" "}
                <span className="text-primary font-semibold">
                  Level {level}
                </span>
                {currentModule ? (
                  <>
                    . Active dossier:{" "}
                    <Link
                      to={`/modules/${currentModule.id}`}
                      className="text-foreground font-medium underline-offset-4 hover:underline"
                    >
                      {currentModule.title}
                    </Link>
                  </>
                ) : (
                  ". No active mission assigned."
                )}
              </p>
            </div>
            <Link
              to={currentModule ? `/modules/${currentModule.id}` : "/modules"}
              className="inline-flex h-10 items-center justify-center gap-2 rounded-[var(--radius-sm)] bg-primary px-5 font-semibold text-primary-foreground transition-colors hover:bg-primary-hover"
              aria-label="Resume training modules"
            >
              {currentModule ? "Continue Mission" : "Resume Training"}
              <ArrowRight className="w-4 h-4" aria-hidden="true" />
            </Link>
          </div>
        </section>
      )}

      <section
        className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4"
        aria-label="Statistics"
      >
        {/* XP Card - Hero stat with progress */}
        <Card className="ui-card-md md:col-span-2 lg:col-span-1">
          <p className="ui-label mb-2" id="score-label">
            Current Score
          </p>
          <h3 className="ui-stat-value" aria-labelledby="score-label">
            {xp}
            <span className="text-body-sm text-muted-foreground font-normal ml-1">
              XP
            </span>
          </h3>
          <Progress
            className="mt-3"
            value={xp}
            min={0}
            max={nextLevelXp}
            aria-label={`XP progress: ${xp} of ${nextLevelXp}`}
            indicatorClassName="bg-primary"
          />
          <p className="text-body-sm text-muted-foreground mt-1.5">
            {nextLevelXp - xp} XP to next level
          </p>
        </Card>

        {/* Modules Completed */}
        <Card className="ui-card-md">
          <p className="ui-label mb-2" id="modules-label">
            Missions Complete
          </p>
          <h3 className="ui-stat-value" aria-labelledby="modules-label">
            {completedModules.length}
            <span className="text-body-sm text-muted-foreground font-normal ml-1">
              / {MODULES.length}
            </span>
          </h3>
        </Card>

        {/* Active Mission */}
        <Card className="ui-card-md">
          <p className="ui-label mb-2" id="mission-label">
            Active Mission
          </p>
          {currentModule ? (
            <Link
              to={`/modules/${currentModule.id}`}
              className="text-h4 truncate block hover:text-primary transition-colors"
              aria-labelledby="mission-label"
            >
              {currentModule.title}
            </Link>
          ) : (
            <h3 className="text-h4 truncate" aria-labelledby="mission-label">
              None assigned
            </h3>
          )}
        </Card>

        {/* Streak */}
        <Card className="ui-card-md">
          <p className="ui-label mb-2" id="streak-label">
            Current Streak
          </p>
          <h3 className="ui-stat-value" aria-labelledby="streak-label">
            {streakDays}
            <span className="text-body-sm text-muted-foreground font-normal ml-1">
              day{streakDays !== 1 ? "s" : ""}
            </span>
          </h3>
          {bonusPercent > 0 && (
            <p className="text-body-sm text-warning font-medium mt-1">
              +{bonusPercent}% XP bonus
            </p>
          )}
        </Card>
      </section>

      <section aria-labelledby="daily-challenge-heading">
        <h2 id="daily-challenge-heading" className="text-h2 mb-4">
          Daily Challenge
        </h2>
        <DailyChallenge />
      </section>

      <section aria-labelledby="intel-refresher-heading">
        <h2 id="intel-refresher-heading" className="sr-only">
          Intel Refresher
        </h2>
        <IntelRefresher />
      </section>

      <section
        aria-labelledby="live-range-heading"
        className="ui-card ui-card-md"
      >
        <h2 id="live-range-heading" className="sr-only">
          Live practice range
        </h2>
        <LiveLabTargets showAll />
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
