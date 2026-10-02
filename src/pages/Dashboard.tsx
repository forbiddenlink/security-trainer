import React, { useMemo } from "react";
import { Link } from "react-router-dom";
import { ArrowRight, ChevronDown } from "lucide-react";
import { useGameStore } from "../store/gameStore";
import { BadgeList } from "../components/BadgeList";
import { DailyChallenge } from "../components/DailyChallenge";
import { IntelRefresher } from "../components/IntelRefresher";
import { RoleSelector } from "../components/RoleSelector";
import { ROLES } from "../data/roles";
import { LiveLabTargets } from "../components/LiveLabTargets";
import { NextBadgePreview } from "../components/NextBadgePreview";
import { RangeInstrument } from "../components/RangeInstrument";
import { RandomMission } from "../components/RandomMission";
import { Progress } from "../components/ui";
import { MODULES } from "../data/modules";
import { LEARNING_PATHS } from "../data/learningPaths";
import { CTF_CHALLENGES } from "../data/ctfChallenges";
import {
  estimateModuleMinutes,
  formatMinutes,
  getModuleStatus,
  getNextLesson,
  getRemainingMinutes,
} from "../lib/moduleMeta";
import type { Module } from "../types";

const TOTAL_LESSONS = MODULES.reduce((n, m) => n + m.lessons.length, 0);
const TOTAL_LABS = MODULES.reduce(
  (n, m) => n + m.lessons.filter((l) => l.type === "lab").length,
  0,
);

const opNumber = (module: Module): string =>
  String(MODULES.indexOf(module) + 1).padStart(2, "0");

const lessonHref = (module: Module, lessonId?: string): string =>
  lessonId ? `/modules/${module.id}/${lessonId}` : `/modules/${module.id}`;

/** First module of the path that matches the learner's role, else module 01. */
function recommendedModule(userRole: string | null): Module {
  const role = ROLES.find((r) => r.id === userRole);
  const path = LEARNING_PATHS.find((p) => p.id === role?.recommendedPathId);
  const id = path?.modules[0];
  return MODULES.find((m) => m.id === id) ?? MODULES[0];
}

interface SectionProps {
  index: string;
  label: string;
  id: string;
  title: string;
  aside?: React.ReactNode;
  children: React.ReactNode;
}

const Section: React.FC<SectionProps> = ({
  index,
  label,
  id,
  title,
  aside,
  children,
}) => (
  <section className="section-rule" aria-labelledby={id}>
    <div className="section-rail">
      <span className="section-index">{index}</span>
      <span className="ui-label">{label}</span>
    </div>
    <div className="min-w-0">
      <div className="flex items-end justify-between gap-4 mb-5">
        <h2 id={id} className="text-h2">
          {title}
        </h2>
        {aside}
      </div>
      {children}
    </div>
  </section>
);

export const Dashboard: React.FC = () => {
  const xp = useGameStore((s) => s.xp);
  const level = useGameStore((s) => s.level);
  const completedModules = useGameStore((s) => s.completedModules);
  const completedLessons = useGameStore((s) => s.completedLessons);
  const currentModuleId = useGameStore((s) => s.currentModuleId);
  const streakDays = useGameStore((s) => s.streakDays);
  const userRole = useGameStore((s) => s.userRole);

  const currentModule = useMemo(
    () => MODULES.find((m) => m.id === currentModuleId),
    [currentModuleId],
  );
  const inProgressModule = useMemo(
    () =>
      MODULES.find(
        (m) =>
          getModuleStatus(m, completedModules, completedLessons) ===
          "in-progress",
      ),
    [completedModules, completedLessons],
  );

  const isNewVisitor =
    xp === 0 && completedModules.length === 0 && completedLessons.length === 0;
  const nextLevelXp = level * 1000;
  const firstMission = recommendedModule(userRole);
  const resumeModule =
    (currentModule && !completedModules.includes(currentModule.id)
      ? currentModule
      : undefined) ??
    inProgressModule ??
    MODULES.find((m) => !completedModules.includes(m.id)) ??
    firstMission;
  const resumeLesson = getNextLesson(resumeModule, completedLessons);
  const resumeDone = resumeModule.lessons.filter((l) =>
    completedLessons.includes(l.id),
  ).length;
  const catalogProgress = completedModules.length / MODULES.length;

  return (
    <div className="space-y-14 md:space-y-20">
      {isNewVisitor ? (
        <section
          className="grid gap-10 lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)] items-center reveal"
          aria-labelledby="hero-heading"
        >
          <div className="min-w-0">
            <p className="flex items-center gap-2 range-readout mb-6">
              <span className="range-dot" aria-hidden="true" />
              Range open · no signup · progress saves locally
            </p>
            <h1 id="hero-heading" className="text-display max-w-[14ch]">
              Break it here. Fix it at work.
            </h1>
            <p className="mt-6 text-body md:text-[1.0625rem] text-muted-foreground max-w-[56ch]">
              SecTrainer is a free, hands-on trainer for application security.{" "}
              {MODULES.length} modules on the OWASP Top 10, injection, auth,
              cloud and AI security, with in-browser code labs, quizzes and CTF
              flags.
            </p>
            <div className="mt-8 flex flex-col sm:flex-row gap-3">
              <Link
                to={lessonHref(firstMission, firstMission.lessons[0]?.id)}
                className="btn-signal"
              >
                Start mission {opNumber(firstMission)}
                <span className="hidden sm:inline -ml-2">
                  : {firstMission.title}
                </span>
                <ArrowRight className="w-4 h-4" aria-hidden="true" />
              </Link>
              <Link to="/modules" className="btn-ghost-rule">
                Browse all {MODULES.length} modules
              </Link>
            </div>
            <p className="mt-3 font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground">
              <span className="sm:hidden">{firstMission.title} · </span>
              {firstMission.lessons.length} lessons ·{" "}
              {formatMinutes(estimateModuleMinutes(firstMission))} ·{" "}
              {firstMission.difficulty}
            </p>
            <div className="mt-10 pt-6 border-t border-border">
              <RoleSelector />
            </div>
          </div>
          <RangeInstrument
            progress={0}
            readouts={[
              { label: "Modules", value: MODULES.length },
              { label: "Lessons", value: TOTAL_LESSONS },
              { label: "Code labs", value: TOTAL_LABS },
              { label: "CTF flags", value: CTF_CHALLENGES.length },
            ]}
          />
        </section>
      ) : (
        <section
          className="grid gap-10 lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)] items-stretch reveal"
          aria-labelledby="hero-heading"
        >
          <div className="min-w-0 flex flex-col">
            <p className="flex items-center gap-2 range-readout mb-6">
              <span className="range-dot" aria-hidden="true" />
              Range status · online · level {level}
            </p>
            <h1 id="hero-heading" className="text-h1">
              Welcome back, Agent.
            </h1>
            <div className="mt-8 flex-1 ui-card ui-card-lg mission-card">
              <p className="ui-label">Resume · OP-{opNumber(resumeModule)}</p>
              <h2 className="mt-2 text-h2">
                <Link
                  to={lessonHref(resumeModule)}
                  className="hover:underline underline-offset-4 decoration-1"
                >
                  {resumeModule.title}
                </Link>
              </h2>
              {resumeLesson && (
                <p className="mt-2 text-body-sm text-muted-foreground">
                  Next up:{" "}
                  <span className="text-foreground">{resumeLesson.title}</span>{" "}
                  ({resumeLesson.type})
                </p>
              )}
              <div className="mt-6">
                <div className="flex justify-between font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground mb-2 tabular-nums">
                  <span>
                    {resumeDone} / {resumeModule.lessons.length} lessons
                  </span>
                  <span>
                    {formatMinutes(
                      getRemainingMinutes(resumeModule, completedLessons),
                    )}{" "}
                    left
                  </span>
                </div>
                <Progress
                  value={resumeDone}
                  max={resumeModule.lessons.length}
                  aria-label={`${resumeDone} of ${resumeModule.lessons.length} lessons complete in ${resumeModule.title}`}
                />
              </div>
              <div className="mt-6 flex flex-wrap gap-3">
                <Link
                  to={lessonHref(resumeModule, resumeLesson?.id)}
                  className="btn-signal"
                  aria-label={`Continue ${resumeModule.title}`}
                >
                  Continue mission
                  <ArrowRight className="w-4 h-4" aria-hidden="true" />
                </Link>
                <Link to="/modules" className="btn-ghost-rule">
                  All modules
                </Link>
              </div>
            </div>
          </div>
          <RangeInstrument
            progress={catalogProgress}
            readouts={[
              { label: "XP", value: xp },
              {
                label: `To L${level + 1}`,
                value: Math.max(0, nextLevelXp - xp),
              },
              {
                label: "Missions",
                value: `${completedModules.length}/${MODULES.length}`,
              },
              { label: "Streak days", value: streakDays },
            ]}
          />
        </section>
      )}

      <Section
        index="01"
        label="Today"
        id="today-heading"
        title="Today’s orders"
      >
        <div className="grid gap-4 md:grid-cols-2 items-stretch">
          <DailyChallenge />
          <RandomMission />
          <div className="md:col-span-2 empty:hidden">
            <IntelRefresher />
          </div>
        </div>
      </Section>

      <Section
        index="02"
        label="Service record"
        id="achievements-heading"
        title="Achievements"
        aside={
          <Link
            to="/profile"
            className="font-mono text-caption uppercase tracking-[0.12em] text-muted-foreground hover:text-foreground"
            aria-label="View all achievements on profile page"
          >
            View all →
          </Link>
        }
      >
        <div className="space-y-4">
          <NextBadgePreview />
          <BadgeList />
        </div>
      </Section>

      <Section
        index="03"
        label="Live range"
        id="live-range-heading"
        title="Local practice targets"
      >
        <details className="group ui-card">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-4 text-body-sm">
            <span>
              Run Juice Shop, DVWA and WebGoat on your machine for open-ended
              practice.
            </span>
            <ChevronDown
              className="w-4 h-4 shrink-0 transition-transform group-open:rotate-180"
              aria-hidden="true"
            />
          </summary>
          <div className="mt-4">
            <LiveLabTargets showAll />
          </div>
        </details>
      </Section>
    </div>
  );
};
