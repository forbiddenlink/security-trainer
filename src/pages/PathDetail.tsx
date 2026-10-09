import React, { useEffect, useMemo, type ComponentType } from "react";
import { useParams, Link } from "react-router-dom";
import {
  ArrowLeft,
  ArrowRight,
  Check,
  Award,
  Cloud,
  FileCheck,
  Server,
  Shield,
  Target,
  Users,
} from "lucide-react";
import { clsx } from "clsx";
import { EmptyState, Progress } from "../components/ui";
import { getPathById } from "../data/learningPaths";
import { MODULES } from "../data/modules";
import { useGameStore } from "../store/gameStore";
import {
  estimateModuleMinutes,
  formatMinutes,
  getNextLesson,
  getRemainingMinutes,
} from "../lib/moduleMeta";

const PATH_ICONS: Record<string, ComponentType<{ className?: string }>> = {
  Shield,
  Server,
  Target,
  Users,
  FileCheck,
  Cloud,
};

const difficultyTone = {
  Beginner: "text-accent border-accent/40",
  Intermediate: "text-warning border-warning/40",
  Advanced: "text-destructive border-destructive/40",
} as const;

export const PathDetail: React.FC = () => {
  const { pathId } = useParams<{ pathId: string }>();
  const {
    completedModules,
    completedLessons,
    completedPaths,
    getPathProgress,
    completePath,
  } = useGameStore();

  const path = pathId ? getPathById(pathId) : undefined;
  const progress = useMemo(
    () => (pathId ? getPathProgress(pathId) : { completed: 0, total: 0 }),
    [pathId, getPathProgress],
  );
  const isCompleted = pathId ? completedPaths.includes(pathId) : false;

  // Check if all modules are complete and award certificate
  useEffect(() => {
    if (
      path &&
      !isCompleted &&
      progress.completed === progress.total &&
      progress.total > 0
    ) {
      completePath(path.id);
    }
  }, [path, isCompleted, progress.completed, progress.total, completePath]);

  if (!path) {
    return (
      <EmptyState
        className="min-h-[50vh]"
        title="Path not found"
        description="This track does not exist. Pick one from the learning paths."
        action={
          <Link to="/paths" className="btn-ghost-rule">
            Back to Paths
          </Link>
        }
      />
    );
  }

  const modules = path.modules
    .map((id) => MODULES.find((m) => m.id === id))
    .filter((m): m is (typeof MODULES)[number] => Boolean(m));
  const nextModule = modules.find((m) => !completedModules.includes(m.id));
  const nextLesson = nextModule
    ? getNextLesson(nextModule, completedLessons)
    : undefined;
  const minutesLeft = modules
    .filter((m) => !completedModules.includes(m.id))
    .reduce((s, m) => s + getRemainingMinutes(m, completedLessons), 0);
  const progressPercent =
    progress.total > 0 ? (progress.completed / progress.total) * 100 : 0;
  const PathIcon = (path.icon && PATH_ICONS[path.icon]) || Shield;

  return (
    <div className="space-y-10 max-w-4xl">
      <Link
        to="/paths"
        className="inline-flex items-center gap-2 font-mono text-caption uppercase tracking-[0.12em] text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="w-4 h-4" aria-hidden="true" />
        All Paths
      </Link>

      <header className="border-b border-border pb-8">
        <div className="flex items-center gap-3 mb-3">
          <span
            className="grid h-8 w-8 place-items-center rounded-[var(--radius-xs)] border border-border bg-muted/40 text-foreground"
            aria-hidden="true"
          >
            <PathIcon className="w-4 h-4" />
          </span>
          <p className="range-readout !mb-0">
            <span className="range-dot" aria-hidden="true" />
            {path.codename} · {path.difficulty}
          </p>
        </div>
        <h1 className="text-display max-w-[16ch]">{path.title}</h1>
        <p className="mt-4 text-muted-foreground max-w-[62ch]">
          {path.description}
        </p>

        <div className="mt-8 grid gap-6 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end">
          <div>
            <div className="flex justify-between font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground mb-2 tabular-nums">
              <span>
                {progress.completed} of {progress.total} modules complete
              </span>
              <span>{Math.round(progressPercent)}%</span>
            </div>
            <Progress
              value={progress.completed}
              max={progress.total}
              aria-label={`${progress.completed} of ${progress.total} modules complete`}
            />
            {!isCompleted && minutesLeft > 0 && (
              <p className="mt-2 font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground tabular-nums">
                About {formatMinutes(minutesLeft)} left
              </p>
            )}
          </div>
          {isCompleted ? (
            <p className="flex items-center gap-2 text-accent font-semibold">
              <Award className="w-5 h-5" aria-hidden="true" />
              Certification Earned: +{path.certificateXp} XP
            </p>
          ) : nextModule ? (
            <Link
              to={`/modules/${nextModule.id}${nextLesson ? `/${nextLesson.id}` : ""}`}
              className="btn-signal group"
            >
              {progress.completed > 0 ? "Continue" : "Start"}:{" "}
              {nextModule.title}
              <ArrowRight
                className="w-4 h-4 transition-transform group-hover:translate-x-1"
                aria-hidden="true"
              />
            </Link>
          ) : null}
        </div>
      </header>

      <section aria-label="Path modules">
        <div className="flex items-baseline justify-between mb-4">
          <h2 className="text-h3">Route</h2>
          <p className="font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground">
            {modules.length} stops · in order
          </p>
        </div>
        <ol className="relative">
          {modules.map((module, index) => {
            const isDone = completedModules.includes(module.id);
            const isCurrent = module.id === nextModule?.id;
            const isLast = index === modules.length - 1;
            return (
              <li key={module.id} className="relative flex gap-4">
                <div className="flex flex-col items-center">
                  <span
                    className={clsx(
                      "z-10 mt-5 grid h-8 w-8 shrink-0 place-items-center rounded-[var(--radius-xs)] font-mono text-[12px] font-semibold tabular-nums",
                      isDone
                        ? "bg-foreground text-background"
                        : isCurrent
                          ? "bg-primary text-primary-foreground"
                          : "border border-border bg-background text-muted-foreground",
                    )}
                    aria-hidden="true"
                  >
                    {isDone ? (
                      <Check className="w-4 h-4" />
                    ) : (
                      String(index + 1).padStart(2, "0")
                    )}
                  </span>
                  {!isLast && (
                    <span
                      className={clsx(
                        "w-px flex-1",
                        isDone ? "bg-foreground/60" : "bg-border",
                      )}
                      aria-hidden="true"
                    />
                  )}
                </div>
                <Link
                  to={`/modules/${module.id}`}
                  className={clsx(
                    "group flex-1 min-w-0 my-2 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between rounded-[var(--radius-md)] border p-4 transition-colors",
                    isCurrent
                      ? "border-foreground"
                      : "border-border hover:border-foreground/60",
                  )}
                  aria-current={isCurrent ? "step" : undefined}
                >
                  <div className="min-w-0">
                    <h3 className="font-semibold group-hover:underline underline-offset-4 decoration-primary decoration-2">
                      {module.title}
                    </h3>
                    <p className="mt-1 font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground tabular-nums">
                      {module.lessons.length} lessons ·{" "}
                      {formatMinutes(estimateModuleMinutes(module))} ·{" "}
                      {module.xpReward} XP
                      {isDone && " · Cleared"}
                      {isCurrent && " · Up next"}
                    </p>
                  </div>
                  <span
                    className={clsx(
                      "ui-chip self-start sm:self-center",
                      difficultyTone[module.difficulty],
                    )}
                  >
                    {module.difficulty}
                  </span>
                </Link>
              </li>
            );
          })}
        </ol>

        <div
          className={clsx(
            "mt-6 flex items-center justify-between gap-4 rounded-[var(--radius-md)] border border-dashed p-5",
            isCompleted ? "border-accent/60" : "border-border",
          )}
        >
          <div className="flex items-center gap-3">
            <Award
              className={clsx(
                "w-5 h-5",
                isCompleted ? "text-accent" : "text-muted-foreground",
              )}
              aria-hidden="true"
            />
            <div>
              <p className="ui-label">Certification</p>
              <p className="font-semibold">
                {isCompleted ? "Earned" : `Finish all ${modules.length} stops`}
              </p>
            </div>
          </div>
          <p className="font-display text-h3 font-extrabold [font-stretch:75%] tabular-nums">
            +{path.certificateXp} XP
          </p>
        </div>
      </section>
    </div>
  );
};
