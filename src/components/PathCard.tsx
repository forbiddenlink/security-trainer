import React, { type ComponentType } from "react";
import { Link } from "react-router-dom";
import {
  ArrowRight,
  Award,
  Cloud,
  FileCheck,
  Lock,
  Server,
  Shield,
  Target,
  Users,
} from "lucide-react";
import { clsx } from "clsx";
import { Progress } from "./ui";
import { useGameStore } from "../store/gameStore";
import { MODULES } from "../data/modules";
import { estimateModuleMinutes, formatMinutes } from "../lib/moduleMeta";
import type { LearningPath } from "../types";

const PATH_ICONS: Record<string, ComponentType<{ className?: string }>> = {
  Shield,
  Server,
  Target,
  Users,
  FileCheck,
  Cloud,
};

interface PathCardProps {
  path: LearningPath;
  index: number;
}

const difficultyTone: Record<LearningPath["difficulty"], string> = {
  Beginner: "text-accent border-accent/40",
  Intermediate: "text-warning border-warning/40",
  Advanced: "text-destructive border-destructive/40",
};

export const PathCard: React.FC<PathCardProps> = ({ path, index }) => {
  const { getPathProgress, isPathUnlocked, completedPaths, completedModules } =
    useGameStore();

  const progress = getPathProgress(path.id);
  const isUnlocked = isPathUnlocked(path.id);
  const isCompleted = completedPaths.includes(path.id);
  const progressPercent =
    progress.total > 0 ? (progress.completed / progress.total) * 100 : 0;
  const remainingToUnlock =
    (path.requiredCompletions ?? 0) - completedModules.length;

  const modules = path.modules
    .map((id) => MODULES.find((m) => m.id === id))
    .filter((m): m is (typeof MODULES)[number] => Boolean(m));
  const totalMinutes = modules.reduce(
    (sum, m) => sum + estimateModuleMinutes(m),
    0,
  );
  const PathIcon = (path.icon && PATH_ICONS[path.icon]) || Shield;

  return (
    <article
      className={clsx(
        "mission-card ui-card relative flex flex-col p-6",
        !isUnlocked && "opacity-60",
        isCompleted && "border-accent/60",
      )}
    >
      <div className="flex items-start justify-between gap-3 mb-4">
        <div className="flex items-center gap-2">
          <span
            className="grid h-7 w-7 place-items-center rounded-[var(--radius-xs)] border border-border bg-muted/40 text-foreground"
            aria-hidden="true"
          >
            <PathIcon className="w-3.5 h-3.5" />
          </span>
          <p className="font-mono text-[11px] uppercase tracking-[0.14em] text-muted-foreground">
            Track {String(index + 1).padStart(2, "0")}
          </p>
        </div>
        <span className={clsx("ui-chip", difficultyTone[path.difficulty])}>
          {path.difficulty}
        </span>
      </div>

      <h2 className="text-h3">{path.title}</h2>
      <p className="mt-1 mb-3 font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground">
        {path.codename}
      </p>
      <p className="text-body-sm text-muted-foreground mb-5 line-clamp-3">
        {path.description}
      </p>

      {modules.length > 0 && (
        <ol
          className="flex items-center gap-1 mb-5"
          aria-label={`${modules.length} modules in this path`}
        >
          {modules.map((m, i) => {
            const done = completedModules.includes(m.id);
            return (
              <li
                key={m.id}
                className="flex-1 flex items-center gap-1"
                title={m.title}
              >
                <span
                  className={clsx(
                    "h-1.5 flex-1",
                    done ? "bg-primary" : "bg-muted",
                  )}
                />
                <span className="sr-only">
                  {i + 1}. {m.title}
                  {done ? " (completed)" : ""}
                </span>
              </li>
            );
          })}
        </ol>
      )}

      <dl className="flex flex-wrap justify-between gap-x-4 gap-y-3 border-t border-border pt-4 mb-5 font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground">
        <div>
          <dt>Progress</dt>
          <dd className="mt-1 text-body-sm normal-case tracking-normal text-foreground tabular-nums whitespace-nowrap">
            {progress.completed}/{progress.total} modules
          </dd>
        </div>
        <div>
          <dt>Time</dt>
          <dd className="mt-1 text-body-sm normal-case tracking-normal text-foreground tabular-nums whitespace-nowrap">
            {totalMinutes > 0 ? formatMinutes(totalMinutes) : "--"}
          </dd>
        </div>
        <div>
          <dt>Cleared</dt>
          <dd className="mt-1 text-body-sm normal-case tracking-normal text-foreground tabular-nums whitespace-nowrap">
            {Math.round(progressPercent)}%
          </dd>
        </div>
      </dl>
      <Progress
        className="sr-only"
        value={progress.completed}
        max={progress.total}
        aria-label={`${path.title}: ${progress.completed} of ${progress.total} modules complete`}
      />

      <div className="mt-auto">
        {!isUnlocked ? (
          <div
            className="flex items-center gap-2 h-11 px-3 border border-dashed border-border rounded-[var(--radius-sm)] text-body-sm text-muted-foreground"
            role="status"
            aria-label={`Locked. Complete ${remainingToUnlock} more modules to unlock.`}
          >
            <Lock className="w-4 h-4 shrink-0" aria-hidden="true" />
            Complete {remainingToUnlock} more modules to unlock
          </div>
        ) : isCompleted ? (
          <Link
            to={`/paths/${path.id}`}
            className="flex items-center justify-between gap-2 h-11 px-3 border border-accent/60 rounded-[var(--radius-sm)] text-accent font-semibold"
          >
            <span className="flex items-center gap-2">
              <Award className="w-4 h-4" aria-hidden="true" />
              Certified
            </span>
            <span className="font-mono text-[11px] uppercase tracking-[0.12em]">
              +{path.certificateXp} XP
            </span>
          </Link>
        ) : (
          <Link
            to={`/paths/${path.id}`}
            className={clsx(
              "group inline-flex h-11 w-full items-center justify-between gap-2 rounded-[var(--radius-sm)] px-4 font-semibold transition-colors",
              progress.completed > 0
                ? "btn-signal"
                : "border border-foreground hover:bg-foreground hover:text-background",
            )}
          >
            {progress.completed > 0 ? "Continue" : "Start"} Path
            <ArrowRight
              className="w-4 h-4 transition-transform group-hover:translate-x-1"
              aria-hidden="true"
            />
          </Link>
        )}
      </div>
    </article>
  );
};
