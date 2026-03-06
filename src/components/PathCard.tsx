import React from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { Lock, ArrowRight, Award, Shield, Server, Target } from "lucide-react";
import { Progress } from "./ui";
import { useGameStore } from "../store/gameStore";
import type { LearningPath } from "../types";

const iconMap: Record<string, React.ElementType> = {
  Shield,
  Server,
  Target,
};

interface PathCardProps {
  path: LearningPath;
  index: number;
}

export const PathCard: React.FC<PathCardProps> = ({ path, index }) => {
  const { getPathProgress, isPathUnlocked, completedPaths, completedModules } =
    useGameStore();

  const progress = getPathProgress(path.id);
  const isUnlocked = isPathUnlocked(path.id);
  const isCompleted = completedPaths.includes(path.id);
  const progressPercent =
    progress.total > 0 ? (progress.completed / progress.total) * 100 : 0;

  const Icon = iconMap[path.icon] || Shield;

  const difficultyColors = {
    Beginner: "text-accent border-accent/30 bg-accent/10",
    Intermediate: "text-warning border-warning/30 bg-warning/10",
    Advanced: "text-destructive border-destructive/30 bg-destructive/10",
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.1 }}
      className={`ui-card relative overflow-hidden ${
        !isUnlocked ? "opacity-60" : ""
      } ${isCompleted ? "border-accent/50 bg-accent/5" : ""}`}
    >
      {/* Decorative gradient */}
      <div
        className={`absolute inset-0 pointer-events-none bg-linear-to-br ${
          isCompleted
            ? "from-accent/10 to-transparent"
            : "from-primary/5 to-transparent"
        }`}
        aria-hidden="true"
      />

      <div className="relative z-10 p-6">
        {/* Header */}
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <div
              className={`w-12 h-12 rounded-lg flex items-center justify-center ${
                isCompleted
                  ? "bg-accent/20 text-accent"
                  : "bg-primary/10 text-primary"
              }`}
            >
              {isCompleted ? (
                <Award className="w-6 h-6" />
              ) : (
                <Icon className="w-6 h-6" />
              )}
            </div>
            <div>
              <p className="text-xs font-mono text-muted-foreground uppercase tracking-wider">
                {path.codename}
              </p>
              <h3 className="text-lg font-semibold">{path.title}</h3>
            </div>
          </div>
          <span
            className={`ui-chip text-xs ${difficultyColors[path.difficulty]}`}
          >
            {path.difficulty}
          </span>
        </div>

        {/* Description */}
        <p className="text-sm text-muted-foreground mb-4 line-clamp-2">
          {path.description}
        </p>

        {/* Progress */}
        <div className="mb-4">
          <div className="flex justify-between text-sm mb-2">
            <span className="text-muted-foreground">
              {progress.completed}/{progress.total} modules
            </span>
            <span className="font-medium">{Math.round(progressPercent)}%</span>
          </div>
          <Progress value={progress.completed} max={progress.total} />
        </div>

        {/* Action */}
        {!isUnlocked ? (
          <div
            className="flex items-center justify-center gap-2 py-2.5 px-4 bg-muted/50 text-muted-foreground rounded-[var(--radius-sm)]"
            role="status"
            aria-label={`Locked. Complete ${path.requiredCompletions! - completedModules.length} more modules to unlock.`}
          >
            <Lock className="w-4 h-4" aria-hidden="true" />
            Complete {path.requiredCompletions! - completedModules.length} more
            modules to unlock
          </div>
        ) : isCompleted ? (
          <div className="flex items-center justify-center gap-2 py-2.5 px-4 bg-accent/20 text-accent rounded-[var(--radius-sm)] font-medium">
            <Award className="w-5 h-5" />
            Certified
          </div>
        ) : (
          <Link
            to={`/paths/${path.id}`}
            className="group inline-flex h-10 w-full items-center justify-center gap-2 rounded-[var(--radius-sm)] bg-primary px-4 font-semibold text-primary-foreground transition-colors hover:bg-primary-hover"
          >
            {progress.completed > 0 ? "Continue" : "Start"} Path
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </Link>
        )}
      </div>
    </motion.div>
  );
};
