import React, { useEffect, useMemo } from "react";
import { useParams, Link } from "react-router-dom";
import { motion } from "framer-motion";
import { ArrowLeft, ArrowRight, CheckCircle, Award } from "lucide-react";
import { Progress } from "../components/ui";
import { getPathById } from "../data/learningPaths";
import { MODULES } from "../data/modules";
import { useGameStore } from "../store/gameStore";

export const PathDetail: React.FC = () => {
  const { pathId } = useParams<{ pathId: string }>();
  const { completedModules, completedPaths, getPathProgress, completePath } =
    useGameStore();

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
      <div className="text-center py-12">
        <p className="text-muted-foreground">Path not found</p>
        <Link to="/paths" className="text-primary hover:underline mt-2 block">
          Back to Paths
        </Link>
      </div>
    );
  }

  // Find next incomplete module
  const nextModuleId = path.modules.find(
    (moduleId) => !completedModules.includes(moduleId),
  );
  const nextModule = nextModuleId
    ? MODULES.find((m) => m.id === nextModuleId)
    : null;

  const progressPercent =
    progress.total > 0 ? (progress.completed / progress.total) * 100 : 0;

  return (
    <div
      className="space-y-8 max-w-4xl mx-auto animate-in fade-in duration-500"
      role="main"
    >
      {/* Back button */}
      <Link
        to="/paths"
        className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
      >
        <ArrowLeft className="w-4 h-4" />
        All Paths
      </Link>

      {/* Header */}
      <section
        className={`ui-card ui-card-lg relative overflow-hidden ${
          isCompleted
            ? "border-accent/50 border-l-[3px] border-l-accent"
            : "ops-briefing"
        }`}
      >
        <div className="relative z-10">
          <p className="text-xs font-mono text-muted-foreground uppercase tracking-wider mb-1">
            {path.codename}
          </p>
          <h1 className="text-h1 mb-2">{path.title}</h1>
          <p className="text-muted-foreground mb-6">{path.description}</p>

          {/* Progress bar */}
          <div className="mb-4">
            <div className="flex justify-between text-sm mb-2">
              <span>
                {progress.completed} of {progress.total} modules complete
              </span>
              <span className="font-medium">
                {Math.round(progressPercent)}%
              </span>
            </div>
            <Progress value={progress.completed} max={progress.total} />
          </div>

          {/* Certificate status */}
          {isCompleted ? (
            <div className="flex items-center gap-2 text-accent font-medium">
              <Award className="w-5 h-5" />
              Certification Earned - +{path.certificateXp} XP
            </div>
          ) : nextModule ? (
            <Link
              to={`/modules/${nextModule.id}`}
              className="group inline-flex h-10 items-center justify-center gap-2 rounded-[var(--radius-sm)] bg-primary px-5 font-semibold text-primary-foreground transition-colors hover:bg-primary-hover"
            >
              Continue: {nextModule.title}
              <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
            </Link>
          ) : null}
        </div>
      </section>

      {/* Module list */}
      <section aria-label="Path modules">
        <h2 className="text-h3 mb-4">Modules in this Path</h2>
        <div className="space-y-3">
          {path.modules.map((moduleId, index) => {
            const module = MODULES.find((m) => m.id === moduleId);
            if (!module) return null;

            const isDone = completedModules.includes(moduleId);
            const isCurrent = moduleId === nextModuleId;

            return (
              <motion.div
                key={moduleId}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.05 }}
              >
                <Link
                  to={`/modules/${moduleId}`}
                  className={`flex items-center gap-4 p-4 rounded-lg border transition-colors ${
                    isCurrent
                      ? "border-primary bg-primary/5"
                      : isDone
                        ? "border-accent/30 bg-accent/5"
                        : "border-border hover:border-primary/50 hover:bg-muted/30"
                  }`}
                >
                  <div
                    className={`w-8 h-8 rounded-full flex items-center justify-center ${
                      isDone
                        ? "bg-accent text-accent-foreground"
                        : isCurrent
                          ? "bg-primary text-primary-foreground"
                          : "bg-muted text-muted-foreground"
                    }`}
                  >
                    {isDone ? (
                      <CheckCircle className="w-5 h-5" />
                    ) : (
                      <span className="text-sm font-bold">{index + 1}</span>
                    )}
                  </div>
                  <div className="flex-1">
                    <h3 className="font-medium">{module.title}</h3>
                    <p className="text-sm text-muted-foreground">
                      {module.lessons.length} lessons • {module.xpReward} XP
                    </p>
                  </div>
                  <span
                    className={`text-xs px-2 py-1 rounded ${
                      module.difficulty === "Beginner"
                        ? "bg-accent/10 text-accent"
                        : module.difficulty === "Intermediate"
                          ? "bg-warning/10 text-warning"
                          : "bg-destructive/10 text-destructive"
                    }`}
                  >
                    {module.difficulty}
                  </span>
                </Link>
              </motion.div>
            );
          })}
        </div>
      </section>
    </div>
  );
};
