import React from "react";
import { MODULES } from "../data/modules";
import { Link } from "react-router-dom";
import { Shield, Lock, CheckCircle } from "lucide-react";
import { useGameStore } from "../store/gameStore";
import { Button, Card } from "../components/ui";
import { clsx } from "clsx";

export const Modules: React.FC = () => {
  const { completedModules } = useGameStore();

  return (
    <div className="space-y-8 max-w-5xl mx-auto animate-in fade-in duration-500">
      <div className="flex flex-col gap-2">
        <h1 className="text-h1">Active Operations</h1>
        <p className="text-muted-foreground text-body">
          Select a mission to upgrade your security clearance level.
        </p>
      </div>

      <div className="grid gap-6">
        {MODULES.map((module) => {
          const isCompleted = completedModules.includes(module.id);
          const isLocked = module.locked; // Logic could be expanded based on level

          return (
            <Card
              key={module.id}
              className={clsx(
                "group relative overflow-hidden ui-card-md",
                isLocked ? "bg-muted/20 opacity-70" : "ui-card-interactive",
              )}
            >
              {!isLocked && (
                <div className="absolute inset-0 bg-linear-to-r from-primary/6 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none" />
              )}

              <div className="grid gap-6 md:grid-cols-[1fr_220px] items-start md:items-center relative z-10">
                <div className="flex gap-4 min-w-0">
                  <div
                    className={clsx(
                      "h-12 w-12 shrink-0 grid place-items-center rounded-[var(--radius-sm)] relative overflow-hidden",
                      isCompleted
                        ? "bg-accent/12 text-accent"
                        : "bg-primary/12 text-primary",
                    )}
                  >
                    <div className="absolute inset-0 bg-current opacity-0 group-hover:opacity-10 transition-opacity" />
                    <Shield className="w-6 h-6 relative z-10" />
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-3 mb-1 flex-wrap">
                      <h3 className="text-h4 group-hover:text-primary transition-colors">
                        {module.title}
                      </h3>
                      {isCompleted && (
                        <span className="ui-chip text-accent border-accent/30 bg-accent/10">
                          <CheckCircle className="w-3 h-3" /> Completed
                        </span>
                      )}
                      <span
                        className={clsx(
                          "ui-chip font-mono",
                          module.difficulty === "Beginner"
                            ? "border-accent/35 text-accent bg-accent/8"
                            : module.difficulty === "Intermediate"
                              ? "border-warning/35 text-warning bg-warning/8"
                              : "border-destructive/35 text-destructive bg-destructive/8",
                        )}
                      >
                        {module.difficulty}
                      </span>
                    </div>
                    <p className="text-muted-foreground max-w-xl group-hover:text-foreground/85 transition-colors">
                      {module.description}
                    </p>
                  </div>
                </div>

                <div className="flex items-center justify-between md:justify-end gap-5">
                  <div className="text-left md:text-right">
                    <p className="ui-label">Reward</p>
                    <p className="text-mono text-primary font-semibold">
                      {module.xpReward} XP
                    </p>
                  </div>

                  {isLocked ? (
                    <Button
                      disabled
                      variant="secondary"
                      className="gap-2 border-transparent bg-muted text-muted-foreground"
                    >
                      <Lock className="w-4 h-4" /> Locked
                    </Button>
                  ) : (
                    <Link
                      to={`/modules/${module.id}`}
                      className={clsx(
                        "inline-flex h-10 items-center justify-center gap-2 rounded-[var(--radius-sm)] px-5 font-semibold transition-colors relative overflow-hidden",
                        isCompleted
                          ? "bg-muted hover:bg-muted/80 text-foreground border border-border hover:border-primary/30"
                          : "bg-primary text-primary-foreground hover:bg-primary/90",
                      )}
                    >
                      <span className="relative z-10">
                        {isCompleted ? "Review" : "Start Mission"}
                      </span>
                    </Link>
                  )}
                </div>
              </div>
            </Card>
          );
        })}
      </div>
    </div>
  );
};
