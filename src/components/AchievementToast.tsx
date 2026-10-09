import type React from "react";
import { useEffect, type ComponentType } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Award, CheckCircle2, Flame, Target, X } from "lucide-react";
import { useGameStore } from "../store/gameStore";
import type { AchievementNotification } from "../types";

const getLabelForType = (type: AchievementNotification["type"]) => {
  switch (type) {
    case "streak":
      return "Streak";
    case "module_complete":
      return "Module cleared";
    case "daily_challenge":
      return "Daily";
    case "badge":
    default:
      return "Badge earned";
  }
};

const getBorderForType = (type: AchievementNotification["type"]) => {
  switch (type) {
    case "streak":
    case "daily_challenge":
      return "border-l-warning";
    case "module_complete":
      return "border-l-accent";
    case "badge":
    default:
      return "border-l-primary";
  }
};

const getIconForType = (
  type: AchievementNotification["type"],
): ComponentType<{ className?: string }> => {
  switch (type) {
    case "streak":
      return Flame;
    case "module_complete":
      return CheckCircle2;
    case "daily_challenge":
      return Target;
    case "badge":
    default:
      return Award;
  }
};

export const AchievementToast: React.FC = () => {
  const { achievementQueue, dismissAchievement } = useGameStore();
  const currentAchievement = achievementQueue[0];

  // Auto-dismiss after 4 seconds
  useEffect(() => {
    if (!currentAchievement) return;

    const timer = setTimeout(() => {
      dismissAchievement();
    }, 4000);

    return () => clearTimeout(timer);
  }, [currentAchievement, dismissAchievement]);

  return (
    <AnimatePresence>
      {currentAchievement && (
        <motion.div
          key={currentAchievement.id}
          initial={{ opacity: 0, x: 24 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: 24 }}
          className={`fixed bottom-24 right-8 z-50 ui-card ui-card-elevated border-l-[3px] ${getBorderForType(currentAchievement.type)} pr-10 min-w-[280px] max-w-sm`}
          role="alert"
          aria-live="polite"
        >
          <button
            type="button"
            onClick={dismissAchievement}
            className="absolute top-1 right-1 p-2 rounded-[var(--radius-sm)] text-muted-foreground hover:text-foreground"
            aria-label="Dismiss notification"
          >
            <X className="w-4 h-4" aria-hidden="true" />
          </button>

          <div className="flex items-start gap-3">
            <span
              className="grid h-8 w-8 shrink-0 place-items-center rounded-[var(--radius-xs)] border border-border bg-muted/40 text-foreground"
              aria-hidden="true"
            >
              {(() => {
                const Icon = getIconForType(currentAchievement.type);
                return <Icon className="w-4 h-4" />;
              })()}
            </span>
            <div className="min-w-0 flex-1">
              <p className="font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground">
                {getLabelForType(currentAchievement.type)}
              </p>
              <h3 className="text-h4 mt-0.5">{currentAchievement.title}</h3>
              <p className="text-body-sm text-muted-foreground mt-0.5">
                {currentAchievement.message}
              </p>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};
