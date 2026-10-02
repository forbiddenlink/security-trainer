import React, { useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X } from "lucide-react";
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
            onClick={dismissAchievement}
            className="absolute top-1 right-1 p-2 rounded-[var(--radius-sm)] text-muted-foreground hover:text-foreground"
            aria-label="Dismiss notification"
          >
            <X className="w-4 h-4" aria-hidden="true" />
          </button>

          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground">
              {getLabelForType(currentAchievement.type)}
            </p>
            <h3 className="text-h4 mt-1">{currentAchievement.title}</h3>
            <p className="text-body-sm text-muted-foreground mt-1">
              {currentAchievement.message}
            </p>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};
