import React, { useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Award, Flame, CheckCircle, Star, X } from "lucide-react";
import { useGameStore } from "../store/gameStore";
import type { AchievementNotification } from "../types";

const getIconForType = (type: AchievementNotification["type"]) => {
  switch (type) {
    case "badge":
      return <Award className="w-10 h-10 text-primary" />;
    case "streak":
      return <Flame className="w-10 h-10 text-warning" />;
    case "module_complete":
      return <CheckCircle className="w-10 h-10 text-accent" />;
    case "daily_challenge":
      return <Star className="w-10 h-10 text-warning" />;
    default:
      return <Award className="w-10 h-10 text-primary" />;
  }
};

const getBorderForType = (type: AchievementNotification["type"]) => {
  switch (type) {
    case "badge":
      return "border-primary";
    case "streak":
      return "border-warning";
    case "module_complete":
      return "border-accent";
    case "daily_challenge":
      return "border-warning";
    default:
      return "border-primary";
  }
};

const getTitleColorForType = (type: AchievementNotification["type"]) => {
  switch (type) {
    case "badge":
      return "text-primary";
    case "streak":
      return "text-warning";
    case "module_complete":
      return "text-accent";
    case "daily_challenge":
      return "text-warning";
    default:
      return "text-primary";
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
          initial={{ opacity: 0, x: 50, scale: 0.8 }}
          animate={{ opacity: 1, x: 0, scale: 1 }}
          exit={{ opacity: 0, x: 50, scale: 0.8 }}
          className={`fixed bottom-24 right-8 z-50 ui-card border-l-4 ${getBorderForType(currentAchievement.type)} p-5 flex items-center gap-4 min-w-[280px]`}
          role="alert"
          aria-live="polite"
        >
          <button
            onClick={dismissAchievement}
            className="absolute top-1 right-1 p-2 rounded-md text-muted-foreground hover:text-foreground hover:bg-muted/50"
            aria-label="Dismiss notification"
          >
            <X className="w-4 h-4" aria-hidden="true" />
          </button>

          <div className="p-3 bg-muted/50 rounded-full">
            {getIconForType(currentAchievement.type)}
          </div>

          <div>
            <h3
              className={`text-lg font-bold ${getTitleColorForType(currentAchievement.type)}`}
            >
              {currentAchievement.title}
            </h3>
            <p className="text-sm text-muted-foreground">
              {currentAchievement.message}
            </p>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};
