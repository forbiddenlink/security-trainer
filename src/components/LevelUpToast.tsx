import React, { useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X } from "lucide-react";
import { useGameStore } from "../store/gameStore";

export const LevelUpToast: React.FC = () => {
  const { level, showLevelUpToast, dismissLevelUpToast } = useGameStore();

  // Auto-dismiss toast after 5 seconds
  useEffect(() => {
    if (!showLevelUpToast) return;

    const timer = setTimeout(() => {
      dismissLevelUpToast();
    }, 5000);

    return () => clearTimeout(timer);
  }, [showLevelUpToast, dismissLevelUpToast]);

  return (
    <AnimatePresence>
      {showLevelUpToast && (
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: 16 }}
          className="fixed bottom-8 right-8 z-50 ui-card ui-card-elevated border-l-[3px] border-l-warning"
          role="alertdialog"
          aria-labelledby="levelup-title"
          aria-describedby="levelup-description"
          aria-live="polite"
        >
          <div className="flex flex-col gap-1 min-w-[280px] pr-8">
            <button
              type="button"
              onClick={dismissLevelUpToast}
              className="absolute top-1 right-1 p-2 rounded-[var(--radius-sm)] text-muted-foreground hover:text-foreground"
              aria-label="Dismiss level up notification"
            >
              <X className="w-4 h-4" aria-hidden="true" />
            </button>

            <p className="font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground">
              Clearance raised
            </p>
            <h3 id="levelup-title" className="text-h3 text-warning">
              Level Up!
            </h3>
            <p
              id="levelup-description"
              className="text-body-sm text-muted-foreground"
            >
              You are now a{" "}
              <span className="text-foreground font-bold">Level {level}</span>{" "}
              Operator.
            </p>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};
