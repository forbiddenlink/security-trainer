import type React from "react";
import { useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ChevronsUp, X } from "lucide-react";
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
          className="fixed bottom-8 right-8 z-50 ui-card ui-card-elevated border-l-[3px] border-l-warning pr-10 min-w-[280px] max-w-sm"
          role="alertdialog"
          aria-labelledby="levelup-title"
          aria-describedby="levelup-description"
          aria-live="polite"
        >
          <button
            type="button"
            onClick={dismissLevelUpToast}
            className="absolute top-1 right-1 p-2 rounded-[var(--radius-sm)] text-muted-foreground hover:text-foreground"
            aria-label="Dismiss level up notification"
          >
            <X className="w-4 h-4" aria-hidden="true" />
          </button>

          <div className="flex items-start gap-3">
            <span
              className="grid h-9 w-9 shrink-0 place-items-center rounded-[var(--radius-xs)] border border-warning/40 bg-warning/10 text-warning"
              aria-hidden="true"
            >
              <ChevronsUp className="w-5 h-5" />
            </span>
            <div className="min-w-0 flex-1">
              <p className="font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground">
                Clearance raised
              </p>
              <h3 id="levelup-title" className="text-h3 text-warning mt-0.5">
                Level Up!
              </h3>
              <p
                id="levelup-description"
                className="text-body-sm text-muted-foreground mt-0.5"
              >
                You are now a{" "}
                <span className="text-foreground font-bold">Level {level}</span>{" "}
                Operator.
              </p>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};
