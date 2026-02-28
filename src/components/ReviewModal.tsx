import React from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, Brain, Frown, Meh, Smile } from "lucide-react";
import { useGameStore } from "../store/gameStore";
import {
  REVIEW_XP_REWARDS,
  type ReviewQuality,
} from "../utils/spacedRepetition";

interface ReviewModalProps {
  isOpen: boolean;
  onClose: () => void;
  lessonId: string;
  lessonTitle: string;
}

interface RatingButtonProps {
  quality: ReviewQuality;
  icon: React.ReactNode;
  label: string;
  description: string;
  xp: number;
  colorClass: string;
  onClick: () => void;
}

const RatingButton: React.FC<RatingButtonProps> = ({
  icon,
  label,
  description,
  xp,
  colorClass,
  onClick,
}) => (
  <button
    onClick={onClick}
    className={`flex-1 flex flex-col items-center gap-2 p-4 rounded-lg border-2 transition-all hover:scale-105 ${colorClass}`}
  >
    <div className="w-10 h-10 rounded-full flex items-center justify-center bg-current/10">
      {icon}
    </div>
    <span className="font-semibold">{label}</span>
    <span className="text-xs text-muted-foreground">{description}</span>
    <span className="text-sm font-medium">+{xp} XP</span>
  </button>
);

export const ReviewModal: React.FC<ReviewModalProps> = ({
  isOpen,
  onClose,
  lessonId,
  lessonTitle,
}) => {
  const { markLessonReviewed } = useGameStore();

  const handleRating = (quality: ReviewQuality) => {
    markLessonReviewed(lessonId, quality);
    onClose();
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50"
            onClick={onClose}
            aria-hidden="true"
          />

          {/* Modal */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            transition={{ type: "spring", damping: 25, stiffness: 300 }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
          >
            <div
              className="w-full max-w-lg ui-card ui-card-elevated p-6 relative"
              role="dialog"
              aria-modal="true"
              aria-labelledby="review-modal-title"
            >
              {/* Close button */}
              <button
                onClick={onClose}
                className="absolute top-4 right-4 p-2 rounded-full hover:bg-muted/50 transition-colors"
                aria-label="Close review modal"
              >
                <X className="w-5 h-5" />
              </button>

              {/* Header */}
              <div className="flex items-center gap-3 mb-6">
                <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center">
                  <Brain className="w-6 h-6 text-primary" />
                </div>
                <div>
                  <h2 id="review-modal-title" className="text-h3">
                    Mission Debrief
                  </h2>
                  <p className="text-sm text-muted-foreground">
                    How well do you remember this intel?
                  </p>
                </div>
              </div>

              {/* Lesson info */}
              <div className="bg-muted/30 rounded-lg p-4 mb-6">
                <p className="text-sm text-muted-foreground mb-1">Reviewing:</p>
                <p className="font-semibold">{lessonTitle}</p>
              </div>

              {/* Rating buttons */}
              <div className="flex gap-3">
                <RatingButton
                  quality="hard"
                  icon={<Frown className="w-5 h-5 text-destructive" />}
                  label="Hard"
                  description="Struggled to recall"
                  xp={REVIEW_XP_REWARDS.hard}
                  colorClass="border-destructive/30 hover:border-destructive hover:bg-destructive/5 text-destructive"
                  onClick={() => handleRating("hard")}
                />
                <RatingButton
                  quality="good"
                  icon={<Meh className="w-5 h-5 text-warning" />}
                  label="Good"
                  description="Recalled with effort"
                  xp={REVIEW_XP_REWARDS.good}
                  colorClass="border-warning/30 hover:border-warning hover:bg-warning/5 text-warning"
                  onClick={() => handleRating("good")}
                />
                <RatingButton
                  quality="easy"
                  icon={<Smile className="w-5 h-5 text-accent" />}
                  label="Easy"
                  description="Instantly recalled"
                  xp={REVIEW_XP_REWARDS.easy}
                  colorClass="border-accent/30 hover:border-accent hover:bg-accent/5 text-accent"
                  onClick={() => handleRating("easy")}
                />
              </div>

              {/* Skip option */}
              <button
                onClick={onClose}
                className="w-full mt-4 py-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
              >
                Skip for now
              </button>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
};
