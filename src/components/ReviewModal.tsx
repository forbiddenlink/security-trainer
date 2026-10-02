import React from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, Frown, Meh, Smile } from "lucide-react";
import { useGameStore } from "../store/gameStore";
import { useFocusTrap } from "../utils/useFocusTrap";
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
    type="button"
    onClick={onClick}
    className={`flex-1 flex flex-col items-start gap-1.5 p-4 rounded-[var(--radius-sm)] border text-left transition-colors ${colorClass}`}
  >
    {icon}
    <span className="font-semibold">{label}</span>
    <span className="text-xs text-muted-foreground">{description}</span>
    <span className="font-mono text-[11px] uppercase tracking-[0.12em]">
      +{xp} XP
    </span>
  </button>
);

export const ReviewModal: React.FC<ReviewModalProps> = ({
  isOpen,
  onClose,
  lessonId,
  lessonTitle,
}) => {
  const { markLessonReviewed } = useGameStore();

  // Focus trap for accessibility
  const modalRef = useFocusTrap<HTMLDivElement>(isOpen, onClose);

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
            className="fixed inset-0 bg-background/80 z-50"
            onClick={onClose}
            aria-hidden="true"
          />

          {/* Modal */}
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 6 }}
            transition={{ duration: 0.2, ease: [0.25, 1, 0.5, 1] }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
          >
            <div
              ref={modalRef}
              className="w-full max-w-lg ui-card ui-card-lg ui-card-elevated relative"
              role="dialog"
              aria-modal="true"
              aria-labelledby="review-modal-title"
            >
              {/* Close button */}
              <button
                type="button"
                onClick={onClose}
                className="absolute top-4 right-4 p-2 rounded-[var(--radius-sm)] text-muted-foreground hover:text-foreground transition-colors"
                aria-label="Close review modal"
              >
                <X className="w-5 h-5" />
              </button>

              {/* Header */}
              <div className="mb-5 pb-4 border-b border-border pr-10">
                <p className="ui-label mb-2">Spaced review</p>
                <h2
                  id="review-modal-title"
                  className="font-display [font-stretch:75%] font-extrabold text-h3"
                >
                  Mission Debrief
                </h2>
                <p className="text-body-sm text-muted-foreground mt-1">
                  How well do you remember this intel?
                </p>
              </div>

              {/* Lesson info */}
              <div className="border-l-[3px] border-border pl-4 mb-6">
                <p className="ui-label mb-1">Reviewing:</p>
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
                  colorClass="border-border hover:border-destructive text-destructive"
                  onClick={() => handleRating("hard")}
                />
                <RatingButton
                  quality="good"
                  icon={<Meh className="w-5 h-5 text-warning" />}
                  label="Good"
                  description="Recalled with effort"
                  xp={REVIEW_XP_REWARDS.good}
                  colorClass="border-border hover:border-warning text-warning"
                  onClick={() => handleRating("good")}
                />
                <RatingButton
                  quality="easy"
                  icon={<Smile className="w-5 h-5 text-accent" />}
                  label="Easy"
                  description="Instantly recalled"
                  xp={REVIEW_XP_REWARDS.easy}
                  colorClass="border-border hover:border-accent text-accent"
                  onClick={() => handleRating("easy")}
                />
              </div>

              {/* Skip option */}
              <button
                type="button"
                onClick={onClose}
                className="btn-ghost-rule w-full mt-4 !h-10 text-sm text-muted-foreground hover:text-foreground transition-colors"
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
