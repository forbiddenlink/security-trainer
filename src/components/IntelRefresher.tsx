import React, { useMemo } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import {
  RefreshCw,
  CheckCircle,
  AlertTriangle,
  ArrowRight,
} from "lucide-react";
import { Card } from "./ui";
import { useGameStore } from "../store/gameStore";
import { MODULES } from "../data/modules";
import { formatReviewDue, getDaysOverdue } from "../utils/spacedRepetition";
import type { LessonReview } from "../types";

/**
 * Find lesson and module info from a lesson ID
 */
function getLessonInfo(lessonId: string): {
  lesson: { id: string; title: string };
  module: { id: string; title: string };
} | null {
  for (const module of MODULES) {
    const lesson = module.lessons.find((l) => l.id === lessonId);
    if (lesson) {
      return {
        lesson: { id: lesson.id, title: lesson.title },
        module: { id: module.id, title: module.title },
      };
    }
  }
  return null;
}

interface ReviewItemProps {
  review: LessonReview;
}

const ReviewItem: React.FC<ReviewItemProps> = ({ review }) => {
  const info = getLessonInfo(review.lessonId);
  if (!info) return null;

  const daysOverdue = getDaysOverdue(review);
  const isOverdue = daysOverdue > 0;

  return (
    <div className="flex items-center justify-between gap-4 p-3 bg-background/50 rounded-lg">
      <div className="flex-1 min-w-0">
        <p className="text-sm text-muted-foreground truncate">
          {info.module.title}
        </p>
        <p className="font-medium truncate">{info.lesson.title}</p>
      </div>
      <div className="flex items-center gap-3 shrink-0">
        <span
          className={`text-xs font-medium ${
            isOverdue ? "text-destructive" : "text-warning"
          }`}
        >
          {formatReviewDue(review)}
        </span>
        <Link
          to={`/modules/${info.module.id}/${info.lesson.id}?review=true`}
          className="inline-flex h-8 items-center justify-center gap-1.5 rounded-[var(--radius-sm)] bg-primary px-3 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary-hover"
        >
          Review
        </Link>
      </div>
    </div>
  );
};

export const IntelRefresher: React.FC = () => {
  const { getReviewsDue, getNextReview } = useGameStore();

  const reviewsDue = useMemo(() => getReviewsDue(), [getReviewsDue]);
  const nextReview = useMemo(() => getNextReview(), [getNextReview]);

  // Show max 3 items in the dashboard preview
  const displayedReviews = reviewsDue.slice(0, 3);
  const hasMoreReviews = reviewsDue.length > 3;

  // Don't render if no reviews exist yet
  const hasAnyReviews = reviewsDue.length > 0 || nextReview !== null;
  if (!hasAnyReviews) {
    return null;
  }

  // Empty state - no reviews due
  if (reviewsDue.length === 0 && nextReview) {
    const nextInfo = getLessonInfo(nextReview.lessonId);

    return (
      <Card className="p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="h-9 w-9 grid place-items-center rounded-[var(--radius-sm)] bg-accent/10 text-accent">
            <CheckCircle className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-lg font-semibold tracking-tight">
              Intel Refresher
            </h3>
            <p className="text-xs text-muted-foreground">
              Your intel is fresh, Agent
            </p>
          </div>
        </div>
        <p className="text-muted-foreground text-sm">
          No reviews due. Next review:{" "}
          <span className="font-medium text-foreground">
            {nextInfo?.lesson.title || "Unknown"}
          </span>{" "}
          {formatReviewDue(nextReview).toLowerCase()}
        </p>
      </Card>
    );
  }

  // Has reviews due
  const overdueCount = reviewsDue.filter((r) => getDaysOverdue(r) > 0).length;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className={`ui-card relative overflow-hidden p-6 ${
        overdueCount > 0
          ? "bg-linear-to-br from-destructive/10 to-destructive/5 border-destructive/30"
          : "bg-linear-to-br from-primary/10 to-primary/5 border-primary/30"
      }`}
    >
      {/* Decorative glow */}
      <div
        className={`absolute -top-10 -right-10 w-32 h-32 blur-3xl rounded-full pointer-events-none ${
          overdueCount > 0 ? "bg-red-500/20" : "bg-primary/20"
        }`}
      />

      <div className="relative z-10">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div
              className={`h-9 w-9 grid place-items-center rounded-[var(--radius-sm)] ${
                overdueCount > 0
                  ? "bg-destructive/10 text-destructive"
                  : "bg-primary/10 text-primary"
              }`}
            >
              {overdueCount > 0 ? (
                <AlertTriangle className="w-5 h-5" />
              ) : (
                <RefreshCw className="w-5 h-5" />
              )}
            </div>
            <div>
              <h3 className="text-lg font-semibold tracking-tight">
                Intel Refresher
              </h3>
              <p className="text-xs text-muted-foreground">
                {reviewsDue.length} lesson{reviewsDue.length !== 1 ? "s" : ""}{" "}
                {reviewsDue.length === 1 ? "needs" : "need"} review
              </p>
            </div>
          </div>
        </div>

        <div className="space-y-2 mb-4">
          {displayedReviews.map((review) => (
            <ReviewItem key={review.lessonId} review={review} />
          ))}
        </div>

        {hasMoreReviews && (
          <Link
            to="/reviews"
            className="group inline-flex h-10 w-full items-center justify-center gap-2 rounded-[var(--radius-sm)] bg-muted px-4 font-medium text-foreground transition-colors hover:bg-muted/80"
          >
            View All ({reviewsDue.length} reviews)
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </Link>
        )}
      </div>
    </motion.div>
  );
};
