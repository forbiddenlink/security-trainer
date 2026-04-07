import React, { useMemo } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import {
  RefreshCw,
  CheckCircle,
  AlertTriangle,
  ArrowLeft,
  Clock,
  BookOpen,
} from "lucide-react";
import { Card } from "../components/ui";
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

interface ReviewCardProps {
  review: LessonReview;
  index: number;
}

const ReviewCard: React.FC<ReviewCardProps> = ({ review, index }) => {
  const info = getLessonInfo(review.lessonId);
  if (!info) return null;

  const daysOverdue = getDaysOverdue(review);
  const isOverdue = daysOverdue > 0;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.05 }}
      className={`ui-card p-4 ${
        isOverdue
          ? "border-destructive/30 bg-destructive/5"
          : "border-warning/30 bg-warning/5"
      }`}
      role="listitem"
    >
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <BookOpen
              className="w-4 h-4 text-muted-foreground shrink-0"
              aria-hidden="true"
            />
            <p className="text-sm text-muted-foreground truncate">
              {info.module.title}
            </p>
          </div>
          <h3 className="font-semibold text-lg truncate">
            {info.lesson.title}
          </h3>
          <div className="flex items-center gap-4 mt-2 text-sm text-muted-foreground">
            <span className="flex items-center gap-1">
              <Clock className="w-3.5 h-3.5" aria-hidden="true" />
              {review.reviewCount} reviews
            </span>
            {review.stability !== undefined ? (
              <span>Stability: {Math.round(review.stability)}d</span>
            ) : (
              <span>Ease: {(review.easeFactor * 100).toFixed(0)}%</span>
            )}
          </div>
        </div>
        <div className="flex flex-col items-end gap-2 shrink-0">
          <span
            className={`flex items-center gap-1.5 text-sm font-medium ${
              isOverdue ? "text-destructive" : "text-warning"
            }`}
          >
            {isOverdue ? (
              <AlertTriangle className="w-4 h-4" aria-hidden="true" />
            ) : (
              <Clock className="w-4 h-4" aria-hidden="true" />
            )}
            {formatReviewDue(review)}
          </span>
          <Link
            to={`/modules/${info.module.id}/${info.lesson.id}?review=true`}
            className="inline-flex h-9 items-center justify-center gap-1.5 rounded-[var(--radius-sm)] bg-primary px-4 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary-hover"
          >
            Review Now
          </Link>
        </div>
      </div>
    </motion.div>
  );
};

export const Reviews: React.FC = () => {
  const { getReviewsDue, getNextReview, lessonReviews } = useGameStore();

  const reviewsDue = useMemo(() => getReviewsDue(), [getReviewsDue]);
  const nextReview = useMemo(() => getNextReview(), [getNextReview]);

  const overdueCount = reviewsDue.filter((r) => getDaysOverdue(r) > 0).length;
  const totalReviews = Object.keys(lessonReviews).length;

  return (
    <div className="container max-w-4xl mx-auto px-4 py-8">
      {/* Header */}
      <div className="mb-8">
        <Link
          to="/"
          className="inline-flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors mb-4"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Dashboard
        </Link>
        <div className="flex items-center gap-4">
          <div
            className={`h-12 w-12 grid place-items-center rounded-lg ${
              overdueCount > 0
                ? "bg-destructive/10 text-destructive"
                : "bg-primary/10 text-primary"
            }`}
          >
            <RefreshCw className="w-6 h-6" aria-hidden="true" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">
              Intel Refresher
            </h1>
            <p className="text-muted-foreground">
              {reviewsDue.length > 0 ? (
                <>
                  {reviewsDue.length} lesson{reviewsDue.length !== 1 ? "s" : ""}{" "}
                  due for review
                  {overdueCount > 0 && (
                    <span className="text-destructive">
                      {" "}
                      ({overdueCount} overdue)
                    </span>
                  )}
                </>
              ) : (
                "All intel is fresh, Agent"
              )}
            </p>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
        <Card className="p-4 text-center">
          <p className="text-2xl font-bold text-primary">{totalReviews}</p>
          <p className="text-sm text-muted-foreground">Total Tracked</p>
        </Card>
        <Card className="p-4 text-center">
          <p className="text-2xl font-bold text-warning">{reviewsDue.length}</p>
          <p className="text-sm text-muted-foreground">Due Now</p>
        </Card>
        <Card className="p-4 text-center">
          <p className="text-2xl font-bold text-destructive">{overdueCount}</p>
          <p className="text-sm text-muted-foreground">Overdue</p>
        </Card>
        <Card className="p-4 text-center">
          <p className="text-2xl font-bold text-accent">
            {totalReviews - reviewsDue.length}
          </p>
          <p className="text-sm text-muted-foreground">Up to Date</p>
        </Card>
      </div>

      {/* Reviews List */}
      {reviewsDue.length > 0 ? (
        <div
          className="space-y-3"
          role="list"
          aria-label="Lessons due for review"
        >
          {reviewsDue.map((review, index) => (
            <ReviewCard key={review.lessonId} review={review} index={index} />
          ))}
        </div>
      ) : nextReview ? (
        <Card className="p-8 text-center">
          <CheckCircle
            className="w-12 h-12 text-accent mx-auto mb-4"
            aria-hidden="true"
          />
          <h2 className="text-xl font-semibold mb-2">All Caught Up!</h2>
          <p className="text-muted-foreground mb-4">
            No reviews due right now. Your next review is scheduled for{" "}
            <span className="font-medium text-foreground">
              {formatReviewDue(nextReview).toLowerCase()}
            </span>
            .
          </p>
          <Link
            to="/"
            className="inline-flex h-10 items-center justify-center gap-2 rounded-[var(--radius-sm)] bg-primary px-6 font-medium text-primary-foreground transition-colors hover:bg-primary-hover"
          >
            Continue Learning
          </Link>
        </Card>
      ) : (
        <Card className="p-8 text-center">
          <BookOpen
            className="w-12 h-12 text-muted-foreground mx-auto mb-4"
            aria-hidden="true"
          />
          <h2 className="text-xl font-semibold mb-2">No Reviews Yet</h2>
          <p className="text-muted-foreground mb-4">
            Complete some lessons to start building your review schedule.
          </p>
          <Link
            to="/modules"
            className="inline-flex h-10 items-center justify-center gap-2 rounded-[var(--radius-sm)] bg-primary px-6 font-medium text-primary-foreground transition-colors hover:bg-primary-hover"
          >
            Browse Modules
          </Link>
        </Card>
      )}
    </div>
  );
};
