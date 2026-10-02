import React, { useMemo } from "react";
import { Link } from "react-router-dom";
import { clsx } from "clsx";
import {
  RefreshCw,
  CheckCircle,
  AlertTriangle,
  Clock,
  BookOpen,
} from "lucide-react";
import { estimateLessonMinutes, formatMinutes } from "../lib/moduleMeta";
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

  const isOverdue = getDaysOverdue(review) > 0;

  return (
    <li className="grid grid-cols-[2.5rem_minmax(0,1fr)] gap-x-3 gap-y-3 py-5 sm:grid-cols-[2.5rem_minmax(0,1fr)_auto] sm:items-center">
      <span
        className="font-mono text-caption tabular-nums text-muted-foreground pt-1"
        aria-hidden="true"
      >
        {String(index + 1).padStart(2, "0")}
      </span>
      <div className="min-w-0">
        <p className="font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground truncate">
          {info.module.title}
        </p>
        <h3 className="mt-1 text-h4 truncate">{info.lesson.title}</h3>
        <p className="mt-1.5 flex flex-wrap gap-x-3 font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground tabular-nums">
          <span
            className={clsx(
              "flex items-center gap-1",
              isOverdue ? "text-destructive" : "text-warning",
            )}
          >
            {isOverdue ? (
              <AlertTriangle className="w-3.5 h-3.5" aria-hidden="true" />
            ) : (
              <Clock className="w-3.5 h-3.5" aria-hidden="true" />
            )}
            {formatReviewDue(review)}
          </span>
          <span>
            {review.reviewCount} review{review.reviewCount === 1 ? "" : "s"}
          </span>
          <span>
            {review.stability !== undefined
              ? `Stability ${Math.round(review.stability)}d`
              : `Ease ${(review.easeFactor * 100).toFixed(0)}%`}
          </span>
        </p>
      </div>
      <Link
        to={`/modules/${info.module.id}/${info.lesson.id}?review=true`}
        className="col-start-2 sm:col-start-3 btn-ghost-rule justify-self-start"
        aria-label={`Review ${info.lesson.title}`}
      >
        Review Now
      </Link>
    </li>
  );
};

export const Reviews: React.FC = () => {
  const { getReviewsDue, getNextReview, lessonReviews } = useGameStore();

  const reviewsDue = useMemo(() => getReviewsDue(), [getReviewsDue]);
  const nextReview = useMemo(() => getNextReview(), [getNextReview]);

  const overdueCount = reviewsDue.filter((r) => getDaysOverdue(r) > 0).length;
  const totalReviews = Object.keys(lessonReviews).length;
  const firstDue = reviewsDue[0] ? getLessonInfo(reviewsDue[0].lessonId) : null;
  const queueMinutes = reviewsDue.reduce((sum, r) => {
    const lesson = MODULES.flatMap((m) => m.lessons).find(
      (l) => l.id === r.lessonId,
    );
    return sum + (lesson ? estimateLessonMinutes(lesson) : 0);
  }, 0);

  const stats: [string, number, string][] = [
    ["Tracked", totalReviews, ""],
    ["Due now", reviewsDue.length, reviewsDue.length ? "text-warning" : ""],
    ["Overdue", overdueCount, overdueCount ? "text-destructive" : ""],
    ["Fresh", totalReviews - reviewsDue.length, ""],
  ];

  return (
    <div className="space-y-10 max-w-4xl">
      <header className="border-b border-border pb-8">
        <p className="range-readout mb-3">
          <span className="range-dot" aria-hidden="true" />
          Spaced repetition · memory protocol
        </p>
        <h1 className="text-display">Intel Review</h1>
        <p className="mt-4 text-muted-foreground max-w-[60ch]">
          {reviewsDue.length > 0 ? (
            <>
              {reviewsDue.length} lesson
              {reviewsDue.length !== 1 ? "s" : ""} due for review
              {overdueCount > 0 && (
                <span className="text-destructive">
                  {" "}
                  ({overdueCount} overdue)
                </span>
              )}
              . Short reviews at the right moment keep what you learned.
            </>
          ) : totalReviews > 0 ? (
            "All intel is fresh, Agent. Lessons come back here when they are due for a refresher."
          ) : (
            "Finished lessons come back here on a spaced schedule, just before you would forget them."
          )}
        </p>
        {firstDue && (
          <div className="mt-6 flex flex-wrap items-center gap-4">
            <Link
              to={`/modules/${firstDue.module.id}/${firstDue.lesson.id}?review=true`}
              className="btn-signal"
            >
              <RefreshCw className="w-4 h-4" aria-hidden="true" />
              Start review queue
            </Link>
            <p className="font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground tabular-nums">
              About {formatMinutes(queueMinutes)} for {reviewsDue.length} due
            </p>
          </div>
        )}
        {totalReviews > 0 && (
          <dl className="mt-8 grid grid-cols-2 sm:grid-cols-4 gap-6">
            {stats.map(([label, value, tone]) => (
              <div key={label}>
                <dt className="ui-label">{label}</dt>
                <dd
                  className={clsx(
                    "mt-1 font-display text-h1 font-extrabold [font-stretch:75%] tabular-nums leading-none",
                    tone,
                  )}
                >
                  {value}
                </dd>
              </div>
            ))}
          </dl>
        )}
      </header>

      {reviewsDue.length > 0 ? (
        <section aria-labelledby="due-heading">
          <h2 id="due-heading" className="text-h3 mb-2">
            Due for review
          </h2>
          <ol
            className="divide-y divide-border border-y border-border"
            aria-label="Lessons due for review"
          >
            {reviewsDue.map((review, index) => (
              <ReviewCard key={review.lessonId} review={review} index={index} />
            ))}
          </ol>
        </section>
      ) : nextReview ? (
        <section className="border border-dashed border-border rounded-[var(--radius-md)] p-8">
          <CheckCircle
            className="w-6 h-6 text-accent mb-4"
            aria-hidden="true"
          />
          <h2 className="text-h3 mb-2">All Caught Up!</h2>
          <p className="text-muted-foreground mb-6 max-w-[56ch]">
            No reviews due right now. Your next review is scheduled for{" "}
            <span className="font-medium text-foreground">
              {formatReviewDue(nextReview).toLowerCase()}
            </span>
            .
          </p>
          <Link to="/" className="btn-ghost-rule">
            Continue Learning
          </Link>
        </section>
      ) : (
        <section className="border border-dashed border-border rounded-[var(--radius-md)] p-8">
          <BookOpen
            className="w-6 h-6 text-muted-foreground mb-4"
            aria-hidden="true"
          />
          <h2 className="text-h3 mb-2">No Reviews Yet</h2>
          <p className="text-muted-foreground mb-6 max-w-[56ch]">
            Complete some lessons to start building your review schedule. Each
            finished lesson returns here when it is due for a refresher.
          </p>
          <Link to="/modules" className="btn-signal">
            Browse Modules
          </Link>
        </section>
      )}
    </div>
  );
};
