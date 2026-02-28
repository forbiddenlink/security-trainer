import type { LessonReview } from "../types";

// ============================================
// SM-2 SPACED REPETITION ALGORITHM
// ============================================

/** Default ease factor for new cards */
const DEFAULT_EASE_FACTOR = 2.5;

/** Minimum ease factor to prevent intervals from shrinking too much */
const MIN_EASE_FACTOR = 1.3;

/** Maximum interval in days (cap at 60 days) */
const MAX_INTERVAL_DAYS = 60;

/** Review quality ratings */
export type ReviewQuality = "hard" | "good" | "easy";

/** XP rewards for each review quality */
export const REVIEW_XP_REWARDS: Record<ReviewQuality, number> = {
  hard: 10,
  good: 15,
  easy: 20,
};

/**
 * Get today's date as ISO string (date only, no time)
 */
export function getTodayString(): string {
  return new Date().toISOString().split("T")[0];
}

/**
 * Add days to a date and return ISO date string
 */
export function addDays(dateString: string, days: number): string {
  const date = new Date(dateString);
  date.setDate(date.getDate() + days);
  return date.toISOString().split("T")[0];
}

/**
 * Calculate days between two date strings
 */
export function daysBetween(date1: string, date2: string): number {
  const d1 = new Date(date1);
  const d2 = new Date(date2);
  const diffTime = d2.getTime() - d1.getTime();
  return Math.floor(diffTime / (1000 * 60 * 60 * 24));
}

/**
 * Create initial review entry for a newly completed lesson
 */
export function createInitialReview(lessonId: string): LessonReview {
  const today = getTodayString();
  return {
    lessonId,
    lastReviewDate: today,
    nextReviewDate: addDays(today, 1), // First review in 1 day
    interval: 1,
    easeFactor: DEFAULT_EASE_FACTOR,
    reviewCount: 0,
  };
}

/**
 * Calculate the next review based on SM-2 algorithm
 *
 * SM-2 Algorithm:
 * - If quality < 3 (hard): reset interval to 1
 * - If quality >= 3: interval = interval * easeFactor
 * - Ease factor adjusts based on quality
 */
export function calculateNextReview(
  currentReview: LessonReview,
  quality: ReviewQuality,
): LessonReview {
  const today = getTodayString();
  let newInterval: number;
  let newEaseFactor = currentReview.easeFactor;

  // Convert quality to numeric (SM-2 uses 0-5 scale)
  const qualityNum = quality === "hard" ? 1 : quality === "good" ? 3 : 5;

  // Adjust ease factor based on quality
  // EF' = EF + (0.1 - (5 - q) * (0.08 + (5 - q) * 0.02))
  newEaseFactor =
    newEaseFactor + (0.1 - (5 - qualityNum) * (0.08 + (5 - qualityNum) * 0.02));
  newEaseFactor = Math.max(MIN_EASE_FACTOR, newEaseFactor);

  if (quality === "hard") {
    // Reset to 1 day for hard reviews
    newInterval = 1;
  } else if (currentReview.reviewCount === 0) {
    // First review after initial learning
    newInterval = 1;
  } else if (currentReview.reviewCount === 1) {
    // Second review
    newInterval = 3;
  } else if (currentReview.reviewCount === 2) {
    // Third review
    newInterval = 7;
  } else {
    // Subsequent reviews: interval * easeFactor
    newInterval = Math.round(currentReview.interval * newEaseFactor);
  }

  // Apply easy bonus
  if (quality === "easy") {
    newInterval = Math.round(newInterval * 1.3);
  }

  // Cap at maximum interval
  newInterval = Math.min(newInterval, MAX_INTERVAL_DAYS);

  return {
    lessonId: currentReview.lessonId,
    lastReviewDate: today,
    nextReviewDate: addDays(today, newInterval),
    interval: newInterval,
    easeFactor: newEaseFactor,
    reviewCount: currentReview.reviewCount + 1,
  };
}

/**
 * Get all lessons that are due for review (nextReviewDate <= today)
 */
export function getLessonsDueForReview(
  reviews: Record<string, LessonReview>,
): LessonReview[] {
  const today = getTodayString();

  return Object.values(reviews)
    .filter((review) => review.nextReviewDate <= today)
    .sort((a, b) => {
      // Sort by most overdue first
      return a.nextReviewDate.localeCompare(b.nextReviewDate);
    });
}

/**
 * Get the next upcoming review (not yet due)
 */
export function getNextUpcomingReview(
  reviews: Record<string, LessonReview>,
): LessonReview | null {
  const today = getTodayString();

  const upcoming = Object.values(reviews)
    .filter((review) => review.nextReviewDate > today)
    .sort((a, b) => a.nextReviewDate.localeCompare(b.nextReviewDate));

  return upcoming[0] || null;
}

/**
 * Calculate how many days overdue a review is
 * Returns 0 if not overdue, positive number if overdue
 */
export function getDaysOverdue(review: LessonReview): number {
  const today = getTodayString();
  const days = daysBetween(review.nextReviewDate, today);
  return Math.max(0, days);
}

/**
 * Format days until review as human-readable string
 */
export function formatReviewDue(review: LessonReview): string {
  const today = getTodayString();
  const daysUntil = daysBetween(today, review.nextReviewDate);

  if (daysUntil < 0) {
    const overdue = Math.abs(daysUntil);
    return overdue === 1 ? "1 day overdue" : `${overdue} days overdue`;
  } else if (daysUntil === 0) {
    return "Due today";
  } else if (daysUntil === 1) {
    return "Due tomorrow";
  } else {
    return `Due in ${daysUntil} days`;
  }
}
