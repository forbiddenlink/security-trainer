import {
  createEmptyCard,
  fsrs,
  generatorParameters,
  Rating,
  type Card,
  type Grade,
} from "ts-fsrs";
import type { LessonReview } from "../types";

// ============================================
// FSRS SPACED REPETITION ALGORITHM
// ============================================
// FSRS (Free Spaced Repetition Scheduler) provides ~150% better
// retention compared to SM-2 through optimized interval scheduling.

/** FSRS scheduler instance with optimized parameters */
const fsrsParams = generatorParameters({
  enable_fuzz: true, // Add small random variance to prevent clustering
  enable_short_term: true, // Enable learning steps for new cards
  maximum_interval: 365, // Cap at 1 year (vs 60 days with SM-2)
});
const scheduler = fsrs(fsrsParams);

/** Review quality ratings mapped to FSRS grades */
export type ReviewQuality = "hard" | "good" | "easy";

/** Map our UI quality to FSRS Rating enum */
const QUALITY_TO_RATING: Record<ReviewQuality, Grade> = {
  hard: Rating.Again,
  good: Rating.Good,
  easy: Rating.Easy,
};

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
 * Convert FSRS Card to our LessonReview format for persistence
 */
function cardToLessonReview(lessonId: string, card: Card): LessonReview {
  const dueDate = card.due instanceof Date ? card.due : new Date(card.due);
  const lastReview = card.last_review
    ? card.last_review instanceof Date
      ? card.last_review
      : new Date(card.last_review)
    : new Date();

  return {
    lessonId,
    lastReviewDate: lastReview.toISOString().split("T")[0],
    nextReviewDate: dueDate.toISOString().split("T")[0],
    interval: Math.round(card.scheduled_days),
    // Store FSRS-specific fields for accurate scheduling
    stability: card.stability,
    difficulty: card.difficulty,
    reps: card.reps,
    lapses: card.lapses,
    state: card.state,
    // Legacy fields for backward compatibility
    easeFactor: 2.5,
    reviewCount: card.reps,
  };
}

/**
 * Convert our LessonReview back to FSRS Card format
 */
function lessonReviewToCard(review: LessonReview): Card {
  // Check if this is a new FSRS-migrated review or legacy SM-2
  if (review.stability !== undefined && review.difficulty !== undefined) {
    // FSRS card - restore full state
    return {
      due: new Date(review.nextReviewDate),
      stability: review.stability,
      difficulty: review.difficulty,
      elapsed_days: 0,
      scheduled_days: review.interval,
      reps: review.reps ?? review.reviewCount,
      lapses: review.lapses ?? 0,
      learning_steps: 0,
      state: review.state ?? 0,
      last_review: new Date(review.lastReviewDate),
    };
  }

  // Legacy SM-2 review - migrate to FSRS format
  // Create a card with approximate state based on SM-2 data
  const now = new Date();
  const card = createEmptyCard(now);

  // If they've reviewed before, we need to simulate that history
  if (review.reviewCount > 0) {
    // Approximate stability based on SM-2 ease factor and interval
    // Higher ease factor and longer intervals = more stable memory
    const approxStability = review.interval * (review.easeFactor / 2.5);

    return {
      ...card,
      due: new Date(review.nextReviewDate),
      stability: Math.max(1, approxStability),
      difficulty: Math.max(1, Math.min(10, 5 - (review.easeFactor - 2.5) * 2)),
      scheduled_days: review.interval,
      reps: review.reviewCount,
      lapses: 0,
      state: 2, // Review state
      last_review: new Date(review.lastReviewDate),
    };
  }

  // Brand new card
  return {
    ...card,
    due: new Date(review.nextReviewDate),
  };
}

/**
 * Create initial review entry for a newly completed lesson
 */
export function createInitialReview(lessonId: string): LessonReview {
  const now = new Date();
  const card = createEmptyCard(now);

  // New cards are due for first review in 1 minute (learning phase)
  // But for our UI, we'll set it to tomorrow for simplicity
  const tomorrow = new Date(now);
  tomorrow.setDate(tomorrow.getDate() + 1);

  const initialCard: Card = {
    ...card,
    due: tomorrow,
    scheduled_days: 1,
  };

  return cardToLessonReview(lessonId, initialCard);
}

/**
 * Calculate the next review using FSRS algorithm
 *
 * FSRS provides optimized scheduling through:
 * - Memory stability tracking (how long until 90% forgetting probability)
 * - Difficulty estimation per card
 * - Optimal interval calculation based on desired retention
 */
export function calculateNextReview(
  currentReview: LessonReview,
  quality: ReviewQuality,
): LessonReview {
  const now = new Date();
  const card = lessonReviewToCard(currentReview);
  const rating = QUALITY_TO_RATING[quality];

  // Use FSRS to calculate next state
  const { card: nextCard } = scheduler.next(card, now, rating);

  return cardToLessonReview(currentReview.lessonId, nextCard);
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
