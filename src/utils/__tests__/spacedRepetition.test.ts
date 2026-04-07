import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  getTodayString,
  addDays,
  daysBetween,
  createInitialReview,
  calculateNextReview,
  getLessonsDueForReview,
  getNextUpcomingReview,
  getDaysOverdue,
  formatReviewDue,
  REVIEW_XP_REWARDS,
} from "../spacedRepetition";
import type { LessonReview } from "../../types";

describe("spacedRepetition (FSRS)", () => {
  describe("getTodayString", () => {
    it("returns date in ISO format without time", () => {
      const result = getTodayString();
      expect(result).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    });
  });

  describe("addDays", () => {
    it("adds positive days to a date", () => {
      expect(addDays("2026-01-01", 5)).toBe("2026-01-06");
    });

    it("adds days across month boundary", () => {
      expect(addDays("2026-01-30", 5)).toBe("2026-02-04");
    });

    it("handles negative days", () => {
      expect(addDays("2026-01-10", -3)).toBe("2026-01-07");
    });
  });

  describe("daysBetween", () => {
    it("calculates positive difference", () => {
      expect(daysBetween("2026-01-01", "2026-01-10")).toBe(9);
    });

    it("calculates negative difference", () => {
      expect(daysBetween("2026-01-10", "2026-01-01")).toBe(-9);
    });

    it("returns 0 for same date", () => {
      expect(daysBetween("2026-01-15", "2026-01-15")).toBe(0);
    });
  });

  describe("createInitialReview", () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2026-02-28"));
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("creates review with correct lesson ID", () => {
      const review = createInitialReview("lesson-1");
      expect(review.lessonId).toBe("lesson-1");
    });

    it("sets next review to 1 day from now", () => {
      const review = createInitialReview("lesson-1");
      expect(review.nextReviewDate).toBe("2026-03-01");
    });

    it("initializes with default ease factor for backward compatibility", () => {
      const review = createInitialReview("lesson-1");
      expect(review.easeFactor).toBe(2.5);
    });

    it("initializes with review count of 0", () => {
      const review = createInitialReview("lesson-1");
      expect(review.reviewCount).toBe(0);
    });

    it("initializes with interval of 1", () => {
      const review = createInitialReview("lesson-1");
      expect(review.interval).toBe(1);
    });

    it("includes FSRS-specific fields", () => {
      const review = createInitialReview("lesson-1");
      expect(review.stability).toBeDefined();
      expect(review.difficulty).toBeDefined();
    });
  });

  describe("calculateNextReview", () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2026-02-28"));
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    const baseReview: LessonReview = {
      lessonId: "test-lesson",
      lastReviewDate: "2026-02-27",
      nextReviewDate: "2026-02-28",
      interval: 1,
      easeFactor: 2.5,
      reviewCount: 0,
      stability: 1,
      difficulty: 5,
      reps: 0,
      lapses: 0,
      state: 0, // New
    };

    it("schedules shorter interval for hard rating", () => {
      const reviewAfterGood = calculateNextReview(baseReview, "good");
      const reviewAfterHard = calculateNextReview(baseReview, "hard");
      // Hard should have shorter interval than good
      expect(reviewAfterHard.interval).toBeLessThanOrEqual(
        reviewAfterGood.interval,
      );
    });

    it("increments review count", () => {
      const result = calculateNextReview(baseReview, "good");
      expect(result.reviewCount).toBeGreaterThan(baseReview.reviewCount);
    });

    it("schedules longer interval for easy rating", () => {
      const reviewAfterGood = calculateNextReview(baseReview, "good");
      const reviewAfterEasy = calculateNextReview(baseReview, "easy");
      // Easy should have longer or equal interval compared to good
      expect(reviewAfterEasy.interval).toBeGreaterThanOrEqual(
        reviewAfterGood.interval,
      );
    });

    it("increases stability after successful reviews", () => {
      const result = calculateNextReview(baseReview, "good");
      expect(result.stability).toBeGreaterThan(baseReview.stability ?? 0);
    });

    it("resets or reduces progress for hard reviews", () => {
      // Create a review that's been reviewed several times
      const advancedReview: LessonReview = {
        ...baseReview,
        interval: 14,
        reviewCount: 5,
        stability: 14,
        reps: 5,
        state: 2, // Review state
      };

      const result = calculateNextReview(advancedReview, "hard");
      // Hard should reduce interval significantly
      expect(result.interval).toBeLessThan(advancedReview.interval);
    });

    it("tracks lapses for hard reviews", () => {
      const reviewWithHistory: LessonReview = {
        ...baseReview,
        reviewCount: 3,
        reps: 3,
        state: 2, // Review state
        lapses: 0,
      };

      const result = calculateNextReview(reviewWithHistory, "hard");
      // FSRS tracks lapses when user forgets
      expect(result.lapses).toBeGreaterThanOrEqual(reviewWithHistory.lapses ?? 0);
    });

    it("updates last review date to today", () => {
      const result = calculateNextReview(baseReview, "good");
      expect(result.lastReviewDate).toBe("2026-02-28");
    });

    it("sets next review date in the future", () => {
      const result = calculateNextReview(baseReview, "good");
      expect(result.nextReviewDate >= "2026-02-28").toBe(true);
    });

    it("handles legacy SM-2 reviews without FSRS fields", () => {
      const legacyReview: LessonReview = {
        lessonId: "legacy-lesson",
        lastReviewDate: "2026-02-27",
        nextReviewDate: "2026-02-28",
        interval: 7,
        easeFactor: 2.6,
        reviewCount: 3,
        // No FSRS fields - testing backward compatibility
      };

      const result = calculateNextReview(legacyReview, "good");
      expect(result.lessonId).toBe("legacy-lesson");
      expect(result.stability).toBeDefined();
      expect(result.difficulty).toBeDefined();
    });
  });

  describe("getLessonsDueForReview", () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2026-02-28"));
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("returns empty array when no reviews exist", () => {
      expect(getLessonsDueForReview({})).toEqual([]);
    });

    it("returns reviews that are due today", () => {
      const reviews: Record<string, LessonReview> = {
        "lesson-1": {
          lessonId: "lesson-1",
          lastReviewDate: "2026-02-27",
          nextReviewDate: "2026-02-28",
          interval: 1,
          easeFactor: 2.5,
          reviewCount: 1,
        },
      };
      const result = getLessonsDueForReview(reviews);
      expect(result).toHaveLength(1);
      expect(result[0].lessonId).toBe("lesson-1");
    });

    it("returns overdue reviews", () => {
      const reviews: Record<string, LessonReview> = {
        "lesson-1": {
          lessonId: "lesson-1",
          lastReviewDate: "2026-02-20",
          nextReviewDate: "2026-02-25",
          interval: 5,
          easeFactor: 2.5,
          reviewCount: 2,
        },
      };
      const result = getLessonsDueForReview(reviews);
      expect(result).toHaveLength(1);
    });

    it("excludes future reviews", () => {
      const reviews: Record<string, LessonReview> = {
        "lesson-1": {
          lessonId: "lesson-1",
          lastReviewDate: "2026-02-28",
          nextReviewDate: "2026-03-01",
          interval: 1,
          easeFactor: 2.5,
          reviewCount: 1,
        },
      };
      expect(getLessonsDueForReview(reviews)).toEqual([]);
    });

    it("sorts by most overdue first", () => {
      const reviews: Record<string, LessonReview> = {
        "lesson-1": {
          lessonId: "lesson-1",
          lastReviewDate: "2026-02-26",
          nextReviewDate: "2026-02-27",
          interval: 1,
          easeFactor: 2.5,
          reviewCount: 1,
        },
        "lesson-2": {
          lessonId: "lesson-2",
          lastReviewDate: "2026-02-20",
          nextReviewDate: "2026-02-25",
          interval: 5,
          easeFactor: 2.5,
          reviewCount: 2,
        },
      };
      const result = getLessonsDueForReview(reviews);
      expect(result[0].lessonId).toBe("lesson-2");
      expect(result[1].lessonId).toBe("lesson-1");
    });
  });

  describe("getNextUpcomingReview", () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2026-02-28"));
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("returns null when no reviews exist", () => {
      expect(getNextUpcomingReview({})).toBeNull();
    });

    it("returns null when all reviews are due or overdue", () => {
      const reviews: Record<string, LessonReview> = {
        "lesson-1": {
          lessonId: "lesson-1",
          lastReviewDate: "2026-02-27",
          nextReviewDate: "2026-02-28",
          interval: 1,
          easeFactor: 2.5,
          reviewCount: 1,
        },
      };
      expect(getNextUpcomingReview(reviews)).toBeNull();
    });

    it("returns the soonest upcoming review", () => {
      const reviews: Record<string, LessonReview> = {
        "lesson-1": {
          lessonId: "lesson-1",
          lastReviewDate: "2026-02-28",
          nextReviewDate: "2026-03-05",
          interval: 7,
          easeFactor: 2.5,
          reviewCount: 2,
        },
        "lesson-2": {
          lessonId: "lesson-2",
          lastReviewDate: "2026-02-28",
          nextReviewDate: "2026-03-01",
          interval: 1,
          easeFactor: 2.5,
          reviewCount: 1,
        },
      };
      const result = getNextUpcomingReview(reviews);
      expect(result?.lessonId).toBe("lesson-2");
    });
  });

  describe("getDaysOverdue", () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2026-02-28"));
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("returns 0 for reviews due today", () => {
      const review: LessonReview = {
        lessonId: "test",
        lastReviewDate: "2026-02-27",
        nextReviewDate: "2026-02-28",
        interval: 1,
        easeFactor: 2.5,
        reviewCount: 1,
      };
      expect(getDaysOverdue(review)).toBe(0);
    });

    it("returns 0 for future reviews", () => {
      const review: LessonReview = {
        lessonId: "test",
        lastReviewDate: "2026-02-28",
        nextReviewDate: "2026-03-05",
        interval: 7,
        easeFactor: 2.5,
        reviewCount: 1,
      };
      expect(getDaysOverdue(review)).toBe(0);
    });

    it("returns positive days for overdue reviews", () => {
      const review: LessonReview = {
        lessonId: "test",
        lastReviewDate: "2026-02-20",
        nextReviewDate: "2026-02-25",
        interval: 5,
        easeFactor: 2.5,
        reviewCount: 1,
      };
      expect(getDaysOverdue(review)).toBe(3);
    });
  });

  describe("formatReviewDue", () => {
    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(new Date("2026-02-28"));
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("formats due today", () => {
      const review: LessonReview = {
        lessonId: "test",
        lastReviewDate: "2026-02-27",
        nextReviewDate: "2026-02-28",
        interval: 1,
        easeFactor: 2.5,
        reviewCount: 1,
      };
      expect(formatReviewDue(review)).toBe("Due today");
    });

    it("formats due tomorrow", () => {
      const review: LessonReview = {
        lessonId: "test",
        lastReviewDate: "2026-02-28",
        nextReviewDate: "2026-03-01",
        interval: 1,
        easeFactor: 2.5,
        reviewCount: 1,
      };
      expect(formatReviewDue(review)).toBe("Due tomorrow");
    });

    it("formats due in X days", () => {
      const review: LessonReview = {
        lessonId: "test",
        lastReviewDate: "2026-02-28",
        nextReviewDate: "2026-03-05",
        interval: 7,
        easeFactor: 2.5,
        reviewCount: 1,
      };
      expect(formatReviewDue(review)).toBe("Due in 5 days");
    });

    it("formats 1 day overdue", () => {
      const review: LessonReview = {
        lessonId: "test",
        lastReviewDate: "2026-02-26",
        nextReviewDate: "2026-02-27",
        interval: 1,
        easeFactor: 2.5,
        reviewCount: 1,
      };
      expect(formatReviewDue(review)).toBe("1 day overdue");
    });

    it("formats X days overdue", () => {
      const review: LessonReview = {
        lessonId: "test",
        lastReviewDate: "2026-02-20",
        nextReviewDate: "2026-02-25",
        interval: 5,
        easeFactor: 2.5,
        reviewCount: 1,
      };
      expect(formatReviewDue(review)).toBe("3 days overdue");
    });
  });

  describe("REVIEW_XP_REWARDS", () => {
    it("has correct XP values", () => {
      expect(REVIEW_XP_REWARDS.hard).toBe(10);
      expect(REVIEW_XP_REWARDS.good).toBe(15);
      expect(REVIEW_XP_REWARDS.easy).toBe(20);
    });
  });
});
