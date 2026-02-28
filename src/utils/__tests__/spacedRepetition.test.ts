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

describe("spacedRepetition", () => {
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

    it("initializes with default ease factor of 2.5", () => {
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
    };

    it("resets interval to 1 for hard rating", () => {
      const result = calculateNextReview(
        { ...baseReview, interval: 7, reviewCount: 3 },
        "hard",
      );
      expect(result.interval).toBe(1);
    });

    it("increments review count", () => {
      const result = calculateNextReview(baseReview, "good");
      expect(result.reviewCount).toBe(1);
    });

    it("sets interval to 3 for second review", () => {
      const result = calculateNextReview(
        { ...baseReview, reviewCount: 1 },
        "good",
      );
      expect(result.interval).toBe(3);
    });

    it("sets interval to 7 for third review", () => {
      const result = calculateNextReview(
        { ...baseReview, reviewCount: 2 },
        "good",
      );
      expect(result.interval).toBe(7);
    });

    it("applies easy bonus multiplier", () => {
      const result = calculateNextReview(
        { ...baseReview, reviewCount: 3, interval: 7 },
        "easy",
      );
      // Interval should be greater due to easy bonus
      expect(result.interval).toBeGreaterThan(7);
    });

    it("caps interval at 60 days", () => {
      const result = calculateNextReview(
        { ...baseReview, reviewCount: 10, interval: 50, easeFactor: 2.5 },
        "easy",
      );
      expect(result.interval).toBeLessThanOrEqual(60);
    });

    it("decreases ease factor for hard reviews", () => {
      const result = calculateNextReview(baseReview, "hard");
      expect(result.easeFactor).toBeLessThan(2.5);
    });

    it("increases ease factor for easy reviews", () => {
      const result = calculateNextReview(baseReview, "easy");
      expect(result.easeFactor).toBeGreaterThan(2.5);
    });

    it("maintains minimum ease factor of 1.3", () => {
      const lowEaseReview = { ...baseReview, easeFactor: 1.35 };
      const result = calculateNextReview(lowEaseReview, "hard");
      expect(result.easeFactor).toBeGreaterThanOrEqual(1.3);
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
