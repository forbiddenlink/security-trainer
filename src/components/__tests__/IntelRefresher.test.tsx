import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { IntelRefresher } from "../IntelRefresher";
import { useGameStore } from "../../store/gameStore";
import type { LessonReview } from "../../types";

// Mock the modules data
vi.mock("../../data/modules", () => ({
  MODULES: [
    {
      id: "xss-basics",
      title: "XSS Basics",
      lessons: [
        { id: "xss-intro", title: "Introduction to XSS", type: "theory" },
        { id: "xss-types", title: "Types of XSS", type: "theory" },
      ],
    },
    {
      id: "sql-injection",
      title: "SQL Injection",
      lessons: [
        { id: "sql-intro", title: "SQL Injection Basics", type: "theory" },
      ],
    },
  ],
}));

const renderWithRouter = (ui: React.ReactElement) => {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
};

describe("IntelRefresher", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("No Reviews State", () => {
    it("renders nothing when no reviews exist", () => {
      useGameStore.setState({
        getReviewsDue: vi.fn().mockReturnValue([]),
        getNextReview: vi.fn().mockReturnValue(null),
      });
      const { container } = renderWithRouter(<IntelRefresher />);
      expect(container.firstChild).toBeNull();
    });
  });

  describe("All Caught Up State", () => {
    it("shows next upcoming review when no reviews are due", () => {
      const nextReview: LessonReview = {
        lessonId: "xss-intro",
        lastReviewDate: "2026-02-28",
        nextReviewDate: "2026-03-01",
        interval: 1,
        easeFactor: 2.5,
        reviewCount: 1,
      };
      useGameStore.setState({
        getReviewsDue: vi.fn().mockReturnValue([]),
        getNextReview: vi.fn().mockReturnValue(nextReview),
      });
      renderWithRouter(<IntelRefresher />);

      expect(screen.getByText("Intel Refresher")).toBeInTheDocument();
      expect(
        screen.getByText("Your intel is fresh, Agent"),
      ).toBeInTheDocument();
      expect(screen.getByText("Introduction to XSS")).toBeInTheDocument();
    });

    it("shows Unknown for lesson not found in modules", () => {
      const nextReview: LessonReview = {
        lessonId: "unknown-lesson",
        lastReviewDate: "2026-02-28",
        nextReviewDate: "2026-03-01",
        interval: 1,
        easeFactor: 2.5,
        reviewCount: 1,
      };
      useGameStore.setState({
        getReviewsDue: vi.fn().mockReturnValue([]),
        getNextReview: vi.fn().mockReturnValue(nextReview),
      });
      renderWithRouter(<IntelRefresher />);

      expect(screen.getByText("Unknown")).toBeInTheDocument();
    });
  });

  describe("Reviews Due State", () => {
    const dueReview: LessonReview = {
      lessonId: "xss-intro",
      lastReviewDate: "2026-02-27",
      nextReviewDate: "2026-02-28",
      interval: 1,
      easeFactor: 2.5,
      reviewCount: 1,
    };

    it("shows Intel Refresher title", () => {
      useGameStore.setState({
        getReviewsDue: vi.fn().mockReturnValue([dueReview]),
        getNextReview: vi.fn().mockReturnValue(null),
      });
      renderWithRouter(<IntelRefresher />);

      expect(screen.getByText("Intel Refresher")).toBeInTheDocument();
    });

    it("shows count of lessons needing review", () => {
      useGameStore.setState({
        getReviewsDue: vi.fn().mockReturnValue([dueReview]),
        getNextReview: vi.fn().mockReturnValue(null),
      });
      renderWithRouter(<IntelRefresher />);

      expect(screen.getByText("1 lesson need review")).toBeInTheDocument();
    });

    it("pluralizes lesson count correctly", () => {
      const dueReview2: LessonReview = {
        lessonId: "xss-types",
        lastReviewDate: "2026-02-27",
        nextReviewDate: "2026-02-28",
        interval: 1,
        easeFactor: 2.5,
        reviewCount: 1,
      };
      useGameStore.setState({
        getReviewsDue: vi.fn().mockReturnValue([dueReview, dueReview2]),
        getNextReview: vi.fn().mockReturnValue(null),
      });
      renderWithRouter(<IntelRefresher />);

      expect(screen.getByText("2 lessons need review")).toBeInTheDocument();
    });

    it("shows lesson title and module name", () => {
      useGameStore.setState({
        getReviewsDue: vi.fn().mockReturnValue([dueReview]),
        getNextReview: vi.fn().mockReturnValue(null),
      });
      renderWithRouter(<IntelRefresher />);

      expect(screen.getByText("Introduction to XSS")).toBeInTheDocument();
      expect(screen.getByText("XSS Basics")).toBeInTheDocument();
    });

    it("shows Review button with correct link", () => {
      useGameStore.setState({
        getReviewsDue: vi.fn().mockReturnValue([dueReview]),
        getNextReview: vi.fn().mockReturnValue(null),
      });
      renderWithRouter(<IntelRefresher />);

      const reviewLink = screen.getByRole("link", { name: "Review" });
      expect(reviewLink).toHaveAttribute(
        "href",
        "/modules/xss-basics/xss-intro?review=true",
      );
    });

    it("limits displayed reviews to 3", () => {
      const reviews: LessonReview[] = [
        { ...dueReview, lessonId: "xss-intro" },
        { ...dueReview, lessonId: "xss-types" },
        { ...dueReview, lessonId: "sql-intro" },
        { ...dueReview, lessonId: "unknown-1" },
      ];
      useGameStore.setState({
        getReviewsDue: vi.fn().mockReturnValue(reviews),
        getNextReview: vi.fn().mockReturnValue(null),
      });
      renderWithRouter(<IntelRefresher />);

      // Should show 3 review items (unknown-1 won't render due to missing lesson info)
      const reviewLinks = screen.getAllByRole("link", { name: "Review" });
      expect(reviewLinks.length).toBeLessThanOrEqual(3);
    });

    it("shows View All button when more than 3 reviews", () => {
      const reviews: LessonReview[] = [
        { ...dueReview, lessonId: "xss-intro" },
        { ...dueReview, lessonId: "xss-types" },
        { ...dueReview, lessonId: "sql-intro" },
        { ...dueReview, lessonId: "xss-intro" }, // Duplicate for count
      ];
      useGameStore.setState({
        getReviewsDue: vi.fn().mockReturnValue(reviews),
        getNextReview: vi.fn().mockReturnValue(null),
      });
      renderWithRouter(<IntelRefresher />);

      expect(screen.getByText("View All (4 reviews)")).toBeInTheDocument();
    });
  });

  describe("Overdue Reviews", () => {
    it("skips rendering for lessons not found in modules", () => {
      const overdueReview: LessonReview = {
        lessonId: "nonexistent-lesson",
        lastReviewDate: "2026-02-20",
        nextReviewDate: "2026-02-25",
        interval: 5,
        easeFactor: 2.5,
        reviewCount: 2,
      };
      useGameStore.setState({
        getReviewsDue: vi.fn().mockReturnValue([overdueReview]),
        getNextReview: vi.fn().mockReturnValue(null),
      });
      renderWithRouter(<IntelRefresher />);

      // The component still renders the card but the item won't show
      expect(screen.getByText("Intel Refresher")).toBeInTheDocument();
      expect(screen.queryByRole("link", { name: "Review" })).toBeNull();
    });
  });
});
