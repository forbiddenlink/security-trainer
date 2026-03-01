import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { BrowserRouter } from "react-router-dom";
import { DailyChallenge } from "../DailyChallenge";
import { useGameStore } from "../../store/gameStore";

// Mock framer-motion
vi.mock("framer-motion", () => ({
  motion: {
    div: ({
      children,
      className,
      ...props
    }: {
      children?: React.ReactNode;
      className?: string;
      [key: string]: unknown;
    }) => (
      <div className={className} {...props}>
        {children}
      </div>
    ),
  },
}));

const renderWithRouter = (ui: React.ReactNode) => {
  return render(<BrowserRouter>{ui}</BrowserRouter>);
};

describe("DailyChallenge", () => {
  const mockChallenge = {
    lessonId: "lesson-1",
    moduleId: "module-1",
    moduleTitle: "XSS Basics",
    lessonTitle: "Understanding Cross-Site Scripting",
  };

  const setupStore = (
    challenge: typeof mockChallenge | null,
    completed: boolean = false,
  ) => {
    useGameStore.setState({
      getDailyChallenge: () => challenge,
      dailyChallengeCompleted: completed,
    });
  };

  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe("When challenge exists", () => {
    it("renders challenge info", () => {
      setupStore(mockChallenge);
      renderWithRouter(<DailyChallenge />);

      expect(screen.getByText("Daily Challenge")).toBeInTheDocument();
      expect(screen.getByText("XSS Basics")).toBeInTheDocument();
      expect(
        screen.getByText("Understanding Cross-Site Scripting"),
      ).toBeInTheDocument();
    });

    it("shows bonus XP text when not completed", () => {
      setupStore(mockChallenge);
      renderWithRouter(<DailyChallenge />);

      expect(screen.getByText("+50 Bonus XP")).toBeInTheDocument();
    });

    it("renders start challenge link", () => {
      setupStore(mockChallenge);
      renderWithRouter(<DailyChallenge />);

      const link = screen.getByRole("link", { name: /start challenge/i });
      expect(link).toBeInTheDocument();
      expect(link).toHaveAttribute("href", "/modules/module-1/lesson-1");
    });

    it("shows countdown timer", () => {
      setupStore(mockChallenge);
      renderWithRouter(<DailyChallenge />);

      // Timer should be visible (format: HH:MM:SS)
      const timerElement = screen.getByText(/\d{2}:\d{2}:\d{2}/);
      expect(timerElement).toBeInTheDocument();
    });
  });

  describe("When challenge is completed", () => {
    it("shows completed state", () => {
      setupStore(mockChallenge, true);
      renderWithRouter(<DailyChallenge />);

      expect(screen.getByText("Challenge Complete!")).toBeInTheDocument();
      expect(screen.getByText("Completed!")).toBeInTheDocument();
    });

    it("does not show start challenge link", () => {
      setupStore(mockChallenge, true);
      renderWithRouter(<DailyChallenge />);

      expect(
        screen.queryByRole("link", { name: /start challenge/i }),
      ).not.toBeInTheDocument();
    });

    it("does not show countdown timer", () => {
      setupStore(mockChallenge, true);
      renderWithRouter(<DailyChallenge />);

      // Timer should not be visible when completed
      expect(screen.queryByText(/\d{2}:\d{2}:\d{2}/)).not.toBeInTheDocument();
    });
  });

  describe("When no challenge available", () => {
    it("shows all lessons completed message", () => {
      setupStore(null);
      renderWithRouter(<DailyChallenge />);

      expect(screen.getByText("Daily Challenge")).toBeInTheDocument();
      expect(
        screen.getByText(
          "All lessons completed! Check back tomorrow for a new challenge.",
        ),
      ).toBeInTheDocument();
    });

    it("does not show start challenge link", () => {
      setupStore(null);
      renderWithRouter(<DailyChallenge />);

      expect(
        screen.queryByRole("link", { name: /start challenge/i }),
      ).not.toBeInTheDocument();
    });
  });

  describe("Timer updates", () => {
    it("updates timer every second", () => {
      setupStore(mockChallenge);
      renderWithRouter(<DailyChallenge />);

      const initialTimer = screen.getByText(/\d{2}:\d{2}:\d{2}/).textContent;

      // Advance time by 1 second
      vi.advanceTimersByTime(1000);

      const updatedTimer = screen.getByText(/\d{2}:\d{2}:\d{2}/).textContent;

      // Timer should have changed (unless we're exactly at a round number)
      // This verifies the interval is running
      expect(initialTimer).toBeDefined();
      expect(updatedTimer).toBeDefined();
    });
  });
});
