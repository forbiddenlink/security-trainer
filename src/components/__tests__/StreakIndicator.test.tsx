import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { StreakIndicator } from "../StreakIndicator";
import { useGameStore } from "../../store/gameStore";

// Mock framer-motion
vi.mock("framer-motion", () => ({
  motion: {
    div: ({
      children,
      ...props
    }: {
      children?: React.ReactNode;
      [key: string]: unknown;
    }) => <div {...props}>{children}</div>,
  },
}));

describe("StreakIndicator", () => {
  const setupStore = (streakDays: number) => {
    useGameStore.setState({
      streakDays,
      getStreakMultiplier: () => 1 + Math.min(streakDays, 7) * 0.1,
    });
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("Rendering", () => {
    it("returns null when streak is 0", () => {
      setupStore(0);
      const { container } = render(<StreakIndicator />);
      expect(container.firstChild).toBeNull();
    });

    it("renders when streak is at least 1", () => {
      setupStore(1);
      render(<StreakIndicator />);

      expect(screen.getByText("1")).toBeInTheDocument();
    });

    it("shows correct streak day count", () => {
      setupStore(5);
      render(<StreakIndicator />);

      expect(screen.getByText("5")).toBeInTheDocument();
    });
  });

  describe("XP Bonus Display", () => {
    it("shows 10% bonus for 1-day streak", () => {
      setupStore(1);
      render(<StreakIndicator />);

      expect(screen.getByText("+10%")).toBeInTheDocument();
    });

    it("shows 50% bonus for 5-day streak", () => {
      setupStore(5);
      render(<StreakIndicator />);

      expect(screen.getByText("+50%")).toBeInTheDocument();
    });

    it("shows 70% max bonus for 7+ day streak", () => {
      setupStore(10);
      render(<StreakIndicator />);

      expect(screen.getByText("+70%")).toBeInTheDocument();
    });
  });

  describe("Accessibility", () => {
    it("has screen reader text describing streak and bonus", () => {
      setupStore(3);
      render(<StreakIndicator />);

      expect(
        screen.getByText("3-day streak with 30% XP bonus"),
      ).toBeInTheDocument();
    });

    it("has descriptive title attribute", () => {
      setupStore(5);
      render(<StreakIndicator />);

      const indicator = screen.getByTitle("5-day streak! +50% XP bonus");
      expect(indicator).toBeInTheDocument();
    });

    it("hides flame icon from screen readers", () => {
      setupStore(1);
      const { container } = render(<StreakIndicator />);

      const flameIcon = container.querySelector('[aria-hidden="true"]');
      expect(flameIcon).toBeInTheDocument();
    });
  });
});
