import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { BadgeList } from "../BadgeList";
import { useGameStore } from "../../store/gameStore";
import { BADGES } from "../../data/badges";

describe("BadgeList", () => {
  const setupStore = (unlockedBadges: string[]) => {
    useGameStore.setState({
      badges: unlockedBadges,
    });
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("Rendering", () => {
    it("renders all badges", () => {
      setupStore([]);
      render(<BadgeList />);

      const badgeList = screen.getByRole("list", {
        name: "Achievement badges",
      });
      expect(badgeList).toBeInTheDocument();

      // Check that all badges are rendered
      BADGES.forEach((badge) => {
        expect(screen.getByText(badge.name)).toBeInTheDocument();
      });
    });

    it("shows badge descriptions", () => {
      setupStore([]);
      render(<BadgeList />);

      BADGES.forEach((badge) => {
        expect(screen.getByText(badge.description)).toBeInTheDocument();
      });
    });
  });

  describe("Badge States", () => {
    it("shows unlocked state for earned badges", () => {
      const unlockedBadgeId = BADGES[0].id;
      setupStore([unlockedBadgeId]);
      render(<BadgeList />);

      const badge = screen.getByLabelText(
        `${BADGES[0].name}: Unlocked - ${BADGES[0].description}`,
      );
      expect(badge).toBeInTheDocument();
      expect(badge).toHaveClass("bg-primary/10");
    });

    it("shows locked state for unearned badges", () => {
      setupStore([]);
      render(<BadgeList />);

      const badge = screen.getByLabelText(
        `${BADGES[0].name}: Locked - ${BADGES[0].description}`,
      );
      expect(badge).toBeInTheDocument();
      expect(badge).toHaveClass("opacity-65");
    });

    it("correctly handles multiple unlocked badges", () => {
      const unlockedIds = BADGES.slice(0, 3).map((b) => b.id);
      setupStore(unlockedIds);
      render(<BadgeList />);

      // First 3 badges should be unlocked
      unlockedIds.forEach((id) => {
        const badge = BADGES.find((b) => b.id === id)!;
        const element = screen.getByLabelText(
          `${badge.name}: Unlocked - ${badge.description}`,
        );
        expect(element).toHaveClass("bg-primary/10");
      });
    });
  });

  describe("Accessibility", () => {
    it("has accessible list role", () => {
      setupStore([]);
      render(<BadgeList />);

      expect(
        screen.getByRole("list", { name: "Achievement badges" }),
      ).toBeInTheDocument();
    });

    it("has aria-label on each badge item", () => {
      setupStore([]);
      render(<BadgeList />);

      BADGES.forEach((badge) => {
        const label = `${badge.name}: Locked - ${badge.description}`;
        expect(screen.getByLabelText(label)).toBeInTheDocument();
      });
    });

    it("hides decorative icons from screen readers", () => {
      setupStore([]);
      const { container } = render(<BadgeList />);

      const hiddenIcons = container.querySelectorAll('[aria-hidden="true"]');
      expect(hiddenIcons.length).toBeGreaterThan(0);
    });

    it("provides screen reader text for unlock condition", () => {
      const unlockedBadgeId = BADGES[0].id;
      setupStore([unlockedBadgeId]);
      render(<BadgeList />);

      expect(screen.getByText("Unlocked")).toBeInTheDocument();
    });
  });
});
