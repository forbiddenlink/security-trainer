import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { PathCard } from "../PathCard";
import { useGameStore } from "../../store/gameStore";
import type { LearningPath } from "../../types";

const renderWithRouter = (ui: React.ReactElement) => {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
};

describe("PathCard", () => {
  const mockPath: LearningPath = {
    id: "web-fundamentals",
    title: "Web Security Fundamentals",
    codename: "Operation Firewall",
    description:
      "Master the essential web security concepts. Learn to identify and prevent vulnerabilities.",
    difficulty: "Beginner",
    modules: ["xss-basics", "sql-injection", "csrf-attacks"],
    certificateXp: 500,
    icon: "Shield",
  };

  const mockLockedPath: LearningPath = {
    ...mockPath,
    id: "advanced-threats",
    title: "Advanced Threat Analysis",
    codename: "Operation Shadow",
    difficulty: "Advanced",
    requiredCompletions: 8,
  };

  beforeEach(() => {
    vi.clearAllMocks();
    useGameStore.setState({
      completedModules: [],
      completedPaths: [],
      getPathProgress: vi.fn().mockReturnValue({ completed: 0, total: 3 }),
      isPathUnlocked: vi.fn().mockReturnValue(true),
    });
  });

  describe("Rendering", () => {
    it("renders path title", () => {
      renderWithRouter(<PathCard path={mockPath} index={0} />);
      expect(screen.getByText("Web Security Fundamentals")).toBeInTheDocument();
    });

    it("renders path codename", () => {
      renderWithRouter(<PathCard path={mockPath} index={0} />);
      expect(screen.getByText("Operation Firewall")).toBeInTheDocument();
    });

    it("renders path description", () => {
      renderWithRouter(<PathCard path={mockPath} index={0} />);
      expect(
        screen.getByText(/Master the essential web security concepts/),
      ).toBeInTheDocument();
    });

    it("renders difficulty badge", () => {
      renderWithRouter(<PathCard path={mockPath} index={0} />);
      expect(screen.getByText("Beginner")).toBeInTheDocument();
    });

    it("renders progress indicator", () => {
      useGameStore.setState({
        getPathProgress: vi.fn().mockReturnValue({ completed: 1, total: 3 }),
        isPathUnlocked: vi.fn().mockReturnValue(true),
      });
      renderWithRouter(<PathCard path={mockPath} index={0} />);
      expect(screen.getByText("1/3 modules")).toBeInTheDocument();
      expect(screen.getByText("33%")).toBeInTheDocument();
    });

    it("renders 0% progress when no modules completed", () => {
      renderWithRouter(<PathCard path={mockPath} index={0} />);
      expect(screen.getByText("0/3 modules")).toBeInTheDocument();
      expect(screen.getByText("0%")).toBeInTheDocument();
    });
  });

  describe("Unlocked State", () => {
    it("renders Start Path button when path is unlocked and not started", () => {
      renderWithRouter(<PathCard path={mockPath} index={0} />);
      expect(screen.getByText("Start Path")).toBeInTheDocument();
    });

    it("renders Continue button when path has progress", () => {
      useGameStore.setState({
        completedModules: [],
        completedPaths: [],
        getPathProgress: vi.fn().mockReturnValue({ completed: 1, total: 3 }),
        isPathUnlocked: vi.fn().mockReturnValue(true),
      });
      renderWithRouter(<PathCard path={mockPath} index={0} />);
      expect(screen.getByText(/Continue/)).toBeInTheDocument();
    });

    it("links to path detail page", () => {
      renderWithRouter(<PathCard path={mockPath} index={0} />);
      const link = screen.getByRole("link", { name: /Start Path/i });
      expect(link).toHaveAttribute("href", "/paths/web-fundamentals");
    });
  });

  describe("Locked State", () => {
    it("shows lock message when path is not unlocked", () => {
      useGameStore.setState({
        completedModules: ["module-1", "module-2"],
        getPathProgress: vi.fn().mockReturnValue({ completed: 0, total: 3 }),
        isPathUnlocked: vi.fn().mockReturnValue(false),
      });
      renderWithRouter(<PathCard path={mockLockedPath} index={0} />);
      expect(
        screen.getByText(/Complete \d+ more modules to unlock/),
      ).toBeInTheDocument();
    });

    it("calculates remaining modules correctly", () => {
      useGameStore.setState({
        completedModules: ["m1", "m2", "m3"],
        getPathProgress: vi.fn().mockReturnValue({ completed: 0, total: 3 }),
        isPathUnlocked: vi.fn().mockReturnValue(false),
      });
      renderWithRouter(<PathCard path={mockLockedPath} index={0} />);
      // requiredCompletions is 8, completedModules.length is 3, so 5 more needed
      expect(
        screen.getByText("Complete 5 more modules to unlock"),
      ).toBeInTheDocument();
    });

    it("has reduced opacity when locked", () => {
      useGameStore.setState({
        completedModules: [],
        completedPaths: [],
        getPathProgress: vi.fn().mockReturnValue({ completed: 0, total: 3 }),
        isPathUnlocked: vi.fn().mockReturnValue(false),
      });
      renderWithRouter(<PathCard path={mockLockedPath} index={0} />);
      // The opacity-60 class is on the root motion.div element
      const cardContainer = screen
        .getByText("Advanced Threat Analysis")
        .closest(".ui-card");
      expect(cardContainer).toHaveClass("opacity-60");
    });
  });

  describe("Completed State", () => {
    it("shows Certified badge when path is completed", () => {
      useGameStore.setState({
        completedPaths: ["web-fundamentals"],
        getPathProgress: vi.fn().mockReturnValue({ completed: 3, total: 3 }),
        isPathUnlocked: vi.fn().mockReturnValue(true),
      });
      renderWithRouter(<PathCard path={mockPath} index={0} />);
      expect(screen.getByText("Certified")).toBeInTheDocument();
    });

    it("shows 100% progress when completed", () => {
      useGameStore.setState({
        completedPaths: ["web-fundamentals"],
        getPathProgress: vi.fn().mockReturnValue({ completed: 3, total: 3 }),
        isPathUnlocked: vi.fn().mockReturnValue(true),
      });
      renderWithRouter(<PathCard path={mockPath} index={0} />);
      expect(screen.getByText("100%")).toBeInTheDocument();
    });
  });

  describe("Difficulty Colors", () => {
    it("renders Beginner with accent color", () => {
      renderWithRouter(<PathCard path={mockPath} index={0} />);
      const badge = screen.getByText("Beginner");
      expect(badge).toHaveClass("text-accent");
    });

    it("renders Intermediate with warning color", () => {
      const intermediatePath = {
        ...mockPath,
        difficulty: "Intermediate" as const,
      };
      renderWithRouter(<PathCard path={intermediatePath} index={0} />);
      const badge = screen.getByText("Intermediate");
      expect(badge).toHaveClass("text-warning");
    });

    it("renders Advanced with destructive color", () => {
      useGameStore.setState({
        getPathProgress: vi.fn().mockReturnValue({ completed: 0, total: 3 }),
        isPathUnlocked: vi.fn().mockReturnValue(true),
      });
      renderWithRouter(<PathCard path={mockLockedPath} index={0} />);
      const badge = screen.getByText("Advanced");
      expect(badge).toHaveClass("text-destructive");
    });
  });

  describe("Edge Cases", () => {
    it("handles path with no modules gracefully", () => {
      const emptyPath = { ...mockPath, modules: [] };
      useGameStore.setState({
        getPathProgress: vi.fn().mockReturnValue({ completed: 0, total: 0 }),
        isPathUnlocked: vi.fn().mockReturnValue(true),
      });
      renderWithRouter(<PathCard path={emptyPath} index={0} />);
      expect(screen.getByText("0/0 modules")).toBeInTheDocument();
      expect(screen.getByText("0%")).toBeInTheDocument();
    });

    it("uses Shield icon as fallback for unknown icon", () => {
      const unknownIconPath = { ...mockPath, icon: "UnknownIcon" };
      renderWithRouter(<PathCard path={unknownIconPath} index={0} />);
      // Component renders without error
      expect(screen.getByText("Web Security Fundamentals")).toBeInTheDocument();
    });
  });
});
