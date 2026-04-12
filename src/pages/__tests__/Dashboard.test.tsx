import { describe, it, expect, beforeEach, vi } from "vitest";
import { screen } from "@testing-library/react";
import {
  renderWithRouter,
  resetGameStore,
  setupGameStore,
} from "../../test/testUtils";
import { Dashboard } from "../Dashboard";

// Mock framer-motion to avoid animation issues in tests
vi.mock("framer-motion", () => ({
  motion: {
    div: ({ children, ...props }: { children?: React.ReactNode }) => (
      <div {...props}>{children}</div>
    ),
  },
}));

describe("Dashboard", () => {
  beforeEach(() => {
    resetGameStore();
  });

  describe("rendering", () => {
    it("renders the welcome message", () => {
      setupGameStore({ userRole: "developer" });
      renderWithRouter(<Dashboard />);

      expect(screen.getByText("Welcome back, Agent.")).toBeInTheDocument();
    });

    it("displays the current XP", () => {
      setupGameStore({ xp: 500, userRole: "developer" });

      renderWithRouter(<Dashboard />);

      // XP value and label are in separate elements
      expect(screen.getByText("500")).toBeInTheDocument();
      expect(screen.getByText("XP")).toBeInTheDocument();
    });

    it("displays the current level", () => {
      setupGameStore({ level: 3, userRole: "developer" });

      renderWithRouter(<Dashboard />);

      expect(screen.getByText("Level 3")).toBeInTheDocument();
    });

    it("calculates XP needed for next level correctly", () => {
      // At level 2 with 500 XP, need 2000 total, so 1500 remaining
      setupGameStore({ level: 2, xp: 500, userRole: "developer" });

      renderWithRouter(<Dashboard />);

      expect(screen.getByText("1500 XP to next level")).toBeInTheDocument();
    });

    it("displays number of completed modules", () => {
      setupGameStore({ completedModules: ["owasp-intro", "sql-injection"], userRole: "developer" });

      renderWithRouter(<Dashboard />);

      expect(screen.getByText("2")).toBeInTheDocument();
    });
  });

  describe("current module display", () => {
    it('shows "None assigned" when no module is set', () => {
      setupGameStore({ currentModuleId: null, userRole: "developer" });

      renderWithRouter(<Dashboard />);

      expect(screen.getByText("None assigned")).toBeInTheDocument();
    });

    it("shows current module title when a module is active", () => {
      setupGameStore({ currentModuleId: "owasp-intro", userRole: "developer" });

      renderWithRouter(<Dashboard />);

      // Multiple elements may contain the title, check at least one exists
      expect(
        screen.getAllByText("Introduction to OWASP").length,
      ).toBeGreaterThan(0);
    });
  });

  describe("navigation links", () => {
    it("has a link to resume training", () => {
      setupGameStore({ userRole: "developer" });
      renderWithRouter(<Dashboard />);

      const resumeLink = screen.getByRole("link", { name: /resume training/i });
      expect(resumeLink).toHaveAttribute("href", "/modules");
    });

    it("has a link to view all achievements", () => {
      setupGameStore({ userRole: "developer" });
      renderWithRouter(<Dashboard />);

      const viewAllLink = screen.getByRole("link", { name: /view all/i });
      expect(viewAllLink).toHaveAttribute("href", "/profile");
    });
  });

  describe("badges section", () => {
    it("renders the badges section with heading", () => {
      setupGameStore({ userRole: "developer" });
      renderWithRouter(<Dashboard />);

      expect(screen.getByText("Achievements")).toBeInTheDocument();
    });
  });

  describe("stat cards", () => {
    it("displays the Current Score card", () => {
      setupGameStore({ userRole: "developer" });
      renderWithRouter(<Dashboard />);

      expect(screen.getByText("Current Score")).toBeInTheDocument();
    });

    it("displays the Missions Complete card", () => {
      setupGameStore({ userRole: "developer" });
      renderWithRouter(<Dashboard />);

      expect(screen.getByText("Missions Complete")).toBeInTheDocument();
    });

    it("displays the Active Mission card", () => {
      setupGameStore({ userRole: "developer" });
      renderWithRouter(<Dashboard />);

      expect(screen.getByText("Active Mission")).toBeInTheDocument();
    });
  });
});
