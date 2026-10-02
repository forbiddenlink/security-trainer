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
    circle: (props: React.SVGProps<SVGCircleElement>) => <circle {...props} />,
  },
  AnimatePresence: ({ children }: { children?: React.ReactNode }) => (
    <>{children}</>
  ),
}));

describe("Dashboard", () => {
  beforeEach(() => {
    resetGameStore();
  });

  describe("new visitor", () => {
    it("shows the hero and a first-mission link into lesson one", () => {
      renderWithRouter(<Dashboard />);

      expect(
        screen.getByRole("heading", { level: 1, name: /break it here/i }),
      ).toBeInTheDocument();
      const start = screen.getByRole("link", { name: /start mission 01/i });
      expect(start).toHaveAttribute("href", "/modules/owasp-intro/owasp-1");
    });

    it("targets the first module of the role's recommended path", () => {
      setupGameStore({ userRole: "devops" });
      renderWithRouter(<Dashboard />);

      const start = screen.getByRole("link", { name: /start mission/i });
      expect(start.getAttribute("href")).toMatch(
        /^\/modules\/cloud-security\//,
      );
    });

    it("offers role calibration as toggle buttons", () => {
      renderWithRouter(<Dashboard />);

      expect(
        screen.getByRole("button", { name: "Developer", pressed: false }),
      ).toBeInTheDocument();
    });
  });

  describe("returning learner", () => {
    it("renders the welcome message", () => {
      setupGameStore({ xp: 100 });
      renderWithRouter(<Dashboard />);

      expect(screen.getByText("Welcome back, Agent.")).toBeInTheDocument();
    });

    it("shows XP, XP to next level and missions as readouts", () => {
      setupGameStore({
        level: 2,
        xp: 500,
        completedModules: ["owasp-intro", "sql-injection"],
      });
      renderWithRouter(<Dashboard />);

      expect(screen.getByText("500")).toBeInTheDocument();
      expect(screen.getByText("1500")).toBeInTheDocument();
      expect(screen.getByText("To L3")).toBeInTheDocument();
      expect(screen.getByText(/^2\/\d+$/)).toBeInTheDocument();
    });

    it("resumes the active module at its next unfinished lesson", () => {
      setupGameStore({
        xp: 50,
        currentModuleId: "sql-injection",
        completedLessons: ["sqli-theory"],
      });
      renderWithRouter(<Dashboard />);

      const resume = screen.getByRole("link", {
        name: /continue sql injection/i,
      });
      expect(resume).toHaveAttribute(
        "href",
        "/modules/sql-injection/sqli-quiz-1",
      );
      expect(
        screen.getByRole("progressbar", { name: /1 of 6 lessons/i }),
      ).toBeInTheDocument();
    });

    it("has a link to view all achievements", () => {
      setupGameStore({ xp: 10 });
      renderWithRouter(<Dashboard />);

      expect(
        screen.getByRole("link", { name: /view all achievements/i }),
      ).toHaveAttribute("href", "/profile");
    });

    it("renders the achievements section heading", () => {
      setupGameStore({ xp: 10 });
      renderWithRouter(<Dashboard />);

      expect(
        screen.getByRole("heading", { name: "Achievements" }),
      ).toBeInTheDocument();
    });
  });
});
