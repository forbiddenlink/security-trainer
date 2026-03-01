import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ThemeToggle } from "../ThemeToggle";
import { useThemeStore } from "../../store/themeStore";

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
  AnimatePresence: ({ children }: { children?: React.ReactNode }) => (
    <>{children}</>
  ),
}));

describe("ThemeToggle", () => {
  const mockSetTheme = vi.fn();

  const setupStore = (theme: "light" | "dark" | "system") => {
    useThemeStore.setState({
      theme,
      setTheme: mockSetTheme,
    });
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("Rendering", () => {
    it("renders light mode icon when theme is light", () => {
      setupStore("light");
      render(<ThemeToggle />);

      const button = screen.getByRole("button");
      expect(button).toHaveAttribute("title", "Theme: light");
    });

    it("renders dark mode icon when theme is dark", () => {
      setupStore("dark");
      render(<ThemeToggle />);

      const button = screen.getByRole("button");
      expect(button).toHaveAttribute("title", "Theme: dark");
    });

    it("renders system mode icon when theme is system", () => {
      setupStore("system");
      render(<ThemeToggle />);

      const button = screen.getByRole("button");
      expect(button).toHaveAttribute("title", "Theme: system");
    });
  });

  describe("Theme Cycling", () => {
    it("cycles from light to dark on click", async () => {
      setupStore("light");
      const user = userEvent.setup();
      render(<ThemeToggle />);

      await user.click(screen.getByRole("button"));

      expect(mockSetTheme).toHaveBeenCalledWith("dark");
    });

    it("cycles from dark to system on click", async () => {
      setupStore("dark");
      const user = userEvent.setup();
      render(<ThemeToggle />);

      await user.click(screen.getByRole("button"));

      expect(mockSetTheme).toHaveBeenCalledWith("system");
    });

    it("cycles from system to light on click", async () => {
      setupStore("system");
      const user = userEvent.setup();
      render(<ThemeToggle />);

      await user.click(screen.getByRole("button"));

      expect(mockSetTheme).toHaveBeenCalledWith("light");
    });
  });

  describe("Accessibility", () => {
    it("has descriptive aria-label for light theme", () => {
      setupStore("light");
      render(<ThemeToggle />);

      const button = screen.getByRole("button");
      expect(button).toHaveAttribute(
        "aria-label",
        "Light mode. Click to switch to dark mode.",
      );
    });

    it("has descriptive aria-label for dark theme", () => {
      setupStore("dark");
      render(<ThemeToggle />);

      const button = screen.getByRole("button");
      expect(button).toHaveAttribute(
        "aria-label",
        "Dark mode. Click to switch to system preference.",
      );
    });

    it("has descriptive aria-label for system theme", () => {
      setupStore("system");
      render(<ThemeToggle />);

      const button = screen.getByRole("button");
      expect(button).toHaveAttribute(
        "aria-label",
        "System preference. Click to switch to light mode.",
      );
    });
  });
});
