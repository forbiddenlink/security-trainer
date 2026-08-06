import { describe, it, expect, beforeEach, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import {
  renderWithRouter,
  resetGameStore,
  userEvent,
} from "../../test/testUtils";
import { LessonView } from "../LessonView";
import { useGameStore } from "../../store/gameStore";

// Mock framer-motion
vi.mock("framer-motion", () => ({
  motion: {
    div: ({ children, ...props }: { children?: React.ReactNode }) => (
      <div {...props}>{children}</div>
    ),
  },
  AnimatePresence: ({ children }: { children?: React.ReactNode }) => (
    <>{children}</>
  ),
}));

// Mock canvas-confetti
vi.mock("canvas-confetti", () => ({
  default: vi.fn(),
}));

// Mock Monaco Editor to avoid DOM issues
vi.mock("../../components/CodeEditor", () => ({
  CodeEditor: ({
    initialCode,
    onChange,
  }: {
    initialCode: string;
    onChange: (val: string) => void;
  }) => (
    <textarea
      data-testid="code-editor"
      defaultValue={initialCode}
      onChange={(e) => onChange(e.target.value)}
    />
  ),
}));

// Mock react-router-dom with dynamic params
const mockNavigate = vi.fn();
let mockModuleId = "owasp-intro";

vi.mock("react-router-dom", async () => {
  const actual = await vi.importActual("react-router-dom");
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useParams: () => ({ moduleId: mockModuleId }),
  };
});

describe("LessonView", () => {
  beforeEach(() => {
    resetGameStore();
    mockNavigate.mockClear();
    mockModuleId = "owasp-intro";
  });

  describe("module not found", () => {
    it("shows error when module does not exist", () => {
      mockModuleId = "non-existent-module";

      renderWithRouter(<LessonView />);

      expect(screen.getByText("Mission not found")).toBeInTheDocument();
    });
  });

  describe("theory lesson", () => {
    it("renders the module title and lesson title", () => {
      renderWithRouter(<LessonView />);

      expect(screen.getByText("Introduction to OWASP")).toBeInTheDocument();
      // Lesson title appears in header and as markdown h1, so use getAllByText
      const lessonTitles = screen.getAllByText("What is OWASP?");
      expect(lessonTitles.length).toBeGreaterThanOrEqual(1);
    });

    it("shows lesson type badge", () => {
      renderWithRouter(<LessonView />);

      expect(screen.getByText("theory")).toBeInTheDocument();
    });

    it("displays step progress", () => {
      renderWithRouter(<LessonView />);

      expect(screen.getByText("Step 1 of 3")).toBeInTheDocument();
    });

    it("renders theory content", () => {
      renderWithRouter(<LessonView />);

      expect(
        screen.getByText(/Open Web Application Security Project/i),
      ).toBeInTheDocument();
    });

    it("has a disabled Back button on first lesson", () => {
      renderWithRouter(<LessonView />);

      const backButton = screen.getByRole("button", {
        name: /go to previous lesson/i,
      });
      expect(backButton).toBeDisabled();
    });

    it("has enabled Next Step button on theory lesson", () => {
      renderWithRouter(<LessonView />);

      const nextButton = screen.getByRole("button", {
        name: /go to next lesson step/i,
      });
      expect(nextButton).toBeEnabled();
    });
  });

  describe("quiz lesson navigation", () => {
    it("advances to quiz lesson when clicking Next", async () => {
      const user = userEvent.setup();
      renderWithRouter(<LessonView />);

      const nextButton = screen.getByRole("button", {
        name: /go to next lesson step/i,
      });
      await user.click(nextButton);

      // Should now be on the quiz lesson
      expect(screen.getByText("Knowledge Check")).toBeInTheDocument();
      expect(screen.getByText("quiz")).toBeInTheDocument();
    });
  });

  describe("quiz lesson", () => {
    beforeEach(async () => {
      mockModuleId = "owasp-intro";
    });

    it("displays quiz question", async () => {
      const user = userEvent.setup();
      renderWithRouter(<LessonView />);

      await user.click(
        screen.getByRole("button", { name: /go to next lesson step/i }),
      );

      expect(
        screen.getByText("What does OWASP stand for?"),
      ).toBeInTheDocument();
    });

    it("renders all quiz options", async () => {
      const user = userEvent.setup();
      renderWithRouter(<LessonView />);

      await user.click(
        screen.getByRole("button", { name: /go to next lesson step/i }),
      );

      expect(
        screen.getByText(/Open Web Application Security Project/),
      ).toBeInTheDocument();
      expect(
        screen.getByText(/Online Website Assessment/i),
      ).toBeInTheDocument();
      expect(
        screen.getByText(/Official Web Authorization/i),
      ).toBeInTheDocument();
      expect(
        screen.getByText(/Only Web Apps Stay Private/i),
      ).toBeInTheDocument();
    });

    it("has a disabled Submit button before selecting an option", async () => {
      const user = userEvent.setup();
      renderWithRouter(<LessonView />);

      await user.click(
        screen.getByRole("button", { name: /go to next lesson step/i }),
      );

      const submitButton = screen.getByRole("button", {
        name: /submit your selected answer/i,
      });
      expect(submitButton).toBeDisabled();
    });

    it("enables Submit button after selecting an option", async () => {
      const user = userEvent.setup();
      renderWithRouter(<LessonView />);

      await user.click(
        screen.getByRole("button", { name: /go to next lesson step/i }),
      );

      // Click an option (now using role="radio")
      const options = screen.getAllByRole("radio");
      await user.click(options[0]);

      const submitButton = screen.getByRole("button", {
        name: /submit your selected answer/i,
      });
      expect(submitButton).toBeEnabled();
    });

    it("shows feedback after submitting correct answer", async () => {
      const user = userEvent.setup();
      renderWithRouter(<LessonView />);

      await user.click(
        screen.getByRole("button", { name: /go to next lesson step/i }),
      );

      // Select the correct answer (first option, using role="radio")
      const options = screen.getAllByRole("radio");
      await user.click(options[0]);

      // Submit
      await user.click(
        screen.getByRole("button", { name: /submit your selected answer/i }),
      );

      // Should show correct-answer feedback
      expect(screen.getByText("Target Neutralized")).toBeInTheDocument();
      expect(
        screen.getByText(
          /OWASP stands for the Open Web Application Security Project/i,
        ),
      ).toBeInTheDocument();
    });

    it("shows feedback after submitting wrong answer", async () => {
      const user = userEvent.setup();
      renderWithRouter(<LessonView />);

      await user.click(
        screen.getByRole("button", { name: /go to next lesson step/i }),
      );

      // Select the wrong answer (second option, using role="radio")
      const options = screen.getAllByRole("radio");
      await user.click(options[1]);

      // Submit
      await user.click(
        screen.getByRole("button", { name: /submit your selected answer/i }),
      );

      // Should show wrong-answer feedback
      expect(screen.getByText("Breach Detected")).toBeInTheDocument();
    });

    it("disables Next button until quiz is submitted", async () => {
      const user = userEvent.setup();
      renderWithRouter(<LessonView />);

      await user.click(
        screen.getByRole("button", { name: /go to next lesson step/i }),
      );

      // Next button should be disabled before submitting (goes to lab on lesson 2 of 3)
      const nextButton = screen.getByRole("button", {
        name: /go to next lesson step/i,
      });
      expect(nextButton).toBeDisabled();
    });

    it("enables Next button after quiz is submitted", async () => {
      const user = userEvent.setup();
      renderWithRouter(<LessonView />);

      await user.click(
        screen.getByRole("button", { name: /go to next lesson step/i }),
      );

      // Select and submit an answer
      const options = screen.getAllByRole("radio");
      await user.click(options[0]);
      await user.click(
        screen.getByRole("button", { name: /submit your selected answer/i }),
      );

      // Next button should now be enabled (goes to lab since there are 3 lessons now)
      const nextButton = screen.getByRole("button", {
        name: /go to next lesson step/i,
      });
      expect(nextButton).toBeEnabled();
    });
  });

  describe("lab lesson", () => {
    beforeEach(() => {
      mockModuleId = "sql-injection";
    });

    // Helper to navigate through quizzes to reach the lab
    const navigateToLab = async (user: ReturnType<typeof userEvent.setup>) => {
      // sql-injection has: theory, quiz-1, quiz-2, quiz-3, quiz-4, lab
      // Navigate through theory first
      await user.click(
        screen.getByRole("button", { name: /go to next lesson step/i }),
      );

      // Answer 4 quizzes
      for (let i = 0; i < 4; i++) {
        const options = screen.getAllByRole("radio");
        await user.click(options[1]); // Select second option (correct answer)
        await user.click(
          screen.getByRole("button", { name: /submit your selected answer/i }),
        );
        await user.click(
          screen.getByRole("button", { name: /go to next lesson step/i }),
        );
      }
    };

    it("shows lab view with code editor", async () => {
      const user = userEvent.setup();
      renderWithRouter(<LessonView />);

      await navigateToLab(user);

      expect(screen.getByText("lab")).toBeInTheDocument();
      expect(screen.getByText("Mission Objective")).toBeInTheDocument();
      expect(screen.getByTestId("code-editor")).toBeInTheDocument();
    });

    it("shows Deploy Patch button", async () => {
      const user = userEvent.setup();
      renderWithRouter(<LessonView />);

      await navigateToLab(user);

      expect(
        screen.getByRole("button", {
          name: /deploy patch and verify your code fix/i,
        }),
      ).toBeInTheDocument();
    });

    it("shows error when submitting vulnerable code", async () => {
      const user = userEvent.setup();
      renderWithRouter(<LessonView />);

      await navigateToLab(user);

      // Click Deploy Patch with the initial vulnerable code
      await user.click(
        screen.getByRole("button", {
          name: /deploy patch and verify your code fix/i,
        }),
      );

      expect(screen.getByText("Vulnerability Detected")).toBeInTheDocument();
      expect(
        screen.getByText(/vulnerability still present/i),
      ).toBeInTheDocument();
    });

    it("disables Next button until lab is verified successfully", async () => {
      const user = userEvent.setup();
      renderWithRouter(<LessonView />);

      await navigateToLab(user);

      const nextButton = screen.getByRole("button", {
        name: /complete this mission and return to modules/i,
      });
      expect(nextButton).toBeDisabled();
    });
  });

  describe("module completion", () => {
    it("completes module and adds XP on last lesson completion", async () => {
      const user = userEvent.setup();
      vi.useFakeTimers({ shouldAdvanceTime: true });
      renderWithRouter(<LessonView />);

      // Go to quiz (lesson 2)
      await user.click(
        screen.getByRole("button", { name: /go to next lesson step/i }),
      );

      // Answer quiz (using role="radio")
      const options = screen.getAllByRole("radio");
      await user.click(options[0]);
      await user.click(
        screen.getByRole("button", { name: /submit your selected answer/i }),
      );

      // Go to lab (lesson 3)
      await user.click(
        screen.getByRole("button", { name: /go to next lesson step/i }),
      );

      // Complete the lab - the verifier checks for INJECTION, XSS, IDOR keywords
      const editor = screen.getByTestId("code-editor");
      await user.clear(editor);
      await user.type(
        editor,
        "// INJECTION: SQL\n// XSS: innerHTML\n// IDOR: No auth check",
      );

      // Submit lab
      await user.click(
        screen.getByRole("button", {
          name: /deploy patch and verify your code fix/i,
        }),
      );

      // Wait for success state then complete
      await waitFor(() => {
        expect(
          screen.getByRole("button", {
            name: /complete this mission and return to modules/i,
          }),
        ).not.toBeDisabled();
      });

      // Complete module
      await user.click(
        screen.getByRole("button", {
          name: /complete this mission and return to modules/i,
        }),
      );

      // Check store was updated
      await waitFor(() => {
        const state = useGameStore.getState();
        expect(state.completedModules).toContain("owasp-intro");
      });

      vi.useRealTimers();
    });
  });

  describe("navigation", () => {
    it("navigates back when clicking Back button", async () => {
      const user = userEvent.setup();
      renderWithRouter(<LessonView />);

      // Go to second lesson
      await user.click(
        screen.getByRole("button", { name: /go to next lesson step/i }),
      );

      // Go back
      await user.click(
        screen.getByRole("button", { name: /go to previous lesson/i }),
      );

      // Should be on first lesson again
      expect(screen.getByText("Step 1 of 3")).toBeInTheDocument();
    });
  });
});
