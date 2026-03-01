import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ReviewModal } from "../ReviewModal";
import { useGameStore } from "../../store/gameStore";

// Mock useFocusTrap to avoid focus interference in tests
vi.mock("../../utils/useFocusTrap", () => ({
  useFocusTrap: () => ({ current: null }),
}));

describe("ReviewModal", () => {
  const mockOnClose = vi.fn();
  const mockMarkLessonReviewed = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    useGameStore.setState({
      markLessonReviewed: mockMarkLessonReviewed,
    });
  });

  describe("Rendering", () => {
    it("renders nothing when modal is closed", () => {
      const { container } = render(
        <ReviewModal
          isOpen={false}
          onClose={mockOnClose}
          lessonId="test-lesson"
          lessonTitle="Test Lesson"
        />,
      );
      expect(container.querySelector('[role="dialog"]')).toBeNull();
    });

    it("renders modal when open", () => {
      render(
        <ReviewModal
          isOpen={true}
          onClose={mockOnClose}
          lessonId="test-lesson"
          lessonTitle="Test Lesson"
        />,
      );
      expect(screen.getByRole("dialog")).toBeInTheDocument();
    });

    it("displays Mission Debrief title", () => {
      render(
        <ReviewModal
          isOpen={true}
          onClose={mockOnClose}
          lessonId="test-lesson"
          lessonTitle="Test Lesson"
        />,
      );
      expect(screen.getByText("Mission Debrief")).toBeInTheDocument();
    });

    it("displays lesson title", () => {
      render(
        <ReviewModal
          isOpen={true}
          onClose={mockOnClose}
          lessonId="test-lesson"
          lessonTitle="SQL Injection Basics"
        />,
      );
      expect(screen.getByText("SQL Injection Basics")).toBeInTheDocument();
    });

    it("displays all three rating buttons", () => {
      render(
        <ReviewModal
          isOpen={true}
          onClose={mockOnClose}
          lessonId="test-lesson"
          lessonTitle="Test Lesson"
        />,
      );
      expect(screen.getByText("Hard")).toBeInTheDocument();
      expect(screen.getByText("Good")).toBeInTheDocument();
      expect(screen.getByText("Easy")).toBeInTheDocument();
    });

    it("displays XP rewards for each rating", () => {
      render(
        <ReviewModal
          isOpen={true}
          onClose={mockOnClose}
          lessonId="test-lesson"
          lessonTitle="Test Lesson"
        />,
      );
      expect(screen.getByText("+10 XP")).toBeInTheDocument();
      expect(screen.getByText("+15 XP")).toBeInTheDocument();
      expect(screen.getByText("+20 XP")).toBeInTheDocument();
    });

    it("displays rating descriptions", () => {
      render(
        <ReviewModal
          isOpen={true}
          onClose={mockOnClose}
          lessonId="test-lesson"
          lessonTitle="Test Lesson"
        />,
      );
      expect(screen.getByText("Struggled to recall")).toBeInTheDocument();
      expect(screen.getByText("Recalled with effort")).toBeInTheDocument();
      expect(screen.getByText("Instantly recalled")).toBeInTheDocument();
    });

    it("displays skip option", () => {
      render(
        <ReviewModal
          isOpen={true}
          onClose={mockOnClose}
          lessonId="test-lesson"
          lessonTitle="Test Lesson"
        />,
      );
      expect(screen.getByText("Skip for now")).toBeInTheDocument();
    });
  });

  describe("User Interactions", () => {
    it("calls markLessonReviewed with hard rating when Hard is clicked", async () => {
      const user = userEvent.setup();
      render(
        <ReviewModal
          isOpen={true}
          onClose={mockOnClose}
          lessonId="test-lesson"
          lessonTitle="Test Lesson"
        />,
      );

      await user.click(screen.getByText("Hard"));

      expect(mockMarkLessonReviewed).toHaveBeenCalledWith(
        "test-lesson",
        "hard",
      );
      expect(mockOnClose).toHaveBeenCalled();
    });

    it("calls markLessonReviewed with good rating when Good is clicked", async () => {
      const user = userEvent.setup();
      render(
        <ReviewModal
          isOpen={true}
          onClose={mockOnClose}
          lessonId="test-lesson"
          lessonTitle="Test Lesson"
        />,
      );

      await user.click(screen.getByText("Good"));

      expect(mockMarkLessonReviewed).toHaveBeenCalledWith(
        "test-lesson",
        "good",
      );
      expect(mockOnClose).toHaveBeenCalled();
    });

    it("calls markLessonReviewed with easy rating when Easy is clicked", async () => {
      const user = userEvent.setup();
      render(
        <ReviewModal
          isOpen={true}
          onClose={mockOnClose}
          lessonId="test-lesson"
          lessonTitle="Test Lesson"
        />,
      );

      await user.click(screen.getByText("Easy"));

      expect(mockMarkLessonReviewed).toHaveBeenCalledWith(
        "test-lesson",
        "easy",
      );
      expect(mockOnClose).toHaveBeenCalled();
    });

    it("closes modal when skip button is clicked", async () => {
      const user = userEvent.setup();
      render(
        <ReviewModal
          isOpen={true}
          onClose={mockOnClose}
          lessonId="test-lesson"
          lessonTitle="Test Lesson"
        />,
      );

      await user.click(screen.getByText("Skip for now"));

      expect(mockOnClose).toHaveBeenCalled();
      expect(mockMarkLessonReviewed).not.toHaveBeenCalled();
    });

    it("closes modal when close button is clicked", async () => {
      const user = userEvent.setup();
      render(
        <ReviewModal
          isOpen={true}
          onClose={mockOnClose}
          lessonId="test-lesson"
          lessonTitle="Test Lesson"
        />,
      );

      await user.click(screen.getByLabelText("Close review modal"));

      expect(mockOnClose).toHaveBeenCalled();
      expect(mockMarkLessonReviewed).not.toHaveBeenCalled();
    });

    it("closes modal when backdrop is clicked", async () => {
      const user = userEvent.setup();
      render(
        <ReviewModal
          isOpen={true}
          onClose={mockOnClose}
          lessonId="test-lesson"
          lessonTitle="Test Lesson"
        />,
      );

      const backdrop = document.querySelector('[aria-hidden="true"]');
      if (backdrop) {
        await user.click(backdrop);
      }

      expect(mockOnClose).toHaveBeenCalled();
    });
  });

  describe("Accessibility", () => {
    it("has accessible dialog role", () => {
      render(
        <ReviewModal
          isOpen={true}
          onClose={mockOnClose}
          lessonId="test-lesson"
          lessonTitle="Test Lesson"
        />,
      );
      expect(screen.getByRole("dialog")).toHaveAttribute("aria-modal", "true");
    });

    it("has accessible title", () => {
      render(
        <ReviewModal
          isOpen={true}
          onClose={mockOnClose}
          lessonId="test-lesson"
          lessonTitle="Test Lesson"
        />,
      );
      expect(screen.getByRole("dialog")).toHaveAttribute(
        "aria-labelledby",
        "review-modal-title",
      );
    });

    it("close button has accessible label", () => {
      render(
        <ReviewModal
          isOpen={true}
          onClose={mockOnClose}
          lessonId="test-lesson"
          lessonTitle="Test Lesson"
        />,
      );
      expect(
        screen.getByRole("button", { name: "Close review modal" }),
      ).toBeInTheDocument();
    });
  });
});
