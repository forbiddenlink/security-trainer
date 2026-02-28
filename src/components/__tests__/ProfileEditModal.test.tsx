import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ProfileEditModal } from "../ProfileEditModal";
import { useAuthStore } from "../../store/authStore";

describe("ProfileEditModal", () => {
  const mockUpdateProfile = vi.fn();
  const mockOnClose = vi.fn();

  // Create a minimal profile for testing
  const createTestProfile = (displayName: string) => ({
    id: "test-user-id",
    email: "test@example.com",
    display_name: displayName,
    avatar_url: null,
    xp: 0,
    level: 1,
    badges: [] as string[],
    completed_modules: [] as string[],
    completed_lessons: [] as string[],
    streak_days: 0,
    last_login_date: null,
    daily_challenge_id: null,
    daily_challenge_date: null,
    daily_challenge_completed: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });

  const setupStore = (overrides: Record<string, unknown> = {}) => {
    useAuthStore.setState({
      user: null,
      profile: createTestProfile("Agent Smith"),
      loading: false,
      error: null,
      updateProfile: mockUpdateProfile,
      ...overrides,
    });
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockUpdateProfile.mockResolvedValue(undefined);
  });

  describe("Rendering", () => {
    it("renders nothing when modal is closed", () => {
      setupStore();
      const { container } = render(
        <ProfileEditModal isOpen={false} onClose={mockOnClose} />,
      );
      expect(container.querySelector('[role="dialog"]')).toBeNull();
    });

    it("renders modal when open", () => {
      setupStore();
      render(<ProfileEditModal isOpen={true} onClose={mockOnClose} />);
      expect(screen.getByRole("dialog")).toBeInTheDocument();
      expect(screen.getByText("Edit Profile")).toBeInTheDocument();
    });

    it("shows current display name in input", () => {
      setupStore();
      render(<ProfileEditModal isOpen={true} onClose={mockOnClose} />);
      const input = screen.getByLabelText("Display Name");
      expect(input).toHaveValue("Agent Smith");
    });

    it("shows empty input when no profile exists", () => {
      setupStore({ profile: null });
      render(<ProfileEditModal isOpen={true} onClose={mockOnClose} />);
      const input = screen.getByLabelText("Display Name");
      expect(input).toHaveValue("");
    });

    it("shows character count", () => {
      setupStore();
      render(<ProfileEditModal isOpen={true} onClose={mockOnClose} />);
      expect(screen.getByText("11/50 characters")).toBeInTheDocument();
    });
  });

  describe("Validation", () => {
    it("shows error for empty display name", async () => {
      const user = userEvent.setup();
      setupStore({ profile: createTestProfile("") });
      render(<ProfileEditModal isOpen={true} onClose={mockOnClose} />);

      const input = screen.getByLabelText("Display Name");
      await user.clear(input);
      await user.click(screen.getByRole("button", { name: "Save Changes" }));

      expect(
        screen.getByText("Display name cannot be empty"),
      ).toBeInTheDocument();
      expect(mockUpdateProfile).not.toHaveBeenCalled();
    });

    it("shows error for display name that is too short", async () => {
      const user = userEvent.setup();
      setupStore({ profile: createTestProfile("") });
      render(<ProfileEditModal isOpen={true} onClose={mockOnClose} />);

      const input = screen.getByLabelText("Display Name");
      await user.type(input, "A");
      await user.click(screen.getByRole("button", { name: "Save Changes" }));

      expect(
        screen.getByText("Display name must be at least 2 characters"),
      ).toBeInTheDocument();
      expect(mockUpdateProfile).not.toHaveBeenCalled();
    });
  });

  describe("Form Submission", () => {
    it("submits valid display name", async () => {
      const user = userEvent.setup();
      setupStore();
      render(<ProfileEditModal isOpen={true} onClose={mockOnClose} />);

      const input = screen.getByLabelText("Display Name");
      await user.clear(input);
      await user.type(input, "New Agent Name");
      await user.click(screen.getByRole("button", { name: "Save Changes" }));

      await waitFor(() => {
        expect(mockUpdateProfile).toHaveBeenCalledWith({
          display_name: "New Agent Name",
        });
      });
    });

    it("trims whitespace from display name", async () => {
      const user = userEvent.setup();
      setupStore();
      render(<ProfileEditModal isOpen={true} onClose={mockOnClose} />);

      const input = screen.getByLabelText("Display Name");
      await user.clear(input);
      await user.type(input, "  Trimmed Name  ");
      await user.click(screen.getByRole("button", { name: "Save Changes" }));

      await waitFor(() => {
        expect(mockUpdateProfile).toHaveBeenCalledWith({
          display_name: "Trimmed Name",
        });
      });
    });

    it("shows success message after submission", async () => {
      const user = userEvent.setup();
      setupStore();
      render(<ProfileEditModal isOpen={true} onClose={mockOnClose} />);

      const input = screen.getByLabelText("Display Name");
      await user.clear(input);
      await user.type(input, "Updated Name");
      await user.click(screen.getByRole("button", { name: "Save Changes" }));

      await waitFor(() => {
        expect(
          screen.getByText("Profile updated successfully"),
        ).toBeInTheDocument();
      });
    });

    it("closes modal after successful submission", async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });
      const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
      setupStore();
      render(<ProfileEditModal isOpen={true} onClose={mockOnClose} />);

      const input = screen.getByLabelText("Display Name");
      await user.clear(input);
      await user.type(input, "Updated Name");
      await user.click(screen.getByRole("button", { name: "Save Changes" }));

      await vi.advanceTimersByTimeAsync(1100);

      expect(mockOnClose).toHaveBeenCalled();
      vi.useRealTimers();
    });
  });

  describe("User Interactions", () => {
    it("closes modal when cancel button is clicked", async () => {
      const user = userEvent.setup();
      setupStore();
      render(<ProfileEditModal isOpen={true} onClose={mockOnClose} />);

      await user.click(screen.getByRole("button", { name: "Cancel" }));

      expect(mockOnClose).toHaveBeenCalled();
    });

    it("closes modal when X button is clicked", async () => {
      const user = userEvent.setup();
      setupStore();
      render(<ProfileEditModal isOpen={true} onClose={mockOnClose} />);

      await user.click(
        screen.getByRole("button", { name: "Close profile editor" }),
      );

      expect(mockOnClose).toHaveBeenCalled();
    });

    it("closes modal when backdrop is clicked", async () => {
      const user = userEvent.setup();
      setupStore();
      render(<ProfileEditModal isOpen={true} onClose={mockOnClose} />);

      // Click the backdrop (first element with aria-hidden)
      const backdrop = document.querySelector('[aria-hidden="true"]');
      if (backdrop) {
        await user.click(backdrop);
      }

      expect(mockOnClose).toHaveBeenCalled();
    });

    it("updates character count as user types", async () => {
      const user = userEvent.setup();
      setupStore({ profile: createTestProfile("") });
      render(<ProfileEditModal isOpen={true} onClose={mockOnClose} />);

      expect(screen.getByText("0/50 characters")).toBeInTheDocument();

      const input = screen.getByLabelText("Display Name");
      await user.type(input, "Test");

      expect(screen.getByText("4/50 characters")).toBeInTheDocument();
    });
  });

  describe("Loading State", () => {
    it("shows loading state during submission", () => {
      setupStore({ loading: true });
      render(<ProfileEditModal isOpen={true} onClose={mockOnClose} />);

      expect(screen.getByText("Saving...")).toBeInTheDocument();
    });

    it("disables submit button while loading", () => {
      setupStore({ loading: true });
      render(<ProfileEditModal isOpen={true} onClose={mockOnClose} />);

      const submitButton = screen.getByRole("button", { name: /saving/i });
      expect(submitButton).toBeDisabled();
    });
  });
});
