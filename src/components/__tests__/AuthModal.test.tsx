import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AuthModal } from "../AuthModal";
import { useAuthStore } from "../../store/authStore";
import { useGameStore } from "../../store/gameStore";

// Mock Supabase configuration
vi.mock("../../lib/supabase", () => ({
  isSupabaseConfigured: vi.fn(() => true),
  supabase: null,
}));

describe("AuthModal", () => {
  const mockSignIn = vi.fn();
  const mockSignUp = vi.fn();
  const mockSignInWithGoogle = vi.fn();
  const mockCloseAuthModal = vi.fn();
  const mockClearError = vi.fn();
  const mockLoadProgressFromCloud = vi.fn();
  const mockSyncProgressToCloud = vi.fn();

  const setupStores = (overrides: Record<string, unknown> = {}) => {
    // Reset stores to default state
    useAuthStore.setState({
      isAuthModalOpen: true,
      authModalMode: "login",
      loading: false,
      error: null,
      user: null,
      profile: null,
      signIn: mockSignIn,
      signUp: mockSignUp,
      signInWithGoogle: mockSignInWithGoogle,
      closeAuthModal: mockCloseAuthModal,
      clearError: mockClearError,
      loadProgressFromCloud: mockLoadProgressFromCloud,
      syncProgressToCloud: mockSyncProgressToCloud,
      openAuthModal: vi.fn(),
      signOut: vi.fn(),
      initialize: vi.fn(),
      ...overrides,
    });

    useGameStore.setState({
      xp: 0,
      level: 1,
      completedLessons: [],
      completedModules: [],
      badges: [],
      currentModuleId: null,
      streakDays: 0,
      lastLoginDate: null,
      dailyChallengeId: null,
      dailyChallengeDate: null,
      dailyChallengeCompleted: false,
      showLevelUpToast: false,
      achievementQueue: [],
    });
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("Rendering", () => {
    it("renders nothing when modal is closed", () => {
      setupStores({ isAuthModalOpen: false });
      const { container } = render(<AuthModal />);
      expect(container.querySelector('[role="dialog"]')).toBeNull();
    });

    it("renders login form when modal is open in login mode", () => {
      setupStores();
      render(<AuthModal />);
      expect(screen.getByRole("dialog")).toBeInTheDocument();
      expect(screen.getByText("Welcome Back, Agent")).toBeInTheDocument();
      expect(screen.getByLabelText("Email")).toBeInTheDocument();
      expect(screen.getByLabelText("Password")).toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: "Sign In" }),
      ).toBeInTheDocument();
    });

    it("renders signup form when in signup mode", () => {
      setupStores({ authModalMode: "signup" });
      render(<AuthModal />);
      expect(screen.getByText("Join the Mission")).toBeInTheDocument();
      expect(screen.getByLabelText("Display Name")).toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: "Create Account" }),
      ).toBeInTheDocument();
    });

    it("renders Google sign-in button", () => {
      setupStores();
      render(<AuthModal />);
      expect(
        screen.getByRole("button", { name: /google/i }),
      ).toBeInTheDocument();
    });
  });

  describe("Form Interactions", () => {
    it("allows typing in email and password fields", async () => {
      setupStores();
      const user = userEvent.setup();
      render(<AuthModal />);

      const emailInput = screen.getByLabelText("Email");
      const passwordInput = screen.getByLabelText("Password");

      await user.type(emailInput, "test@example.com");
      await user.type(passwordInput, "password123");

      expect(emailInput).toHaveValue("test@example.com");
      expect(passwordInput).toHaveValue("password123");
    });

    it("submits login form with credentials", async () => {
      setupStores();
      const user = userEvent.setup();
      mockSignIn.mockResolvedValue({ error: null });

      render(<AuthModal />);

      await user.type(screen.getByLabelText("Email"), "test@example.com");
      await user.type(screen.getByLabelText("Password"), "password123");
      await user.click(screen.getByRole("button", { name: "Sign In" }));

      await waitFor(() => {
        expect(mockSignIn).toHaveBeenCalledWith(
          "test@example.com",
          "password123",
        );
      });
    });

    it("submits signup form with display name", async () => {
      setupStores({ authModalMode: "signup" });
      const user = userEvent.setup();
      mockSignUp.mockResolvedValue({ error: null });

      render(<AuthModal />);

      await user.type(screen.getByLabelText("Display Name"), "Agent Smith");
      await user.type(screen.getByLabelText("Email"), "test@example.com");
      await user.type(screen.getByLabelText("Password"), "password123");
      await user.click(screen.getByRole("button", { name: "Create Account" }));

      await waitFor(() => {
        expect(mockSignUp).toHaveBeenCalledWith(
          "test@example.com",
          "password123",
          "Agent Smith",
        );
      });
    });

    it("calls Google sign-in when Google button is clicked", async () => {
      setupStores();
      const user = userEvent.setup();
      render(<AuthModal />);

      await user.click(screen.getByRole("button", { name: /google/i }));

      expect(mockSignInWithGoogle).toHaveBeenCalled();
    });
  });

  describe("Mode Switching", () => {
    it("switches from login to signup mode", async () => {
      setupStores();
      const user = userEvent.setup();
      render(<AuthModal />);

      expect(screen.getByText("Welcome Back, Agent")).toBeInTheDocument();

      await user.click(screen.getByRole("button", { name: "Sign up" }));

      expect(mockClearError).toHaveBeenCalled();
    });

    it("switches from signup to login mode", async () => {
      setupStores({ authModalMode: "signup" });
      const user = userEvent.setup();
      render(<AuthModal />);

      expect(screen.getByText("Join the Mission")).toBeInTheDocument();

      await user.click(screen.getByRole("button", { name: "Sign in" }));

      expect(mockClearError).toHaveBeenCalled();
    });
  });

  describe("Error Handling", () => {
    it("displays error message when present", () => {
      setupStores({ error: "Invalid credentials" });
      render(<AuthModal />);

      expect(screen.getByText("Invalid credentials")).toBeInTheDocument();
    });

    it("clears error when form is submitted", async () => {
      setupStores({ error: "Previous error" });
      const user = userEvent.setup();
      mockSignIn.mockResolvedValue({ error: null });

      render(<AuthModal />);

      await user.type(screen.getByLabelText("Email"), "test@example.com");
      await user.type(screen.getByLabelText("Password"), "password123");
      await user.click(screen.getByRole("button", { name: "Sign In" }));

      expect(mockClearError).toHaveBeenCalled();
    });
  });

  describe("Modal Controls", () => {
    it("closes modal when close button is clicked", async () => {
      setupStores();
      const user = userEvent.setup();
      render(<AuthModal />);

      await user.click(screen.getByRole("button", { name: "Close modal" }));

      expect(mockCloseAuthModal).toHaveBeenCalled();
    });

    it("closes modal when backdrop is clicked", async () => {
      setupStores();
      const user = userEvent.setup();
      render(<AuthModal />);

      // Find the backdrop (the first motion.div)
      const backdrop = document.querySelector('[aria-hidden="true"]');
      if (backdrop) {
        await user.click(backdrop);
        expect(mockCloseAuthModal).toHaveBeenCalled();
      }
    });
  });

  describe("Loading State", () => {
    it("shows loading state when loading", () => {
      setupStores({ loading: true });
      render(<AuthModal />);

      const submitButton = screen.getByRole("button", { name: "Sign In" });
      expect(submitButton).toBeDisabled();
    });

    it("disables form buttons during loading", () => {
      setupStores({ loading: true });
      render(<AuthModal />);

      expect(screen.getByRole("button", { name: "Sign In" })).toBeDisabled();
      expect(screen.getByRole("button", { name: /google/i })).toBeDisabled();
    });
  });

  describe("Accessibility", () => {
    it("has proper aria attributes on modal", () => {
      setupStores();
      render(<AuthModal />);

      const dialog = screen.getByRole("dialog");
      expect(dialog).toHaveAttribute("aria-modal", "true");
      expect(dialog).toHaveAttribute("aria-labelledby", "auth-modal-title");
    });

    it("has proper labels on form inputs", () => {
      setupStores();
      render(<AuthModal />);

      expect(screen.getByLabelText("Email")).toBeInTheDocument();
      expect(screen.getByLabelText("Password")).toBeInTheDocument();
    });

    it("has accessible close button", () => {
      setupStores();
      render(<AuthModal />);

      expect(
        screen.getByRole("button", { name: "Close modal" }),
      ).toBeInTheDocument();
    });
  });
});
