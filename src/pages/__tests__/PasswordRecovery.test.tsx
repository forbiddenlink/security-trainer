import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import type { AuthChangeEvent, Session } from "@supabase/supabase-js";
import { PasswordRecovery } from "../PasswordRecovery";
import {
  observeRecovery,
  useRecovery,
  isRecoveryLocation,
} from "../../lib/passwordRecovery";

const auth = vi.hoisted(() => ({
  onAuthStateChange: vi.fn(),
  getSession: vi.fn(),
  updateUser: vi.fn(),
  resetPasswordForEmail: vi.fn(),
}));
vi.mock("../../lib/supabase", () => ({
  supabase: { auth },
  isSupabaseConfigured: () => true,
}));

const fresh = new URL(
  "https://trainer.example/reset-password#type=recovery&access_token=fixture",
);
const session = { user: { id: "learner" } } as Session;
let emit: (event: AuthChangeEvent, session: Session | null) => void;

beforeEach(() => {
  vi.resetAllMocks();
  useRecovery.setState({ ready: false, userId: null });
  auth.onAuthStateChange.mockImplementation((listener) => {
    emit = listener;
  });
  auth.getSession.mockResolvedValue({ data: { session }, error: null });
});

function submitPassword(confirmation = "example-only") {
  fireEvent.change(screen.getByLabelText("New password"), {
    target: { value: "example-only" },
  });
  fireEvent.change(screen.getByLabelText("Confirm new password"), {
    target: { value: confirmation },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save new password" }));
}

describe("password recovery", () => {
  it("accepts recovery callbacks from previously issued profile links", () => {
    expect(isRecoveryLocation(new URL("/profile" + fresh.hash, fresh))).toBe(
      true,
    );
    expect(isRecoveryLocation(new URL("/profile", fresh))).toBe(false);
  });

  it("saves a matching password once for the recovered session", async () => {
    observeRecovery(fresh);
    emit("PASSWORD_RECOVERY", session);
    auth.updateUser.mockResolvedValue({ error: null });
    render(<PasswordRecovery />);
    submitPassword("different");
    expect(auth.updateUser).not.toHaveBeenCalled();
    submitPassword();
    expect(
      await screen.findByText("Your password has been updated."),
    ).toBeVisible();
    expect(auth.updateUser).toHaveBeenCalledExactlyOnceWith({
      password: "example-only",
    });
    expect(useRecovery.getState().userId).toBeNull();
  });

  it("does not update another account if the session changes", async () => {
    observeRecovery(fresh);
    emit("PASSWORD_RECOVERY", session);
    auth.getSession.mockResolvedValue({
      data: { session: { user: { id: "another" } } },
      error: null,
    });
    render(<PasswordRecovery />);
    submitPassword();
    await screen.findByRole("button", { name: "Send reset email" });
    expect(auth.updateUser).not.toHaveBeenCalled();
  });

  it.each(["", "#error=access_denied&error_code=otp_expired"])(
    "offers another email on a plain or spent link %s",
    async (suffix) => {
      observeRecovery(new URL("/reset-password" + suffix, fresh));
      auth.resetPasswordForEmail.mockResolvedValue({ error: null });
      render(<PasswordRecovery />);
      expect(screen.queryByLabelText("New password")).toBeNull();
      fireEvent.change(screen.getByLabelText("Email"), {
        target: { value: "learner@example.test" },
      });
      fireEvent.click(screen.getByRole("button", { name: "Send reset email" }));
      await screen.findByText(/if this address has an account/i);
      expect(auth.updateUser).not.toHaveBeenCalled();
    },
  );

  it("requires the recovery event even when a session already exists", () => {
    observeRecovery(fresh);
    emit("INITIAL_SESSION", session);
    render(<PasswordRecovery />);
    expect(screen.queryByLabelText("New password")).toBeNull();
  });
});
