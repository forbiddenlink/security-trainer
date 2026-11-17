import { describe, it, expect, beforeEach, vi } from "vitest";
import { screen, waitFor } from "@testing-library/react";
import {
  renderWithRouter,
  resetGameStore,
  userEvent,
} from "../../test/testUtils";
import { Profile } from "../Profile";
import { useGameStore } from "../../store/gameStore";
import { useAuthStore } from "../../store/authStore";
import { useScamStore } from "../../store/scamStore";
import { scenariosForLevel } from "../../lib/scamSurvival";

// Mock framer-motion to a passthrough
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

// Certificate pulls in html-to-image; stub it out for this page test
vi.mock("../../components/Certificate", () => ({
  Certificate: () => <div data-testid="certificate" />,
}));

describe("Profile - training focus", () => {
  beforeEach(() => {
    resetGameStore();
  });

  it("shows the current role and can re-open the role picker", async () => {
    const user = userEvent.setup();
    useGameStore.setState({ userRole: "developer" });

    renderWithRouter(<Profile />);

    // Current role is surfaced
    expect(screen.getByText("Training Focus")).toBeInTheDocument();
    expect(screen.getByText("Developer / Engineer")).toBeInTheDocument();

    // Role selector is hidden until requested
    expect(screen.queryByText(/calibrate your track/i)).not.toBeInTheDocument();

    // Re-open the onboarding role picker
    await user.click(screen.getByRole("button", { name: /change focus/i }));

    expect(screen.getByText(/calibrate your track/i)).toBeInTheDocument();
  });
});

describe("Profile - account deletion", () => {
  it("clears saved Scam Survival progress after a successful delete", async () => {
    const user = userEvent.setup();
    resetGameStore();
    const sc = scenariosForLevel(1)[0];
    const safe = sc.choices.find((c) => c.outcome === "safe")!;
    useScamStore.getState().record(sc.id, safe.id);
    expect(useScamStore.getState().progress.completed.length).toBe(1);
    useAuthStore.setState({
      user: { id: "u1" } as never,
      deleteAccount: vi.fn().mockResolvedValue({ error: null }),
    });
    renderWithRouter(<Profile />);
    await user.click(screen.getByRole("button", { name: /^delete account/i }));
    await user.click(
      screen.getByRole("button", { name: /yes, delete my account/i }),
    );
    await waitFor(() =>
      expect(useScamStore.getState().progress.completed).toEqual([]),
    );
  });
});
