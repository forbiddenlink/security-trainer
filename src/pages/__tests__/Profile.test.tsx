import { describe, it, expect, beforeEach, vi } from "vitest";
import { screen } from "@testing-library/react";
import {
  renderWithRouter,
  resetGameStore,
  userEvent,
} from "../../test/testUtils";
import { Profile } from "../Profile";
import { useGameStore } from "../../store/gameStore";

// Mock framer-motion to a passthrough
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
    expect(screen.queryByText("Select Your Role")).not.toBeInTheDocument();

    // Re-open the onboarding role picker
    await user.click(screen.getByRole("button", { name: /change focus/i }));

    expect(screen.getByText("Select Your Role")).toBeInTheDocument();
  });
});
