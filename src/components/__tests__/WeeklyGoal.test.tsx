import { describe, it, expect, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { WeeklyGoal } from "../WeeklyGoal";
import { useGameStore } from "../../store/gameStore";

describe("WeeklyGoal", () => {
  beforeEach(() => useGameStore.getState().resetProgress());

  it("shows the XP still needed for the first tier on an empty week", () => {
    render(<WeeklyGoal />);
    expect(screen.getByText("0 XP")).toBeInTheDocument();
    expect(screen.getByText(/250 XP to On duty/)).toBeInTheDocument();
  });

  it("names the tier reached after earning XP today", () => {
    const today = new Date().toISOString().split("T")[0];
    useGameStore.setState({ xpByDay: { [today]: 700 } });
    render(<WeeklyGoal />);
    expect(screen.getByRole("meter", { name: "Weekly XP" })).toHaveAttribute(
      "aria-valuenow",
      "700",
    );
    expect(screen.getByText(/500 XP to Relentless/)).toBeInTheDocument();
  });
});
