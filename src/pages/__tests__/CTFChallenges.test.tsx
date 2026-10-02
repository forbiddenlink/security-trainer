import { describe, it, expect, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { CTFChallenges } from "../CTFChallenges";
import { useGameStore } from "../../store/gameStore";
import { CTF_CHALLENGES } from "../../data/ctfChallenges";

describe("CTFChallenges hide solved", () => {
  beforeEach(() => useGameStore.getState().resetProgress());

  it("removes solved challenges from the board when toggled", async () => {
    const solved = CTF_CHALLENGES[0];
    useGameStore.setState({
      ctfProgress: {
        [solved.id]: {
          challengeId: solved.id,
          solved: true,
          hintsUsed: [],
          attempts: 1,
          pointsEarned: solved.points,
        },
      },
    } as never);
    const user = userEvent.setup();
    render(
      <MemoryRouter initialEntries={["/ctf"]}>
        <CTFChallenges />
      </MemoryRouter>,
    );

    expect(screen.getAllByText(solved.title).length).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: "Hide solved" }));
    expect(screen.queryByText(solved.title)).toBeNull();
  });

  it("does not offer the toggle before anything is solved", () => {
    render(
      <MemoryRouter initialEntries={["/ctf"]}>
        <CTFChallenges />
      </MemoryRouter>,
    );
    expect(screen.queryByRole("button", { name: "Hide solved" })).toBeNull();
  });
});
