import { describe, expect, it } from "vitest";
import { fireEvent, screen } from "@testing-library/react";
import { renderWithRouter } from "../../test/testUtils";
import { CascadingFailure } from "../CascadingFailure";

const click = (name: RegExp) =>
  fireEvent.click(screen.getByRole("button", { name }));

describe("CascadingFailure page", () => {
  it("shows the symptoms and a turn counter at the start", () => {
    renderWithRouter(<CascadingFailure />);
    expect(
      screen.getByRole("heading", { level: 1, name: /cascading failure/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/page latency is up/i)).toBeInTheDocument();
    expect(screen.getByText(/turn 0 of 10/i)).toBeInTheDocument();
  });

  it("advances a turn and disables the action that was used", () => {
    renderWithRouter(<CascadingFailure />);
    click(/which database queries are the slowest/i);
    expect(screen.getByText(/turn 1 of 10/i)).toBeInTheDocument();
    expect(
      screen.getByRole("button", {
        name: /which database queries are the slowest/i,
      }),
    ).toBeDisabled();
    expect(
      screen.getAllByText(/hourly reporting export/i).length,
    ).toBeGreaterThan(0);
  });

  it("does not show a win screen, and shows a postmortem with turns when it ends", () => {
    renderWithRouter(<CascadingFailure />);
    click(/which database queries are the slowest/i);
    click(/who uses the reporting export/i);
    click(/pause the hourly reporting export/i);
    click(/short status update/i);
    click(/what are customers reporting/i);
    expect(
      screen.getByRole("heading", { name: /postmortem/i }),
    ).toBeInTheDocument();
    expect(screen.getAllByText(/Turn \d+/).length).toBeGreaterThan(0);
    expect(screen.queryByText(/you win|victory|congratulations/i)).toBeNull();
  });

  it("restarts with a fresh game", () => {
    renderWithRouter(<CascadingFailure />);
    click(/what are customers reporting/i);
    click(/start over/i);
    expect(screen.getByText(/turn 0 of 10/i)).toBeInTheDocument();
  });

  it("links to the incident response module", () => {
    renderWithRouter(<CascadingFailure />);
    expect(
      screen.getByRole("link", { name: /incident response module/i }),
    ).toHaveAttribute("href", "/modules/incident-response");
  });
});
