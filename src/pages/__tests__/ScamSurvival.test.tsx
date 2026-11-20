import { beforeEach, describe, expect, it } from "vitest";
import { fireEvent, screen } from "@testing-library/react";
import { renderWithRouter } from "../../test/testUtils";
import { ScamSurvival } from "../ScamSurvival";
import { useScamStore } from "../../store/scamStore";
import { useAuthStore } from "../../store/authStore";
import { scenariosForLevel } from "../../lib/scamSurvival";

const first = scenariosForLevel(1)[0];
const safe = first.choices.find((c) => c.outcome === "safe")!;
const risky = first.choices.find((c) => c.outcome === "risky")!;

describe("ScamSurvival page", () => {
  beforeEach(() => {
    localStorage.clear();
    useScamStore.getState().resetAll();
    useScamStore.setState({
      textOnly: false,
      highContrast: false,
      humour: true,
    });
    useAuthStore.setState({ user: null });
  });

  it("starts with level 1 open and later levels locked", () => {
    renderWithRouter(<ScamSurvival />);
    expect(
      screen.getByRole("heading", { level: 1, name: /scam survival/i }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /level 1/i })).toBeEnabled();
    expect(screen.getByRole("button", { name: /level 2/i })).toBeDisabled();
  });

  it("shows a scenario as static text with no links or images", () => {
    const { container } = renderWithRouter(<ScamSurvival />);
    fireEvent.click(screen.getByRole("button", { name: /level 1/i }));
    expect(
      screen.getByRole("progressbar", { name: /scenario 1 of/i }),
    ).toHaveValue(1);
    expect(screen.getByText(first.messages[0].from)).toBeInTheDocument();
    const region = screen.getByRole("region", { name: /message/i });
    expect(region.querySelector("a")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
  });

  it("explains a safe answer with red flags and does not save for a guest", () => {
    renderWithRouter(<ScamSurvival />);
    fireEvent.click(screen.getByRole("button", { name: /level 1/i }));
    fireEvent.click(screen.getByRole("button", { name: safe.label }));
    expect(screen.getByText(safe.feedback)).toBeInTheDocument();
    expect(screen.getByText(first.red_flags[0])).toBeInTheDocument();
    expect(useScamStore.getState().progress.completed).toEqual([]);
  });

  it("saves progress when a user is signed in", () => {
    useAuthStore.setState({ user: { id: "u1" } as never });
    renderWithRouter(<ScamSurvival />);
    fireEvent.click(screen.getByRole("button", { name: /level 1/i }));
    fireEvent.click(screen.getByRole("button", { name: safe.label }));
    expect(useScamStore.getState().progress.completed).toContain(first.id);
  });

  it("shows a gentle reflection on a first slip and never blocks", () => {
    renderWithRouter(<ScamSurvival />);
    fireEvent.click(screen.getByRole("button", { name: /level 1/i }));
    fireEvent.click(screen.getByRole("button", { name: risky.label }));
    expect(screen.getByText(/everyone slips/i)).toBeInTheDocument();
    fireEvent.click(screen.getByText("See a safe response"));
    expect(screen.getByText(safe.feedback)).toBeVisible();
    expect(screen.getByRole("button", { name: /try again/i })).toBeEnabled();
  });

  it("text-only and high-contrast modes are available", () => {
    renderWithRouter(<ScamSurvival />);
    fireEvent.click(screen.getByLabelText(/text only/i));
    fireEvent.click(screen.getByLabelText(/high contrast/i));
    expect(useScamStore.getState().textOnly).toBe(true);
    expect(useScamStore.getState().highContrast).toBe(true);
  });

  it("links each level to its lesson", () => {
    renderWithRouter(<ScamSurvival />);
    fireEvent.click(screen.getByRole("button", { name: /level 1/i }));
    expect(
      screen.getByRole("link", { name: /recognizing phishing attacks/i }),
    ).toHaveAttribute(
      "href",
      "/modules/phishing-awareness/phishing-recognizing",
    );
  });

  it("returns to the level picker when the progress mode changes", () => {
    useAuthStore.setState({ user: { id: "u1" } as never });
    renderWithRouter(<ScamSurvival />);
    fireEvent.click(screen.getByRole("button", { name: /level 1/i }));
    expect(
      screen.getByRole("region", { name: /message/i }),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText(/guest mode/i));
    expect(screen.queryByRole("region", { name: /message/i })).toBeNull();
    expect(screen.getByRole("button", { name: /level 2/i })).toBeDisabled();
  });
});
