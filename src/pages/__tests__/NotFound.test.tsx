import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import { renderWithRouter } from "../../test/testUtils";
import { NotFound } from "../NotFound";

describe("NotFound", () => {
  it("tells the visitor the page does not exist and links home", () => {
    renderWithRouter(<NotFound />);
    expect(
      screen.getByRole("heading", { level: 1, name: /page not found/i }),
    ).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /back to dashboard/i })).toHaveAttribute(
      "href",
      "/",
    );
  });
});
