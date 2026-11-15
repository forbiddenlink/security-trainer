import { afterEach, describe, expect, it } from "vitest";
import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { CanonicalLink } from "../CanonicalLink";

afterEach(() => {
  document.head.querySelectorAll('link[rel="canonical"]').forEach((n) => n.remove());
});

const canonical = () =>
  document.head.querySelectorAll<HTMLLinkElement>('link[rel="canonical"]');

describe("CanonicalLink", () => {
  it("points the canonical at the production host and the current path", () => {
    render(
      <MemoryRouter initialEntries={["/modules"]}>
        <CanonicalLink />
      </MemoryRouter>,
    );
    expect(canonical()).toHaveLength(1);
    expect(canonical()[0].href).toBe("https://security-trainer.vercel.app/modules");
  });

  it("reuses the existing tag instead of adding a second one", () => {
    const existing = document.createElement("link");
    existing.rel = "canonical";
    existing.href = "https://security-trainer.vercel.app/";
    document.head.appendChild(existing);
    render(
      <MemoryRouter initialEntries={["/paths/web"]}>
        <CanonicalLink />
      </MemoryRouter>,
    );
    expect(canonical()).toHaveLength(1);
    expect(canonical()[0].href).toBe("https://security-trainer.vercel.app/paths/web");
  });
});
