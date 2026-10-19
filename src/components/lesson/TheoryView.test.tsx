import { render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { TheoryView } from "./TheoryView";

vi.mock("./MermaidDiagram", () => ({ MermaidDiagram: () => null }));

describe("TheoryView", () => {
  it("does not nest the video embed inside a paragraph", () => {
    const { container } = render(
      <TheoryView
        content={
          'Intro text\n\n::video[https://www.youtube.com/watch?v=I-vjt5dU7wQ]{title="Demo" caption="A demo"}\n\nOutro'
        }
      />,
    );
    expect(container.querySelector("figure")).not.toBeNull();
    expect(container.querySelector("p figure, p div")).toBeNull();
  });
});
