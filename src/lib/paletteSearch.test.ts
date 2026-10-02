import { describe, it, expect } from "vitest";
import { rankPaletteItems, type PaletteItem } from "./paletteSearch";

const items: PaletteItem[] = [
  {
    id: "1",
    kind: "module",
    title: "SQL Injection (SQLi)",
    href: "/a",
    keywords: "database",
  },
  { id: "2", kind: "module", title: "NoSQL Injection", href: "/b" },
  { id: "3", kind: "page", title: "Leaderboard", href: "/leaderboard" },
  { id: "4", kind: "ctf", title: "SQL or Not to SQL", href: "/ctf" },
];

describe("rankPaletteItems", () => {
  it("returns every item when the query is empty", () => {
    expect(rankPaletteItems(items, "  ")).toHaveLength(4);
  });

  it("ranks title prefix matches above substring matches", () => {
    const ids = rankPaletteItems(items, "sql").map((i) => i.id);
    expect(ids[0]).toBe("1");
    expect(ids).toContain("2");
    expect(ids).not.toContain("3");
  });

  it("matches keywords and is case-insensitive", () => {
    expect(rankPaletteItems(items, "DATABASE").map((i) => i.id)).toEqual(["1"]);
  });

  it("requires every query word to match", () => {
    expect(rankPaletteItems(items, "sql not").map((i) => i.id)).toEqual(["4"]);
  });
});
