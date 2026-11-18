import { beforeEach, describe, expect, it } from "vitest";
import { useScamStore } from "./scamStore";
import { scenariosForLevel } from "../lib/scamSurvival";

describe("scamStore", () => {
  beforeEach(() => {
    localStorage.clear();
    useScamStore.getState().resetAll();
  });

  it("records a safe answer and persists it", () => {
    const s = scenariosForLevel(1)[0];
    const safe = s.choices.find((c) => c.outcome === "safe")!;
    useScamStore.getState().record(s.id, safe.id);
    expect(useScamStore.getState().progress.completed).toContain(s.id);
    const saved = JSON.parse(localStorage.getItem("scam-survival-storage")!);
    expect(saved.state.progress.completed).toContain(s.id);
  });

  it("loads old or broken saves defensively", async () => {
    localStorage.setItem(
      "scam-survival-storage",
      JSON.stringify({
        state: { progress: { completed: ["gone", 4] } },
        version: 0,
      }),
    );
    await useScamStore.persist.rehydrate();
    const p = useScamStore.getState().progress;
    expect(p.completed).toEqual([]);
    expect(p.habits.pause).toBe(0);
    expect(useScamStore.getState().humour).toBe(true);
  });
});
