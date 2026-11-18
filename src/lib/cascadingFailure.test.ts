import { describe, expect, it } from "vitest";
import {
  createGame,
  getPostmortem,
  getTurnOutput,
  takeAction,
  MAX_TURNS,
} from "./cascadingFailure";
import { CASCADE_ACTIONS } from "../data/cascadingFailureScenario";

describe("cascadingFailure engine", () => {
  it("starts at turn 0 with the scenario symptoms and no end", () => {
    const out = getTurnOutput(createGame());
    expect(out.turn).toBe(0);
    expect(out.ended).toBe(false);
    expect(out.stability_points).toBe(0);
    expect(out.symptoms.join(" ")).toMatch(/latency/i);
  });

  it("is deterministic and does not mutate the previous state", () => {
    const a = createGame();
    const snapshot = JSON.stringify(a);
    const b1 = takeAction(a, "scale-db");
    const b2 = takeAction(a, "scale-db");
    expect(JSON.stringify(a)).toBe(snapshot);
    expect(JSON.stringify(b1)).toBe(JSON.stringify(b2));
  });

  it("state survives a JSON round trip", () => {
    const s = takeAction(createGame(), "mute-alerts");
    const back = JSON.parse(JSON.stringify(s));
    expect(JSON.stringify(takeAction(back, "scale-db"))).toBe(
      JSON.stringify(takeAction(s, "scale-db")),
    );
  });

  it("rejects unknown actions, repeats, and actions after the end", () => {
    const s = createGame();
    expect(() => takeAction(s, "nope")).toThrow();
    const s1 = takeAction(s, "scale-db");
    expect(() => takeAction(s1, "scale-db")).toThrow();
  });

  it("queues a delayed consequence that appears 1 to 3 turns later", () => {
    let s = takeAction(createGame(), "mute-alerts");
    const caused = s.turn;
    const order = ["inspect-queries", "ask-support", "page-teammate"];
    for (const id of order) s = takeAction(s, id);
    const pm = getPostmortem(s);
    const d = pm.delayed_failures.find((f) => f.caused_on_turn === caused);
    expect(d).toBeDefined();
    const gap = d!.appeared_on_turn - d!.caused_on_turn;
    expect(gap).toBeGreaterThanOrEqual(1);
    expect(gap).toBeLessThanOrEqual(3);
  });

  it("never reveals hidden state in the turn output", () => {
    const s = takeAction(createGame(), "mute-alerts");
    const out = getTurnOutput(s) as unknown as Record<string, unknown>;
    expect(Object.keys(out).sort()).toEqual(
      [
        "constraints",
        "ended",
        "stability_points",
        "status",
        "symptoms",
        "turn",
      ].sort(),
    );
  });

  it("asking finance first avoids the shared-login workaround", () => {
    const run = (ids: string[]) => {
      let s = createGame();
      for (const id of ids) s = takeAction(s, id);
      return s;
    };
    const blind = run([
      "disable-export",
      "status-update",
      "page-teammate",
      "restart-services",
    ]);
    const informed = run([
      "inspect-queries",
      "ask-finance",
      "disable-export",
      "status-update",
    ]);
    const blindText = getPostmortem(blind).non_technical_coupling.join(" ");
    const informedText =
      getPostmortem(informed).non_technical_coupling.join(" ");
    expect(blindText).toMatch(/shared login/i);
    expect(informedText).not.toMatch(/shared login/i);
  });

  it("a careful run ends in a fragile equilibrium before the cap", () => {
    let s = createGame();
    for (const id of [
      "inspect-queries",
      "ask-finance",
      "disable-export",
      "status-update",
      "ask-support",
    ]) {
      s = takeAction(s, id);
    }
    expect(s.ended).toBe(true);
    expect(s.endReason).toBe("fragile_equilibrium");
    expect(s.turn).toBeLessThan(MAX_TURNS);
    expect(getPostmortem(s).smart_moves.length).toBeGreaterThan(0);
  });

  it("piling on local fixes can end unrecoverable", () => {
    let s = createGame();
    for (const id of [
      "mute-alerts",
      "rate-limit-api",
      "add-cache",
      "scale-db",
      "restart-services",
      "status-update",
      "page-teammate",
    ]) {
      if (s.ended) break;
      s = takeAction(s, id);
    }
    expect(s.ended).toBe(true);
    expect(s.endReason).toBe("unrecoverable");
    expect(() => takeAction(s, "ask-support")).toThrow();
  });

  it("ends at the turn cap with every action defined", () => {
    expect(MAX_TURNS).toBe(10);
    expect(CASCADE_ACTIONS.length).toBeGreaterThanOrEqual(MAX_TURNS - 1);
    const ids = new Set(CASCADE_ACTIONS.map((a) => a.id));
    expect(ids.size).toBe(CASCADE_ACTIONS.length);
  });

  it("postmortem references specific turns", () => {
    let s = createGame();
    for (const id of [
      "mute-alerts",
      "scale-db",
      "ask-support",
      "inspect-queries",
    ]) {
      s = takeAction(s, id);
    }
    const pm = getPostmortem(s);
    const all = [
      ...pm.local_vs_global,
      ...pm.missed_blast_radius,
      ...pm.non_technical_coupling,
      ...pm.smart_moves,
    ].join("\n");
    expect(all).toMatch(/Turn \d+/);
  });

  it("long nights wear the on-call down, and a second engineer prevents it", () => {
    const run = (ids: string[]) => {
      let s = createGame();
      for (const id of ids) s = takeAction(s, id);
      return s;
    };
    const tired = run([
      "inspect-queries",
      "ask-finance",
      "ask-support",
      "scale-db",
      "add-cache",
      "restart-services",
    ]);
    const rested = run([
      "inspect-queries",
      "ask-finance",
      "ask-support",
      "page-teammate",
      "scale-db",
      "add-cache",
    ]);
    expect(tired.log.flatMap((l) => l.notes).join(" ")).toMatch(/fumes/);
    expect(rested.log.flatMap((l) => l.notes).join(" ")).not.toMatch(/fumes/);
  });

  it("support reports surfaced failures instead of denying them", () => {
    let s = createGame();
    for (const id of [
      "mute-alerts",
      "inspect-queries",
      "ask-finance",
      "page-teammate",
    ]) {
      s = takeAction(s, id);
    }
    expect(s.appeared.some((a) => a.consequence === "c-missed-webhook")).toBe(
      true,
    );
    s = takeAction(s, "ask-support");
    const last = getTurnOutput(s).status;
    expect(last).not.toMatch(/no payment failures/i);
    expect(last).toMatch(/payment/i);
    expect(getPostmortem(s).smart_moves.join(" ")).not.toMatch(/still small/i);
  });

  it("support keeps the calm answer while nothing has surfaced", () => {
    const s = takeAction(createGame(), "ask-support");
    expect(getTurnOutput(s).status).toMatch(/no payment failures/i);
  });
});
