import {
  CASCADE_ACTIONS,
  CASCADE_CONSEQUENCES,
  CASCADE_STABLE_HEALTH,
  CASCADE_START_CONSTRAINTS,
  CASCADE_START_HEALTH,
  CASCADE_START_SYMPTOMS,
  type ActionDef,
  type ConsequenceDef,
} from "../data/cascadingFailureScenario";

/**
 * Deterministic engine for the Cascading Failure game. All state is plain
 * JSON so it can be stored and passed back each turn. `health`, `fatigue`,
 * `flags` and `pending` are hidden: the UI only sees `getTurnOutput`.
 */

export const MAX_TURNS = 10;

export type EndReason = "unrecoverable" | "fragile_equilibrium" | "turn_cap";

interface Pending {
  consequence: string;
  causedOn: number;
  dueTurn: number;
}

interface LogEntry {
  turn: number;
  actionId: string;
  notes: string[];
}

interface Appeared {
  consequence: string;
  causedOn: number;
  appearedOn: number;
}

export interface GameState {
  turn: number;
  health: number;
  fatigue: number;
  stability: number;
  symptoms: string[];
  constraints: string[];
  flags: string[];
  used: string[];
  pending: Pending[];
  appeared: Appeared[];
  usedOnTurn: Record<string, number>;
  creditedMoves: { turn: number; text: string }[];
  log: LogEntry[];
  ended: boolean;
  endReason: EndReason | null;
}

export interface TurnOutput {
  turn: number;
  status: string;
  symptoms: string[];
  constraints: string[];
  stability_points: number;
  ended: boolean;
}

export interface Postmortem {
  local_vs_global: string[];
  missed_blast_radius: string[];
  non_technical_coupling: string[];
  delayed_failures: {
    caused_on_turn: number;
    appeared_on_turn: number;
    what: string;
  }[];
  smart_moves: string[];
}

const ACTIONS = new Map<string, ActionDef>(
  CASCADE_ACTIONS.map((a) => [a.id, a]),
);
const CONSEQUENCES = new Map<string, ConsequenceDef>(
  CASCADE_CONSEQUENCES.map((c) => [c.id, c]),
);

export function createGame(): GameState {
  return {
    turn: 0,
    health: CASCADE_START_HEALTH,
    fatigue: 0,
    stability: 0,
    symptoms: [...CASCADE_START_SYMPTOMS],
    constraints: [...CASCADE_START_CONSTRAINTS],
    flags: [],
    used: [],
    pending: [],
    appeared: [],
    usedOnTurn: {},
    creditedMoves: [],
    log: [],
    ended: false,
    endReason: null,
  };
}

const addUnique = (list: string[], items: string[] = []) => {
  for (const i of items) if (!list.includes(i)) list.push(i);
};
const removeAll = (list: string[], items: string[] = []) =>
  list.filter((i) => !items.includes(i));

function clone(s: GameState): GameState {
  return JSON.parse(JSON.stringify(s)) as GameState;
}

export function takeAction(prev: GameState, actionId: string): GameState {
  if (prev.ended) throw new Error("The incident has ended.");
  const action = ACTIONS.get(actionId);
  if (!action) throw new Error(`Unknown action: ${actionId}`);
  if (prev.used.includes(actionId)) throw new Error("Action already used.");

  const s = clone(prev);
  const turn = s.turn + 1;
  const healthBefore = s.health;
  const notes: string[] = [];

  // 1. Delayed consequences that come due this turn.
  const due = s.pending.filter((p) => p.dueTurn <= turn);
  s.pending = s.pending.filter((p) => p.dueTurn > turn);
  for (const p of due) {
    const c = CONSEQUENCES.get(p.consequence);
    if (!c) continue;
    s.health += c.health;
    s.fatigue += c.fatigue ?? 0;
    addUnique(s.symptoms, c.addSymptoms);
    s.symptoms = removeAll(s.symptoms, c.removeSymptoms);
    addUnique(s.constraints, c.addConstraints);
    addUnique(s.flags, c.setFlags);
    s.appeared.push({
      consequence: c.id,
      causedOn: p.causedOn,
      appearedOn: turn,
    });
    notes.push(c.text);
  }

  // 2. Immediate effects of the player's action.
  s.health += action.health;
  s.fatigue = Math.max(0, s.fatigue + (action.fatigue ?? 0));
  addUnique(s.symptoms, action.addSymptoms);
  s.symptoms = removeAll(s.symptoms, action.removeSymptoms);
  addUnique(s.constraints, action.addConstraints);
  addUnique(s.flags, action.setFlags);
  s.used.push(action.id);
  s.usedOnTurn[action.id] = turn;
  const variant =
    action.variant &&
    s.appeared.some((a) => action.variant!.ifAppeared.includes(a.consequence))
      ? action.variant
      : null;
  notes.unshift(variant ? variant.result : action.result);

  // 3. Queue new delayed consequences.
  for (const sch of action.schedule ?? []) {
    if (sch.ifFlag && !s.flags.includes(sch.ifFlag)) continue;
    if (sch.unlessFlag && s.flags.includes(sch.unlessFlag)) continue;
    s.pending.push({
      consequence: sch.consequence,
      causedOn: turn,
      dueTurn: turn + sch.delay,
    });
  }

  // 4. Long nights wear you down; tired on-call makes mistakes.
  if (turn >= 3) s.fatigue += 1;
  if (s.fatigue >= 4) {
    s.health -= 3;
    notes.push(
      "You are running on fumes and a command goes to the wrong host.",
    );
  }

  s.turn = turn;
  if (s.health >= healthBefore) s.stability += 1;
  const credit = variant ? variant.smart : action.smart;
  if (credit && s.health >= healthBefore) {
    s.creditedMoves.push({ turn, text: credit });
  }
  s.log.push({ turn, actionId, notes });

  // 5. End conditions.
  if (s.health <= 0) {
    s.ended = true;
    s.endReason = "unrecoverable";
  } else if (
    s.flags.includes("rootMitigated") &&
    s.pending.length === 0 &&
    s.health >= CASCADE_STABLE_HEALTH
  ) {
    s.ended = true;
    s.endReason = "fragile_equilibrium";
  } else if (turn >= MAX_TURNS) {
    s.ended = true;
    s.endReason = "turn_cap";
  }
  return s;
}

const END_TEXT: Record<EndReason, string> = {
  unrecoverable:
    "The system has tipped past what you can recover tonight. Time to hand over and write it up.",
  fragile_equilibrium:
    "Things are holding. It is not fixed for good, but nothing is getting worse right now.",
  turn_cap:
    "The night is over. Whatever is still queued will arrive after your shift.",
};

export function getTurnOutput(s: GameState): TurnOutput {
  let status: string;
  if (s.turn === 0) {
    status = "Start of shift. Pick one action or one question per turn.";
  } else {
    const last = s.log[s.log.length - 1];
    status = last.notes.join(" ");
    if (s.ended && s.endReason) status += " " + END_TEXT[s.endReason];
  }
  return {
    turn: s.turn,
    status,
    symptoms: [...s.symptoms],
    constraints: [...s.constraints],
    stability_points: s.stability,
    ended: s.ended,
  };
}

export function getPostmortem(s: GameState): Postmortem {
  const pm: Postmortem = {
    local_vs_global: [],
    missed_blast_radius: [],
    non_technical_coupling: [],
    delayed_failures: [],
    smart_moves: [],
  };
  for (const a of s.appeared) {
    const c = CONSEQUENCES.get(a.consequence);
    const action = CASCADE_ACTIONS.find(
      (x) => s.usedOnTurn[x.id] === a.causedOn,
    );
    if (!c) continue;
    const line = `Turn ${a.causedOn} (${action?.label ?? "an earlier move"}), showed up on turn ${a.appearedOn}: ${c.lesson}`;
    if (c.category === "local_vs_global") pm.local_vs_global.push(line);
    else if (c.category === "blast_radius") pm.missed_blast_radius.push(line);
    else pm.non_technical_coupling.push(line);
    pm.delayed_failures.push({
      caused_on_turn: a.causedOn,
      appeared_on_turn: a.appearedOn,
      what: c.text,
    });
  }
  for (const p of s.pending) {
    const c = CONSEQUENCES.get(p.consequence);
    if (!c) continue;
    const line = `Turn ${p.causedOn}: ${c.lesson} It had not surfaced when the shift ended (due turn ${p.dueTurn}).`;
    if (c.category === "non_technical") pm.non_technical_coupling.push(line);
    else pm.missed_blast_radius.push(line);
  }
  for (const m of s.creditedMoves)
    pm.smart_moves.push(`Turn ${m.turn}: ${m.text}`);
  return pm;
}
