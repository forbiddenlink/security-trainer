import { MODULES } from "../data/modules";
import { LEARNING_PATHS } from "../data/learningPaths";

/**
 * Field rank, derived from completed modules and certified paths. Paths are
 * required from Operative up so a rank means breadth, not only volume.
 */
export interface Rank {
  name: string;
  modules: number;
  paths: number;
}

export const RANKS: readonly Rank[] = [
  { name: "Recruit", modules: 0, paths: 0 },
  { name: "Field Agent", modules: 3, paths: 0 },
  { name: "Operative", modules: 10, paths: 1 },
  { name: "Specialist", modules: 20, paths: 2 },
  { name: "Handler", modules: 30, paths: 4 },
  { name: "Director", modules: MODULES.length, paths: LEARNING_PATHS.length },
];

export interface RankStatus {
  current: Rank;
  next: Rank | null;
  /** 0..1 toward the next rank, by the slower of the two requirements. */
  progress: number;
}

export function getRank(modulesDone: number, pathsDone: number): RankStatus {
  let index = 0;
  RANKS.forEach((r, i) => {
    if (modulesDone >= r.modules && pathsDone >= r.paths) index = i;
  });
  const current = RANKS[index];
  const next = RANKS[index + 1] ?? null;
  if (!next) return { current, next, progress: 1 };
  const part = (done: number, from: number, to: number): number =>
    to <= from ? 1 : Math.min(1, Math.max(0, (done - from) / (to - from)));
  const progress = Math.min(
    part(modulesDone, current.modules, next.modules),
    part(pathsDone, current.paths, next.paths),
  );
  return { current, next, progress };
}
