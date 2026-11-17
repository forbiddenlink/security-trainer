import { create } from "zustand";
import { persist } from "zustand/middleware";
import {
  applyChoice,
  emptyProgress,
  normalizeProgress,
  resetLevel,
  type ChoiceResult,
  type ScamProgress,
} from "../lib/scamSurvival";

/**
 * Saved Scam Survival progress and display settings. Guest mode never calls
 * `record`: the page keeps guest progress in component state instead, so
 * nothing is written to storage. Local only: no cloud sync, no DB change.
 */
interface ScamStore {
  progress: ScamProgress;
  textOnly: boolean;
  highContrast: boolean;
  humour: boolean;
  record: (
    scenarioId: string,
    choiceId: string,
    opts?: { practice?: boolean },
  ) => ChoiceResult;
  resetLevel: (level: number) => void;
  setSetting: (key: "textOnly" | "highContrast" | "humour", v: boolean) => void;
  resetAll: () => void;
}

export const useScamStore = create<ScamStore>()(
  persist(
    (set, get) => ({
      progress: emptyProgress(),
      textOnly: false,
      highContrast: false,
      humour: true,
      record: (scenarioId, choiceId, opts) => {
        const { progress, result } = applyChoice(
          get().progress,
          scenarioId,
          choiceId,
          opts,
        );
        set({ progress });
        return result;
      },
      resetLevel: (level) =>
        set((s) => ({ progress: resetLevel(s.progress, level) })),
      setSetting: (key, v) => set({ [key]: v }),
      resetAll: () => set({ progress: emptyProgress() }),
    }),
    {
      name: "scam-survival-storage",
      partialize: (s) => ({
        progress: s.progress,
        textOnly: s.textOnly,
        highContrast: s.highContrast,
        humour: s.humour,
      }),
      merge: (persisted, current) => {
        const p = (persisted ?? {}) as Partial<ScamStore>;
        return {
          ...current,
          progress: normalizeProgress(p.progress),
          textOnly: p.textOnly === true,
          highContrast: p.highContrast === true,
          humour: p.humour !== false,
        };
      },
    },
  ),
);
