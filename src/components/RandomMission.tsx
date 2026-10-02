import React, { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Dices, ArrowRight } from "lucide-react";
import { MODULES } from "../data/modules";
import { useGameStore } from "../store/gameStore";
import { estimateModuleMinutes, formatMinutes } from "../lib/moduleMeta";

/** "Assign me something": a random unfinished module, with a reroll. */
export const RandomMission: React.FC = () => {
  const completedModules = useGameStore((s) => s.completedModules);
  const pool = useMemo(
    () => MODULES.filter((m) => !completedModules.includes(m.id)),
    [completedModules],
  );
  const [seed, setSeed] = useState(() => Math.random());
  const mission = pool.length
    ? pool[Math.floor(seed * pool.length)]
    : undefined;

  if (!mission) {
    return (
      <div className="ui-card ui-card-md">
        <p className="ui-label mb-2">Random assignment</p>
        <p className="text-body-sm text-muted-foreground">
          Every module is complete. Try the CTF board next.
        </p>
      </div>
    );
  }

  return (
    <div className="ui-card ui-card-md mission-card flex flex-col">
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="ui-label flex items-center gap-2">
            <Dices className="w-3.5 h-3.5" aria-hidden="true" />
            Random assignment
          </p>
          <h3 className="text-h3 mt-2">Assign me something</h3>
        </div>
        <button
          type="button"
          onClick={() => setSeed(Math.random())}
          className="font-mono text-caption uppercase tracking-[0.12em] text-muted-foreground hover:text-foreground underline-offset-4 hover:underline"
        >
          Reroll
        </button>
      </div>
      <div
        className="mt-5 border-t border-border pt-4 flex-1"
        aria-live="polite"
      >
        <p className="font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground">
          {mission.difficulty} · {mission.lessons.length} lessons ·{" "}
          {formatMinutes(estimateModuleMinutes(mission))}
        </p>
        <p className="mt-1 text-h4">{mission.title}</p>
      </div>
      <Link
        to={`/modules/${mission.id}`}
        className="ui-button-secondary mt-5 self-start group"
      >
        Accept mission
        <ArrowRight
          className="w-4 h-4 group-hover:translate-x-0.5 transition-transform"
          aria-hidden="true"
        />
      </Link>
    </div>
  );
};
