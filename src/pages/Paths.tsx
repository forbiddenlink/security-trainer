import React from "react";
import { PathCard } from "../components/PathCard";
import { LEARNING_PATHS } from "../data/learningPaths";
import { useGameStore } from "../store/gameStore";

export const Paths: React.FC = () => {
  const { completedPaths } = useGameStore();
  const totalBonus = LEARNING_PATHS.reduce((s, p) => s + p.certificateXp, 0);

  return (
    <div className="space-y-10">
      <header className="grid gap-6 md:grid-cols-[minmax(0,1fr)_auto] md:items-end border-b border-border pb-8">
        <div>
          <p className="range-readout mb-3">
            <span className="range-dot" aria-hidden="true" />
            Specializations · {LEARNING_PATHS.length} tracks ·{" "}
            {completedPaths.length} certified
          </p>
          <h1 className="text-display max-w-[14ch]">Learning Paths</h1>
          <p className="mt-4 text-muted-foreground max-w-[60ch]">
            Ordered tracks of modules that build on each other. Finish every
            module in a track to earn its certification and bonus XP.
          </p>
        </div>
        <dl className="flex gap-8 font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground">
          <div>
            <dt>Certified</dt>
            <dd className="mt-1 font-display text-h2 font-extrabold [font-stretch:75%] normal-case tracking-normal text-foreground tabular-nums">
              {completedPaths.length}/{LEARNING_PATHS.length}
            </dd>
          </div>
          <div>
            <dt>Bonus XP</dt>
            <dd className="mt-1 font-display text-h2 font-extrabold [font-stretch:75%] normal-case tracking-normal text-foreground tabular-nums">
              {totalBonus.toLocaleString()}
            </dd>
          </div>
        </dl>
      </header>

      <section aria-label="Learning paths">
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {LEARNING_PATHS.map((path, index) => (
            <PathCard key={path.id} path={path} index={index} />
          ))}
        </div>
      </section>

      <p className="text-body-sm text-muted-foreground border-t border-border pt-4">
        Take tracks in any order. Advanced tracks unlock after you complete a
        set number of modules. Certifications appear on your profile.
      </p>
    </div>
  );
};
