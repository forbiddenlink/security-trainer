import React, { useState } from "react";
import { Link } from "react-router-dom";
import { clsx } from "clsx";
import {
  HABIT_BADGES,
  SCAM_LEVELS,
  type HabitTag,
  type ScamScenario,
} from "../data/scamScenarios";
import {
  applyChoice,
  earnedBadges,
  emptyProgress,
  isLevelComplete,
  isLevelUnlocked,
  nextScenario,
  resetLevel,
  scenariosForLevel,
  type ChoiceResult,
  type ScamProgress,
} from "../lib/scamSurvival";
import { useScamStore } from "../store/scamStore";
import { useAuthStore } from "../store/authStore";

const HABIT_PRAISE: Record<HabitTag, string> = {
  pause: "You paused before acting.",
  verify: "You checked through a channel you already trust.",
  resist_escalation: "You did not let the pressure set your pace.",
  balanced: "You judged each message on its merits.",
};

const HABIT_LABEL: Record<HabitTag, string> = {
  pause: "Pause",
  verify: "Verify",
  resist_escalation: "Resist pressure",
  balanced: "Stay balanced",
};

interface Round {
  scenario: ScamScenario;
  practice: boolean;
  chosen: string | null;
  result: ChoiceResult | null;
}

export const ScamSurvival: React.FC = () => {
  const user = useAuthStore((s) => s.user);
  const saved = useScamStore((s) => s.progress);
  const { textOnly, highContrast, humour } = useScamStore();
  const setSetting = useScamStore((s) => s.setSetting);
  const record = useScamStore((s) => s.record);
  const resetSaved = useScamStore((s) => s.resetLevel);

  const [optOut, setOptOut] = useState(false);
  const [guestProgress, setGuestProgress] =
    useState<ScamProgress>(emptyProgress);
  const [level, setLevel] = useState<number | null>(null);
  const [round, setRound] = useState<Round | null>(null);

  const guest = !user || optOut;
  const progress = guest ? guestProgress : saved;

  const startLevel = (lv: number, practice = false) => {
    setLevel(lv);
    const list = scenariosForLevel(lv);
    const next = practice ? list[0] : nextScenario(progress, lv);
    setRound(
      next ? { scenario: next, practice, chosen: null, result: null } : null,
    );
  };

  const choose = (choiceId: string) => {
    if (!round || round.chosen) return;
    let result: ChoiceResult;
    if (guest) {
      const out = applyChoice(guestProgress, round.scenario.id, choiceId, {
        practice: round.practice,
      });
      setGuestProgress(out.progress);
      result = out.result;
    } else {
      result = record(round.scenario.id, choiceId, {
        practice: round.practice,
      });
    }
    setRound({ ...round, chosen: choiceId, result });
  };

  const goNext = () => {
    if (!round || level === null) return;
    if (round.practice) {
      const list = scenariosForLevel(level);
      const i = list.findIndex((s) => s.id === round.scenario.id);
      const next = list[i + 1];
      setRound(
        next
          ? { scenario: next, practice: true, chosen: null, result: null }
          : null,
      );
      return;
    }
    const next = nextScenario(progress, level);
    setRound(
      next
        ? { scenario: next, practice: false, chosen: null, result: null }
        : null,
    );
  };

  const retry = () => {
    if (!round) return;
    setRound({ ...round, chosen: null, result: null });
  };

  const restartLevel = (lv: number) => {
    if (guest) setGuestProgress((p) => resetLevel(p, lv));
    else resetSaved(lv);
    setLevel(null);
    setRound(null);
  };

  const hc = highContrast;
  const btn = clsx(
    "w-full text-left px-4 py-3 rounded-[var(--radius-sm)] border",
    hc
      ? "border-2 border-white bg-black text-white hover:bg-white hover:text-black disabled:opacity-100 disabled:border-dashed"
      : "btn-ghost-rule",
  );

  const levelDone = level !== null && !round;

  return (
    <div
      className={clsx(
        "max-w-3xl space-y-8",
        hc && "bg-black text-white p-4 rounded-[var(--radius-sm)]",
      )}
      data-contrast={hc ? "high" : "normal"}
    >
      <header>
        <p className="range-readout mb-3">
          <span className="range-dot" aria-hidden="true" />
          Scam awareness
        </p>
        <h1 className="text-display">Scam survival</h1>
        <p
          className={clsx("mt-4 max-w-[60ch]", !hc && "text-muted-foreground")}
        >
          Short, made-up messages. Pick how you would respond. There are no
          scores against other people and no timers. Some messages are real, so
          the goal is good judgement, not fear.
        </p>
      </header>

      <fieldset className="flex flex-wrap gap-x-6 gap-y-2">
        <legend className="ui-label mb-2">Display and saving</legend>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={textOnly}
            onChange={(e) => setSetting("textOnly", e.target.checked)}
          />
          Text only
        </label>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={highContrast}
            onChange={(e) => setSetting("highContrast", e.target.checked)}
          />
          High contrast
        </label>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={humour}
            onChange={(e) => setSetting("humour", e.target.checked)}
          />
          Light humour
        </label>
        {user && (
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={optOut}
              onChange={(e) => setOptOut(e.target.checked)}
            />
            Guest mode (do not save)
          </label>
        )}
      </fieldset>
      {guest && (
        <p className={clsx(!hc && "text-muted-foreground")}>
          Guest mode: your progress is not saved and is lost when you leave this
          page.{!user && " Sign in to keep it."}
        </p>
      )}

      {level === null && (
        <>
          <section aria-labelledby="ss-levels" className="space-y-3">
            <h2 id="ss-levels" className="text-h2">
              Levels
            </h2>
            <ul className="space-y-2">
              {SCAM_LEVELS.map((lv) => {
                const unlocked = isLevelUnlocked(progress, lv.level);
                const total = scenariosForLevel(lv.level).length;
                const done = scenariosForLevel(lv.level).filter((s) =>
                  progress.completed.includes(s.id),
                ).length;
                return (
                  <li key={lv.level}>
                    <button
                      type="button"
                      className={clsx(btn, !unlocked && "opacity-60")}
                      disabled={!unlocked}
                      onClick={() => startLevel(lv.level)}
                    >
                      <span className="block font-medium">
                        Level {lv.level}: {lv.title}
                      </span>
                      <span className="block text-body-sm">
                        {lv.goal} {done} of {total} done.
                        {!unlocked &&
                          " Finish the level before it to open this one."}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </section>

          <section aria-labelledby="ss-habits" className="space-y-3">
            <h2 id="ss-habits" className="text-h2">
              Good habits
            </h2>
            <ul className="grid gap-2 sm:grid-cols-2">
              {HABIT_BADGES.map((b) => {
                const count = progress.habits[b.tag];
                const earned = earnedBadges(progress).some(
                  (e) => e.tag === b.tag,
                );
                return (
                  <li
                    key={b.tag}
                    className={clsx(
                      "p-3 border",
                      hc ? "border-white" : "ui-card",
                    )}
                  >
                    <p className="font-medium">
                      {b.name}
                      {earned ? " (earned)" : ""}
                    </p>
                    <p className="text-body-sm">{b.description}</p>
                    <p className="font-mono text-caption">
                      {HABIT_LABEL[b.tag]}: {count} of {b.threshold}
                    </p>
                  </li>
                );
              })}
            </ul>
          </section>
        </>
      )}

      {level !== null && (
        <section aria-labelledby="ss-play" className="space-y-5">
          <div className="flex flex-wrap items-baseline justify-between gap-3">
            <h2 id="ss-play" className="text-h2">
              Level {level}: {SCAM_LEVELS[level - 1].title}
            </h2>
            <button
              type="button"
              className="underline underline-offset-4"
              onClick={() => {
                setLevel(null);
                setRound(null);
              }}
            >
              Back to levels
            </button>
          </div>
          <p>
            Want the background? Read{" "}
            <Link
              to={`/modules/${SCAM_LEVELS[level - 1].lesson.moduleId}/${SCAM_LEVELS[level - 1].lesson.lessonId}`}
              className="underline underline-offset-4"
            >
              {SCAM_LEVELS[level - 1].lesson.label}
            </Link>
            .
          </p>

          {round && (
            <>
              {round.practice && (
                <p className="font-mono text-caption">
                  Practice: nothing here counts toward your level.
                </p>
              )}
              <section
                aria-label={`Message, ${round.scenario.scenario_type}`}
                className="space-y-2"
              >
                {round.scenario.messages.map((m, i) => (
                  <div
                    key={i}
                    className={clsx(
                      "p-3 whitespace-pre-wrap",
                      textOnly
                        ? "border-l-2 pl-3"
                        : hc
                          ? "border-2 border-white"
                          : "ui-card",
                    )}
                  >
                    <p className="font-mono text-caption">{m.from}</p>
                    <p>{m.text}</p>
                  </div>
                ))}
              </section>

              <ul className="space-y-2" aria-label="Your options">
                {round.scenario.choices.map((c) => (
                  <li key={c.id}>
                    <button
                      type="button"
                      className={btn}
                      disabled={round.chosen !== null}
                      aria-pressed={round.chosen === c.id}
                      onClick={() => choose(c.id)}
                    >
                      {c.label}
                    </button>
                  </li>
                ))}
              </ul>

              {round.result && (
                <div className="space-y-3" aria-live="polite">
                  <p>{round.result.choice.feedback}</p>
                  {round.scenario.is_legitimate && (
                    <p>This message was real.</p>
                  )}
                  {round.scenario.red_flags.length > 0 && (
                    <div>
                      <h3 className="ui-label mb-1">Red flags in this one</h3>
                      <ul className="list-disc pl-5">
                        {round.scenario.red_flags.map((f) => (
                          <li key={f}>{f}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {round.result.choice.outcome === "safe" ? (
                    <p>
                      Good habit: {HABIT_PRAISE[round.scenario.habit_tags[0]]}
                    </p>
                  ) : (
                    <p>
                      {round.result.reflection
                        ? "Everyone slips on these, and it is how the habit forms. Take a moment to think about what you would look for next time. Nothing is lost."
                        : "No penalty. You can try this one again."}
                    </p>
                  )}
                  {humour && round.scenario.quip && (
                    <p className="italic">{round.scenario.quip}</p>
                  )}
                  {round.result.newBadges.map((n) => (
                    <p key={n} className="font-medium">
                      Badge earned: {n}
                    </p>
                  ))}
                  <div className="flex flex-wrap gap-3">
                    {round.result.choice.outcome === "safe" ||
                    round.practice ? (
                      <button type="button" className={btn} onClick={goNext}>
                        Next
                      </button>
                    ) : (
                      <button type="button" className={btn} onClick={retry}>
                        Try again
                      </button>
                    )}
                  </div>
                </div>
              )}
            </>
          )}

          {levelDone && (
            <div className="space-y-3">
              <p className="font-medium">
                {isLevelComplete(progress, level)
                  ? "Level complete. Nice steady work."
                  : "That is all for this round."}
              </p>
              <div className="flex flex-wrap gap-3">
                <button
                  type="button"
                  className={btn}
                  onClick={() => startLevel(level, true)}
                >
                  Practice this level again
                </button>
                <button
                  type="button"
                  className={btn}
                  onClick={() => restartLevel(level)}
                >
                  Reset this level
                </button>
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  );
};
