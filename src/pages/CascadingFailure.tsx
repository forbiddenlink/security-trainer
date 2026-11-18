import React, { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { clsx } from "clsx";
import {
  CASCADE_ACTIONS,
  CASCADE_SETUP,
  CASCADE_TITLE,
} from "../data/cascadingFailureScenario";
import {
  MAX_TURNS,
  createGame,
  getPostmortem,
  getTurnOutput,
  takeAction,
  type GameState,
} from "../lib/cascadingFailure";

const POSTMORTEM_SECTIONS = [
  ["local_vs_global", "Where a local fix hurt the whole"],
  ["missed_blast_radius", "Where the blast radius was missed"],
  ["non_technical_coupling", "Where people and process mattered most"],
  ["smart_moves", "Smart moves that bought time"],
] as const;

export const CascadingFailure: React.FC = () => {
  const [game, setGame] = useState<GameState>(() => createGame());
  const out = useMemo(() => getTurnOutput(game), [game]);
  const postmortem = useMemo(
    () => (game.ended ? getPostmortem(game) : null),
    [game],
  );

  const questions = CASCADE_ACTIONS.filter((a) => a.kind === "question");
  const actions = CASCADE_ACTIONS.filter((a) => a.kind === "action");

  const renderButtons = (list: typeof CASCADE_ACTIONS) => (
    <ul className="space-y-2">
      {list.map((a) => {
        const used = game.used.includes(a.id);
        return (
          <li key={a.id}>
            <button
              type="button"
              disabled={used || game.ended}
              onClick={() => setGame((g) => takeAction(g, a.id))}
              className={clsx(
                "btn-ghost-rule w-full text-left",
                (used || game.ended) && "opacity-50 cursor-not-allowed",
              )}
            >
              {a.label}
            </button>
          </li>
        );
      })}
    </ul>
  );

  return (
    <div className="max-w-4xl space-y-8">
      <header>
        <p className="range-readout mb-3">
          <span className="range-dot" aria-hidden="true" />
          Incident practice
        </p>
        <h1 className="text-display">Cascading failure</h1>
        <p className="mt-4 text-muted-foreground max-w-[60ch]">
          {CASCADE_TITLE}. {CASCADE_SETUP} There is no perfect fix. Each move
          has side effects, and some show up a few turns later. You get up to{" "}
          {MAX_TURNS} turns. Do one thing per turn: take an action or ask one
          question. For the framework behind this, see the{" "}
          <Link
            to="/modules/incident-response"
            className="underline underline-offset-4"
          >
            Incident Response module
          </Link>
          .
        </p>
      </header>

      <section aria-labelledby="cf-status" className="ui-card p-5 space-y-4">
        <div className="flex items-baseline justify-between gap-4">
          <h2 id="cf-status" className="text-h2">
            Status
          </h2>
          <p className="font-mono text-caption tabular-nums" aria-live="polite">
            Turn {out.turn} of {MAX_TURNS}, stability points{" "}
            {out.stability_points}
          </p>
        </div>
        <p aria-live="polite">{out.status}</p>
        <div className="grid gap-6 sm:grid-cols-2">
          <div>
            <h3 className="ui-label mb-2">What you can see</h3>
            <ul className="list-disc pl-5 space-y-1">
              {out.symptoms.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="ui-label mb-2">Constraints in force</h3>
            <ul className="list-disc pl-5 space-y-1">
              {out.constraints.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      {!game.ended && (
        <section aria-labelledby="cf-moves" className="space-y-5">
          <h2 id="cf-moves" className="text-h2">
            Your move
          </h2>
          <div>
            <h3 className="ui-label mb-2">Ask a question</h3>
            {renderButtons(questions)}
          </div>
          <div>
            <h3 className="ui-label mb-2">Take an action</h3>
            {renderButtons(actions)}
          </div>
        </section>
      )}

      {postmortem && (
        <section aria-labelledby="cf-pm" className="ui-card p-5 space-y-5">
          <h2 id="cf-pm" className="text-h2">
            Postmortem
          </h2>
          {POSTMORTEM_SECTIONS.map(([key, title]) => (
            <div key={key}>
              <h3 className="ui-label mb-2">{title}</h3>
              {postmortem[key].length === 0 ? (
                <p className="text-muted-foreground">Nothing to report.</p>
              ) : (
                <ul className="list-disc pl-5 space-y-1">
                  {postmortem[key].map((line) => (
                    <li key={line}>{line}</li>
                  ))}
                </ul>
              )}
            </div>
          ))}
          <div>
            <h3 className="ui-label mb-2">Delayed failures</h3>
            {postmortem.delayed_failures.length === 0 ? (
              <p className="text-muted-foreground">None this time.</p>
            ) : (
              <ul className="list-disc pl-5 space-y-1">
                {postmortem.delayed_failures.map((d) => (
                  <li key={`${d.caused_on_turn}-${d.what}`}>
                    Caused on turn {d.caused_on_turn}, appeared on turn{" "}
                    {d.appeared_on_turn}: {d.what}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </section>
      )}

      <div>
        <button
          type="button"
          className="btn-ghost-rule"
          onClick={() => setGame(createGame())}
        >
          Start over
        </button>
      </div>
    </div>
  );
};
