import React, { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { prefersReducedMotion } from "../utils/prefersReducedMotion";
import { motion } from "framer-motion";
import { clsx } from "clsx";
import { Timer, Skull, CheckCircle, Zap } from "lucide-react";
import { MODULES } from "../data/modules";
import { useGameStore } from "../store/gameStore";
import { Button } from "../components/ui";
import type { QuizQuestion } from "../types";

const EXAM_SECONDS = 60;
const EXAM_QUESTIONS = 5;

function drawQuestions(): (QuizQuestion & { moduleId: string })[] {
  const pool: (QuizQuestion & { moduleId: string })[] = [];
  MODULES.forEach((mod) => {
    mod.lessons.forEach((lesson) => {
      if (lesson.type === "quiz" && lesson.quiz) {
        pool.push({ ...lesson.quiz, moduleId: mod.id });
      }
    });
  });

  // Fisher-Yates shuffle for proper randomization
  const shuffled = [...pool];
  for (let i = shuffled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled.slice(0, EXAM_QUESTIONS);
}

export const Challenge: React.FC = () => {
  const navigate = useNavigate();
  const { unlockBadge, addXp } = useGameStore();
  const [questions, setQuestions] = useState<
    (QuizQuestion & { moduleId: string })[]
  >([]);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [timeLeft, setTimeLeft] = useState(EXAM_SECONDS);
  const [gameOver, setGameOver] = useState(false);
  const [userWon, setUserWon] = useState(false);
  const [gameStarted, setGameStarted] = useState(false);

  // Initialize game
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- one-time init on mount, not a cascade
    setQuestions(drawQuestions());
  }, []);

  const retry = () => {
    setQuestions(drawQuestions());
    setCurrentIndex(0);
    setTimeLeft(EXAM_SECONDS);
    setGameOver(false);
    setGameStarted(true);
  };

  // Timer logic
  useEffect(() => {
    if (!gameStarted || gameOver || userWon) return;

    const timer = setInterval(() => {
      setTimeLeft((prev) => {
        if (prev <= 1) {
          setGameOver(true);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [gameStarted, gameOver, userWon]);

  const handleAnswer = useCallback(
    (optionIndex: number) => {
      const currentQuestion = questions[currentIndex];

      if (optionIndex !== currentQuestion.correctAnswer) {
        setGameOver(true); // Permadeath
      } else {
        if (currentIndex === questions.length - 1) {
          setUserWon(true);
          addXp(1000);
          unlockBadge("badge-elite");
          if (!prefersReducedMotion()) {
            import("canvas-confetti")
              .then((confetti) => {
                confetti.default({ particleCount: 200, spread: 100 });
              })
              .catch(() => {
                // Confetti animation failed to load - not critical
              });
          }
        } else {
          setCurrentIndex((prev) => prev + 1);
        }
      }
    },
    [questions, currentIndex, addXp, unlockBadge],
  );

  // Keyboard handler for answer options
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent, idx: number) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        handleAnswer(idx);
      }
    },
    [handleAnswer],
  );

  if (!gameStarted) {
    return (
      <div
        className="max-w-3xl space-y-10"
        role="region"
        aria-label="Final exam start screen"
      >
        <header className="border-b border-border pb-8">
          <p className="range-readout mb-3">
            <span className="range-dot" aria-hidden="true" />
            Clearance protocol · alpha-7
          </p>
          <h1 className="text-display">FINAL EXAM</h1>
          <p className="mt-4 text-muted-foreground max-w-[56ch]">
            A timed run of questions drawn at random from every module&apos;s
            knowledge checks. Clear it to earn Elite Hacker status.
          </p>
        </header>
        <ol className="grid gap-px overflow-hidden rounded-[var(--radius-md)] border border-border bg-border sm:grid-cols-3">
          {[
            ["01", "60 Seconds.", "One clock for the whole run."],
            ["02", "5 Random Questions.", "Drawn from all 42 modules."],
            ["03", "One mistake ends the run.", "Read every option first."],
          ].map(([n, title, sub]) => (
            <li key={n} className="bg-background p-5">
              <p className="font-mono text-[11px] tracking-[0.12em] text-muted-foreground">
                {n}
              </p>
              <p
                className={clsx(
                  "mt-2 font-display text-h3 font-extrabold [font-stretch:80%]",
                  n === "03" && "text-destructive",
                )}
              >
                {title}
              </p>
              <p className="mt-1 text-body-sm text-muted-foreground">{sub}</p>
            </li>
          ))}
        </ol>
        <div className="flex flex-wrap items-center gap-4">
          <Button
            onClick={() => setGameStarted(true)}
            size="lg"
            variant="signal"
            className="px-8"
            aria-label="Start the final exam"
          >
            <Zap className="w-4 h-4" aria-hidden="true" />
            INITIATE PROTOCOL
          </Button>
          <p className="font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground">
            Reward · +1,000 XP · Elite Hacker badge
          </p>
        </div>
      </div>
    );
  }

  if (gameOver) {
    return (
      <div
        className="max-w-3xl border-l-[3px] border-destructive pl-6 py-2 space-y-5"
        role="alert"
        aria-live="assertive"
      >
        <p className="flex items-center gap-2 font-mono text-caption uppercase tracking-[0.14em] text-destructive">
          <Skull className="w-4 h-4" aria-hidden="true" />
          {timeLeft === 0 ? "Clock ran out" : "Wrong answer"} · question{" "}
          {currentIndex + 1} of {questions.length}
        </p>
        <h1 className="text-display text-destructive">MISSION FAILED</h1>
        <p className="text-body text-muted-foreground">
          The vulnerability remains unpatched.
        </p>
        <div className="flex flex-wrap gap-3">
          <Button onClick={retry} variant="signal" className="px-5">
            Try again
          </Button>
          <Button
            onClick={() => navigate("/")}
            variant="outline"
            className="px-5"
            aria-label="Return to dashboard"
          >
            Return to Base
          </Button>
        </div>
      </div>
    );
  }

  if (userWon) {
    return (
      <div
        className="max-w-3xl border-l-[3px] border-accent pl-6 py-2 space-y-5"
        role="alert"
        aria-live="polite"
      >
        <p className="flex items-center gap-2 font-mono text-caption uppercase tracking-[0.14em] text-accent">
          <CheckCircle className="w-4 h-4" aria-hidden="true" />
          {questions.length}/{questions.length} correct · {timeLeft}s left
        </p>
        <h1 className="text-display">MISSION ACCOMPLISHED</h1>
        <p className="text-h4 font-normal">
          You have earned the{" "}
          <span className="font-semibold">Elite Hacker</span> Status.
        </p>
        <Button
          onClick={() => navigate("/profile")}
          variant="signal"
          className="px-5"
          aria-label="View your profile and achievements"
        >
          View Status
        </Button>
      </div>
    );
  }

  const question = questions[currentIndex];

  if (!question) {
    return (
      <p className="py-20 font-mono text-caption uppercase tracking-[0.14em] text-muted-foreground">
        Loading questions...
      </p>
    );
  }

  return (
    <div className="max-w-3xl" aria-label="Final exam quiz">
      {/* HUD */}
      <div className="sticky top-16 z-10 -mx-4 mb-8 border-b border-border bg-background/92 px-4 py-3 backdrop-blur md:-mx-8 md:px-8">
        <div className="flex items-center justify-between gap-4">
          <div
            className={clsx(
              "flex items-center gap-2 font-mono text-h3 font-semibold tabular-nums",
              timeLeft <= 10 && "text-destructive",
            )}
            aria-live="polite"
            aria-atomic="true"
          >
            <Timer className="w-5 h-5" aria-hidden="true" />
            <span aria-label={`${timeLeft} seconds remaining`}>
              {timeLeft}s
            </span>
            <span className="sr-only">Time remaining: {timeLeft} seconds</span>
          </div>
          <div className="flex items-center gap-3">
            <ol className="flex gap-1" aria-hidden="true">
              {questions.map((_, i) => (
                <li
                  key={i}
                  className={clsx(
                    "h-1.5 w-6",
                    i < currentIndex
                      ? "bg-foreground/70"
                      : i === currentIndex
                        ? "bg-primary"
                        : "bg-muted",
                  )}
                />
              ))}
            </ol>
            <p
              className="font-mono text-caption uppercase tracking-[0.12em] text-muted-foreground"
              aria-live="polite"
            >
              Question {currentIndex + 1} of {questions.length}
            </p>
          </div>
        </div>
        <div className="mt-3 h-1 bg-muted" aria-hidden="true">
          <div
            className={clsx(
              "h-full transition-[width] duration-1000 ease-linear",
              timeLeft <= 10 ? "bg-destructive" : "bg-foreground",
            )}
            style={{ width: `${(timeLeft / EXAM_SECONDS) * 100}%` }}
          />
        </div>
      </div>

      {/* Question */}
      <motion.div
        key={currentIndex}
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.18 }}
        role="form"
        aria-labelledby="challenge-question"
      >
        <p className="ui-label mb-3">Question {currentIndex + 1}</p>
        <h2
          id="challenge-question"
          className="text-h3 md:text-h2 mb-8 max-w-[34ch]"
        >
          {question.question}
        </h2>
        <div
          className="space-y-3"
          role="radiogroup"
          aria-label="Answer options"
        >
          {question.options.map((option, idx) => (
            <button
              key={idx}
              onClick={() => handleAnswer(idx)}
              onKeyDown={(e) => handleKeyDown(e, idx)}
              role="radio"
              aria-checked={false}
              tabIndex={0}
              className="group flex w-full min-h-[56px] items-center gap-3 rounded-[var(--radius-sm)] border border-border px-4 py-3 text-left transition-colors hover:border-foreground hover:bg-muted"
              aria-label={`Option ${String.fromCharCode(65 + idx)}: ${option}`}
            >
              <span
                className="quiz-key group-hover:!border-foreground"
                aria-hidden="true"
              >
                {String.fromCharCode(65 + idx)}
              </span>
              {option}
            </button>
          ))}
        </div>
      </motion.div>
    </div>
  );
};
