import React, { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { prefersReducedMotion } from "../utils/prefersReducedMotion";
import { motion } from "framer-motion";
import { clsx } from "clsx";
import { Timer, AlertTriangle, Skull, CheckCircle } from "lucide-react";
import { MODULES } from "../data/modules";
import { useGameStore } from "../store/gameStore";
import { Button, Card } from "../components/ui";
import type { QuizQuestion } from "../types";

export const Challenge: React.FC = () => {
  const navigate = useNavigate();
  const { unlockBadge, addXp } = useGameStore();
  const [questions, setQuestions] = useState<
    (QuizQuestion & { moduleId: string })[]
  >([]);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [timeLeft, setTimeLeft] = useState(60);
  const [gameOver, setGameOver] = useState(false);
  const [userWon, setUserWon] = useState(false);
  const [gameStarted, setGameStarted] = useState(false);

  // Initialize game
  useEffect(() => {
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
    // eslint-disable-next-line react-hooks/set-state-in-effect -- one-time init on mount, not a cascade
    setQuestions(shuffled.slice(0, 5));
  }, []);

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
        className="flex flex-col items-center justify-center h-full max-w-2xl mx-auto text-center space-y-8 animate-in fade-in zoom-in duration-500"
        role="region"
        aria-label="Final exam start screen"
      >
        <div
          className="p-7 rounded-full bg-destructive/10 border-2 border-destructive/30 animate-pulse"
          aria-hidden="true"
        >
          <AlertTriangle className="w-20 h-20 text-destructive" />
        </div>
        <h1 className="text-display text-foreground">FINAL EXAM</h1>
        <p className="text-h4 text-muted-foreground font-normal">
          60 Seconds. 5 Random Questions. <br />
          <span className="text-destructive font-semibold">
            One mistake ends the run.
          </span>
        </p>
        <Button
          onClick={() => setGameStarted(true)}
          variant="destructive"
          size="lg"
          className="px-8 text-body"
          aria-label="Start the final exam"
        >
          INITIATE PROTOCOL
        </Button>
      </div>
    );
  }

  if (gameOver) {
    return (
      <div
        className="flex flex-col items-center justify-center h-full text-center space-y-6"
        role="alert"
        aria-live="assertive"
      >
        <Skull className="w-28 h-28 text-destructive" aria-hidden="true" />
        <h1 className="text-h1 text-destructive">MISSION FAILED</h1>
        <p className="text-body text-muted-foreground">
          The vulnerability remains unpatched.
        </p>
        <Button
          onClick={() => navigate("/")}
          variant="outline"
          className="px-5"
          aria-label="Return to dashboard"
        >
          Return to Base
        </Button>
      </div>
    );
  }

  if (userWon) {
    return (
      <div
        className="flex flex-col items-center justify-center h-full text-center space-y-6"
        role="alert"
        aria-live="polite"
      >
        <CheckCircle className="w-28 h-28 text-accent" aria-hidden="true" />
        <h1 className="text-h1 text-accent">MISSION ACCOMPLISHED</h1>
        <p className="text-h4 font-normal">
          You have earned the{" "}
          <span className="font-semibold text-warning">Elite Hacker</span>{" "}
          Status.
        </p>
        <Button
          onClick={() => navigate("/profile")}
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
      <div className="flex items-center justify-center h-full">
        <p className="text-muted-foreground">Loading questions...</p>
      </div>
    );
  }

  return (
    <div
      className="max-w-3xl mx-auto h-full flex flex-col justify-center"
      role="main"
      aria-label="Final exam quiz"
    >
      {/* HUD */}
      <Card className="ui-card-md flex justify-between items-center mb-8">
        <div
          className={clsx(
            "flex items-center gap-2 text-h2 font-mono font-bold text-destructive",
            timeLeft <= 10 && "animate-pulse",
          )}
          aria-live="polite"
          aria-atomic="true"
        >
          <Timer className="w-8 h-8" aria-hidden="true" />
          <span aria-label={`${timeLeft} seconds remaining`}>{timeLeft}s</span>
          <span className="sr-only">Time remaining: {timeLeft} seconds</span>
        </div>
        <div className="text-muted-foreground text-body-sm" aria-live="polite">
          Question {currentIndex + 1} of {questions.length}
        </div>
      </Card>

      {/* Question Card */}
      <motion.div
        key={currentIndex}
        initial={{ opacity: 0, x: 50 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.2 }}
        className="ui-card ui-card-lg ui-card-elevated"
        role="form"
        aria-labelledby="challenge-question"
      >
        <h2 id="challenge-question" className="text-h2 mb-8">
          {question.question}
        </h2>
        <div
          className="space-y-4"
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
              className="w-full text-left p-4 rounded-[var(--radius-sm)] bg-muted/40 hover:bg-primary/8 border border-border/50 hover:border-primary/50 transition-all duration-150 group"
              aria-label={`Option ${String.fromCharCode(65 + idx)}: ${option}`}
            >
              <span
                className="font-mono text-primary mr-4 opacity-50 group-hover:opacity-100"
                aria-hidden="true"
              >
                {String.fromCharCode(65 + idx)}.
              </span>
              {option}
            </button>
          ))}
        </div>
      </motion.div>
    </div>
  );
};
