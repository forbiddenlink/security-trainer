import React, { memo, useState, useCallback } from "react";
import type { QuizQuestion } from "../../types";
import { CheckCircle, XCircle } from "lucide-react";
import { Button, Card } from "../ui";
import { clsx } from "clsx";

interface QuizViewProps {
  quiz: QuizQuestion;
  onComplete: () => void;
}

/**
 * Interactive quiz component with keyboard accessibility
 */
export const QuizView: React.FC<QuizViewProps> = memo(
  ({ quiz, onComplete }) => {
    const [selectedOption, setSelectedOption] = useState<number | null>(null);
    const [submitted, setSubmitted] = useState(false);

    const handleKeyDown = useCallback(
      (e: React.KeyboardEvent, idx: number) => {
        if (submitted) return;
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          setSelectedOption(idx);
        }
      },
      [submitted],
    );

    const handleSubmit = () => {
      setSubmitted(true);
      // Notify parent that quiz is complete (for navigation purposes)
      onComplete();
    };

    return (
      <div className="max-w-2xl">
        <Card
          className="ui-card-lg"
          role="form"
          aria-labelledby="quiz-question"
        >
          <p className="ui-label mb-3">Question</p>
          <h2 id="quiz-question" className="text-h2 mb-6">
            {quiz.question}
          </h2>
          <div
            className="space-y-3"
            role="radiogroup"
            aria-label="Quiz options"
          >
            {quiz.options.map((option, idx) => (
              <button
                key={idx}
                onClick={() => !submitted && setSelectedOption(idx)}
                onKeyDown={(e) => handleKeyDown(e, idx)}
                role="radio"
                aria-checked={selectedOption === idx}
                aria-disabled={submitted}
                tabIndex={0}
                className={clsx(
                  "w-full min-h-[56px] text-left px-4 py-3 rounded-[var(--radius-sm)] border transition-colors duration-150 flex items-center justify-between gap-3",
                  selectedOption === idx && !submitted
                    ? "border-foreground bg-muted shadow-[inset_3px_0_0_var(--color-primary)]"
                    : "border-border hover:border-foreground/60",
                  submitted && idx === quiz.correctAnswer
                    ? "!border-accent shadow-[inset_3px_0_0_var(--color-accent)]"
                    : "",
                  submitted &&
                    selectedOption === idx &&
                    idx !== quiz.correctAnswer
                    ? "!border-destructive shadow-[inset_3px_0_0_var(--color-destructive)]"
                    : "",
                )}
              >
                <span className="flex items-center gap-3 min-w-0">
                  <span
                    className={clsx(
                      "quiz-key",
                      submitted && idx === quiz.correctAnswer
                        ? "!border-accent !text-accent-foreground bg-accent"
                        : submitted && selectedOption === idx
                          ? "!border-destructive !text-destructive-foreground bg-destructive"
                          : selectedOption === idx && !submitted
                            ? "!border-foreground !text-background bg-foreground"
                            : "",
                    )}
                    aria-hidden="true"
                  >
                    {String.fromCharCode(65 + idx)}
                  </span>
                  <span>{option}</span>
                </span>
                {submitted && idx === quiz.correctAnswer && (
                  <>
                    <CheckCircle
                      className="w-5 h-5 text-accent"
                      aria-hidden="true"
                    />
                    <span className="sr-only">Correct answer</span>
                  </>
                )}
                {submitted &&
                  selectedOption === idx &&
                  idx !== quiz.correctAnswer && (
                    <>
                      <XCircle
                        className="w-5 h-5 text-destructive"
                        aria-hidden="true"
                      />
                      <span className="sr-only">Incorrect answer</span>
                    </>
                  )}
              </button>
            ))}
          </div>

          {!submitted ? (
            <Button
              onClick={handleSubmit}
              disabled={selectedOption === null}
              className="mt-6"
              aria-label="Submit your selected answer"
            >
              Submit Answer
            </Button>
          ) : (
            <div
              className={clsx(
                "mt-6 py-3 pl-4 border-l-[3px]",
                selectedOption === quiz.correctAnswer
                  ? "border-accent text-accent"
                  : "border-destructive text-destructive",
              )}
              role="alert"
              aria-live="polite"
            >
              <p className="range-verdict-title">
                {selectedOption === quiz.correctAnswer ? (
                  <>
                    <CheckCircle
                      className="w-4 h-4 shrink-0"
                      aria-hidden="true"
                    />
                    Target Neutralized
                  </>
                ) : (
                  <>
                    <XCircle className="w-4 h-4 shrink-0" aria-hidden="true" />
                    Breach Detected
                  </>
                )}
              </p>
              <p className="text-body-sm mt-2 text-foreground">
                {quiz.explanation}
              </p>
            </div>
          )}
        </Card>
      </div>
    );
  },
);

QuizView.displayName = "QuizView";
