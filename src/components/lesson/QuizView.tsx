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
      <div className="max-w-2xl mx-auto mt-4 md:mt-8">
        <Card
          className="p-6 md:p-8"
          role="form"
          aria-labelledby="quiz-question"
        >
          <h3
            id="quiz-question"
            className="text-xl font-semibold tracking-tight mb-6"
          >
            {quiz.question}
          </h3>
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
                  "w-full min-h-[52px] text-left p-4 rounded-[var(--radius-sm)] border transition-colors flex items-center justify-between",
                  selectedOption === idx
                    ? "border-2 border-primary bg-primary/8"
                    : "border-border hover:bg-muted/50",
                  submitted && idx === quiz.correctAnswer
                    ? "border-accent bg-accent/10"
                    : "",
                  submitted &&
                    selectedOption === idx &&
                    idx !== quiz.correctAnswer
                    ? "border-destructive bg-destructive/10"
                    : "",
                )}
              >
                <span>{option}</span>
                {submitted && idx === quiz.correctAnswer && (
                  <>
                    <CheckCircle
                      className="w-5 h-5 text-emerald-500"
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
              className="mt-6 w-full"
              aria-label="Submit your selected answer"
            >
              Submit Answer
            </Button>
          ) : (
            <div
              className={clsx(
                "mt-6 p-4 rounded-[var(--radius-sm)] border",
                selectedOption === quiz.correctAnswer
                  ? "bg-accent/10 border-accent/20 text-accent"
                  : "bg-destructive/10 border-destructive/20 text-destructive",
              )}
              role="alert"
              aria-live="polite"
            >
              <p className="font-bold flex items-center gap-2">
                {selectedOption === quiz.correctAnswer
                  ? "Correct!"
                  : "Incorrect"}
              </p>
              <p className="text-sm mt-1 text-foreground">{quiz.explanation}</p>
            </div>
          )}
        </Card>
      </div>
    );
  },
);

QuizView.displayName = "QuizView";
