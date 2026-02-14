import React, { memo, useState, useCallback } from "react";
import type { QuizQuestion } from "../../types";
import { CheckCircle, XCircle } from "lucide-react";
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
      <div className="max-w-2xl mx-auto mt-10">
        <div
          className="bg-card border border-border rounded-xl p-8 shadow-sm"
          role="form"
          aria-labelledby="quiz-question"
        >
          <h3 id="quiz-question" className="text-xl font-bold mb-6">
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
                  "w-full text-left p-4 rounded-lg border transition-all flex items-center justify-between",
                  selectedOption === idx
                    ? "border-primary bg-primary/5"
                    : "border-border hover:bg-muted/50",
                  submitted && idx === quiz.correctAnswer
                    ? "border-emerald-500 bg-emerald-500/10"
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
            <button
              onClick={handleSubmit}
              disabled={selectedOption === null}
              className="mt-6 w-full py-3 bg-primary text-primary-foreground font-bold rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
              aria-label="Submit your selected answer"
            >
              Submit Answer
            </button>
          ) : (
            <div
              className={clsx(
                "mt-6 p-4 rounded-lg border",
                selectedOption === quiz.correctAnswer
                  ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-500"
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
        </div>
      </div>
    );
  },
);

QuizView.displayName = "QuizView";
