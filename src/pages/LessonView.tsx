import React, { useState, useEffect, lazy, Suspense } from "react";
import { useParams, useNavigate, useSearchParams } from "react-router-dom";
import { MODULES } from "../data/modules";
import { useGameStore } from "../store/gameStore";
// Import light views directly (not via the barrel) so the barrel's static
// LabView re-export doesn't pull Monaco/xterm back into this chunk.
import { TheoryView } from "../components/lesson/TheoryView";
import { QuizView } from "../components/lesson/QuizView";

// Lazy-loaded: LabView pulls in Monaco + xterm, only needed for lab lessons.
const LabView = lazy(() =>
  import("../components/lesson/LabView").then((m) => ({ default: m.LabView })),
);
import { ReviewModal } from "../components/ReviewModal";
import { LiveLabTargets } from "../components/LiveLabTargets";
import { Button, EmptyState, Progress } from "../components/ui";
import {
  ChevronRight,
  ChevronLeft,
  ChevronDown,
  Check,
  BookOpen,
  Code,
  HelpCircle,
} from "lucide-react";
import { clsx } from "clsx";
import { formatMinutes, getRemainingMinutes } from "../lib/moduleMeta";
import { motion, AnimatePresence } from "framer-motion";
import { prefersReducedMotion } from "../utils/prefersReducedMotion";

export const LessonView: React.FC = () => {
  const { moduleId, lessonId } = useParams<{
    moduleId: string;
    lessonId?: string;
  }>();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const {
    completeModule,
    completeLesson,
    addXp,
    isLessonDueForReview,
    completedModules,
    completedLessons,
  } = useGameStore();

  // Check if this is a review session
  const isReviewSession = searchParams.get("review") === "true";

  const module = MODULES.find((m) => m.id === moduleId);

  // Find initial lesson index from URL param, or default to 0
  const initialLessonIndex =
    lessonId && module
      ? Math.max(
          0,
          module.lessons.findIndex((l) => l.id === lessonId),
        )
      : 0;
  const [currentLessonIndex, setCurrentLessonIndex] =
    useState(initialLessonIndex);
  const [quizCompleted, setQuizCompleted] = useState(false);
  const [labCompleted, setLabCompleted] = useState(false);
  const [showLessonMenu, setShowLessonMenu] = useState(false);
  const [showReviewModal, setShowReviewModal] = useState(false);
  const [reviewLessonId, setReviewLessonId] = useState<string | null>(null);
  const [reviewLessonTitle, setReviewLessonTitle] = useState<string>("");
  const [showComplete, setShowComplete] = useState(false);

  const currentLesson = module?.lessons[currentLessonIndex];
  const isFirstLesson = currentLessonIndex === 0;
  const isLastLesson =
    module && currentLessonIndex === module.lessons.length - 1;

  // Reset completion state when lesson changes
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- intentional reset on lesson navigation, not a cascade
    setQuizCompleted(false);
    setLabCompleted(false);
  }, [currentLessonIndex]);

  if (!module || !currentLesson) {
    return (
      <EmptyState
        className="min-h-[50vh]"
        title="Mission not found"
        description="This module or lesson does not exist. Return to Active Operations."
        action={
          <Button onClick={() => navigate("/modules")} variant="primary">
            Back to Modules
          </Button>
        }
      />
    );
  }

  const getLessonIcon = (type: string) => {
    switch (type) {
      case "theory":
        return BookOpen;
      case "lab":
        return Code;
      case "quiz":
        return HelpCircle;
      default:
        return BookOpen;
    }
  };

  const jumpToLesson = (index: number) => {
    setCurrentLessonIndex(index);
    setShowLessonMenu(false);
  };

  const fireConfetti = () => {
    if (prefersReducedMotion()) return;
    import("canvas-confetti")
      .then((confetti) => {
        confetti.default({
          particleCount: 100,
          spread: 70,
          origin: { y: 0.6 },
        });
      })
      .catch(() => {
        // Confetti animation failed to load - not critical
      });
  };

  const handleNext = () => {
    // Check if this lesson is due for review before completing
    const isDueForReview =
      isReviewSession || isLessonDueForReview(currentLesson.id);

    // Mark current lesson as complete (this initializes review tracking for new lessons)
    completeLesson(currentLesson.id, module.id);

    // Award module-completion rewards on the last lesson BEFORE any review-modal
    // interrupt, so finishing a module always grants its XP and celebration even
    // when the final lesson also happens to be due for review.
    if (isLastLesson) {
      completeModule(module.id);
      // Pass moduleId to apply difficulty multiplier
      addXp(module.xpReward, module.id);
      fireConfetti();
    }

    // Show review modal if this lesson was due for review
    if (isDueForReview) {
      setReviewLessonId(currentLesson.id);
      setReviewLessonTitle(currentLesson.title);
      setShowReviewModal(true);
      return; // Don't navigate yet, wait for review modal
    }

    if (isLastLesson) {
      setShowComplete(true);
    } else {
      setCurrentLessonIndex((prev) => prev + 1);
    }
  };

  // Next uncompleted module to recommend after finishing this one
  const nextModule = MODULES.find(
    (m) => m.id !== module.id && !completedModules.includes(m.id),
  );

  const handleReviewModalClose = () => {
    setShowReviewModal(false);
    // Return to modules after finishing the final lesson, otherwise back to the
    // dashboard where remaining reviews surface.
    navigate(isLastLesson ? "/modules" : "/");
  };

  const handlePrev = () => {
    if (!isFirstLesson) {
      setCurrentLessonIndex((prev) => prev - 1);
    }
  };

  const opNumber = String(MODULES.indexOf(module) + 1).padStart(2, "0");
  const minutesLeft = getRemainingMinutes(module, completedLessons);

  return (
    <div className="flex flex-col min-h-[calc(100dvh-64px)]">
      <div className="sticky top-16 z-10 border-b border-border bg-background/92 backdrop-blur px-4 py-3 md:px-8 flex items-center justify-between gap-4">
        <div className="min-w-0">
          <p className="flex items-center gap-2 range-readout mb-1 truncate">
            <span className="range-dot" aria-hidden="true" />
            <span className="truncate">
              OP-{opNumber} · <span>{module.title}</span>
            </span>
          </p>
          <div className="flex items-center gap-2 min-w-0">
            <h1 className="text-h4 font-body [font-stretch:100%] tracking-normal truncate">
              {currentLesson.title}
            </h1>
            <span className="ui-chip shrink-0">{currentLesson.type}</span>
          </div>
        </div>
        <div className="flex items-center gap-3 md:gap-5 shrink-0">
          <ol
            className="hidden md:flex items-center gap-1"
            aria-label="Lesson steps"
          >
            {module.lessons.map((lesson, idx) => {
              const done = completedLessons.includes(lesson.id);
              const isCurrent = idx === currentLessonIndex;
              return (
                <li key={lesson.id}>
                  <button
                    type="button"
                    onClick={() => jumpToLesson(idx)}
                    className="group grid h-6 place-items-center px-0.5"
                    aria-label={`Go to step ${idx + 1}: ${lesson.title}${done ? " (completed)" : ""}`}
                    aria-current={isCurrent ? "step" : undefined}
                  >
                    <span
                      className={clsx(
                        "block h-1.5 w-6 transition-colors",
                        isCurrent
                          ? "bg-primary"
                          : done
                            ? "bg-foreground/70"
                            : "bg-muted group-hover:bg-foreground/30",
                      )}
                    />
                  </button>
                </li>
              );
            })}
          </ol>
          <div className="relative">
            <button
              onClick={() => setShowLessonMenu(!showLessonMenu)}
              className="h-9 inline-flex items-center gap-2 font-mono text-caption uppercase tracking-[0.1em] text-muted-foreground hover:text-foreground transition-colors px-3 rounded-[var(--radius-sm)] border border-border hover:border-foreground"
              aria-expanded={showLessonMenu}
              aria-haspopup="true"
              aria-label={`Step ${currentLessonIndex + 1} of ${module.lessons.length}. Click to see all lessons.`}
            >
              Step {currentLessonIndex + 1} of {module.lessons.length}
              <ChevronDown
                className={clsx(
                  "w-4 h-4 transition-transform",
                  showLessonMenu && "rotate-180",
                )}
                aria-hidden="true"
              />
            </button>
            {showLessonMenu && (
              <>
                <div
                  className="fixed inset-0 z-40"
                  onClick={() => setShowLessonMenu(false)}
                  aria-hidden="true"
                />
                <div
                  className="absolute right-0 top-full mt-2 w-80 max-w-[88vw] ui-card ui-card-elevated z-50 !p-1.5 max-h-80 overflow-auto"
                  role="menu"
                  aria-label="Lesson navigation"
                >
                  {module.lessons.map((lesson, idx) => {
                    const Icon = getLessonIcon(lesson.type);
                    const isCurrent = idx === currentLessonIndex;
                    const done = completedLessons.includes(lesson.id);
                    return (
                      <button
                        key={lesson.id}
                        onClick={() => jumpToLesson(idx)}
                        role="menuitem"
                        className={clsx(
                          "w-full text-left px-3 py-2.5 flex items-center gap-3 rounded-[var(--radius-sm)] hover:bg-muted transition-colors",
                          isCurrent && "bg-muted",
                        )}
                      >
                        <span
                          className={clsx(
                            "w-6 h-6 rounded-[var(--radius-xs)] grid place-items-center font-mono text-[11px] font-semibold",
                            isCurrent
                              ? "bg-primary text-primary-foreground"
                              : done
                                ? "bg-foreground/80 text-background"
                                : "border border-border text-muted-foreground",
                          )}
                        >
                          {done && !isCurrent ? (
                            <Check className="w-3.5 h-3.5" />
                          ) : (
                            idx + 1
                          )}
                        </span>
                        <Icon
                          className="w-4 h-4 text-muted-foreground"
                          aria-hidden="true"
                        />
                        <span className="flex-1 truncate text-sm">
                          {lesson.title}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </>
            )}
          </div>
          <Progress
            className="sr-only"
            value={currentLessonIndex + 1}
            min={1}
            max={module.lessons.length}
            aria-label={`Lesson progress: step ${currentLessonIndex + 1} of ${module.lessons.length}`}
          />
        </div>
      </div>

      <div className="flex-1 relative">
        <AnimatePresence mode="wait">
          <motion.div
            key={currentLesson.id}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.2, ease: [0.2, 0.8, 0.2, 1] }}
            className="px-4 py-8 md:px-8 md:py-10"
          >
            {currentLesson.type === "theory" && (
              <div className="grid gap-10 xl:grid-cols-[minmax(0,1fr)_260px] max-w-[1100px]">
                <div className="space-y-8 min-w-0">
                  <TheoryView content={currentLesson.content || ""} />
                  <LiveLabTargets moduleId={module.id} />
                </div>
                <aside className="hidden xl:block" aria-label="Mission outline">
                  <div className="sticky top-40 border-t border-border pt-4">
                    <p className="ui-label mb-3">Mission outline</p>
                    <ol className="space-y-1">
                      {module.lessons.map((lesson, idx) => {
                        const done = completedLessons.includes(lesson.id);
                        const isCurrent = idx === currentLessonIndex;
                        return (
                          <li key={lesson.id}>
                            <button
                              type="button"
                              onClick={() => jumpToLesson(idx)}
                              className={clsx(
                                "w-full text-left flex gap-3 py-1.5 text-[13px] leading-snug",
                                isCurrent
                                  ? "text-foreground font-medium"
                                  : "text-muted-foreground hover:text-foreground",
                              )}
                            >
                              <span className="font-mono text-[11px] tabular-nums w-5 shrink-0 pt-px">
                                {done ? "✓" : String(idx + 1).padStart(2, "0")}
                              </span>
                              <span>{lesson.title}</span>
                            </button>
                          </li>
                        );
                      })}
                    </ol>
                    <p className="mt-4 pt-3 border-t border-border font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground tabular-nums">
                      {formatMinutes(minutesLeft)} left in mission
                    </p>
                  </div>
                </aside>
              </div>
            )}

            {currentLesson.type === "quiz" && currentLesson.quiz && (
              <div className="max-w-2xl">
                <QuizView
                  key={currentLesson.id}
                  quiz={currentLesson.quiz}
                  onComplete={() => setQuizCompleted(true)}
                />
              </div>
            )}

            {currentLesson.type === "lab" && currentLesson.lab && (
              <div className="space-y-6">
                <div className="lg:h-[calc(100dvh-64px-77px-73px-80px)] lg:min-h-[560px]">
                  <Suspense
                    fallback={
                      <div className="grid h-[480px] place-items-center ui-card">
                        <p className="font-mono text-caption uppercase tracking-[0.12em] text-muted-foreground">
                          Loading workspace…
                        </p>
                      </div>
                    }
                  >
                    <LabView
                      key={currentLesson.id}
                      lab={currentLesson.lab}
                      lessonId={currentLesson.id}
                      onSuccess={() => setLabCompleted(true)}
                    />
                  </Suspense>
                </div>
                <LiveLabTargets moduleId={module.id} />
              </div>
            )}
          </motion.div>
        </AnimatePresence>
      </div>

      <nav
        className="sticky bottom-0 z-10 border-t border-border bg-background/92 backdrop-blur px-4 py-3 md:px-8 flex justify-between items-center gap-3"
        aria-label="Lesson navigation"
      >
        <Button
          onClick={handlePrev}
          disabled={isFirstLesson}
          variant="outline"
          aria-label="Go to previous lesson"
        >
          <ChevronLeft className="w-4 h-4" aria-hidden="true" /> Back
        </Button>

        <p className="hidden sm:block font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground tabular-nums">
          {currentLesson.type === "quiz" && !quizCompleted
            ? "Answer correctly to continue"
            : currentLesson.type === "lab" && !labCompleted
              ? "Deploy a passing patch to continue"
              : `${formatMinutes(minutesLeft)} left`}
        </p>

        <Button
          onClick={handleNext}
          disabled={
            (currentLesson.type === "quiz" && !quizCompleted) ||
            (currentLesson.type === "lab" && !labCompleted)
          }
          variant={isLastLesson ? "signal" : "primary"}
          className="px-5"
          aria-label={
            isLastLesson
              ? "Complete this mission and return to modules"
              : "Go to next lesson step"
          }
        >
          {isLastLesson ? "Complete Mission" : "Next Step"}{" "}
          <ChevronRight className="w-4 h-4" aria-hidden="true" />
        </Button>
      </nav>

      {/* Mission complete panel with next-mission recommendation */}
      {showComplete && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur px-4"
          role="dialog"
          aria-modal="true"
          aria-label="Mission complete"
        >
          <div className="ui-card ui-card-elevated ui-card-lg range-ticks relative max-w-md w-full text-center space-y-4">
            <span className="range-readout justify-center">
              Debrief · OP-{opNumber}
            </span>
            <h2 className="text-h2">Mission Complete</h2>
            <p className="text-muted-foreground">
              You cleared{" "}
              <span className="text-foreground">{module.title}</span> and banked
              +{module.xpReward} XP.
            </p>
            <div className="flex flex-col gap-2 pt-1">
              {nextModule ? (
                <Button
                  variant="signal"
                  className="w-full justify-center h-auto min-h-12 py-3"
                  onClick={() => navigate(`/modules/${nextModule.id}`)}
                >
                  Start Next Mission: {nextModule.title}
                  <ChevronRight className="w-4 h-4" aria-hidden="true" />
                </Button>
              ) : (
                <p className="text-body-sm text-accent">
                  Every module cleared. Outstanding work, operator.
                </p>
              )}
              <Button
                variant="outline"
                className="w-full justify-center"
                onClick={() => navigate("/modules")}
              >
                Back to Modules
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Review Modal for spaced repetition */}
      <ReviewModal
        isOpen={showReviewModal}
        onClose={handleReviewModalClose}
        lessonId={reviewLessonId || ""}
        lessonTitle={reviewLessonTitle}
      />
    </div>
  );
};
