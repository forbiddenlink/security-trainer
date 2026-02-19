import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { MODULES } from "../data/modules";
import { useGameStore } from "../store/gameStore";
import { TheoryView, QuizView, LabView } from "../components/lesson";
import { Button, Progress } from "../components/ui";
import {
  ChevronRight,
  ChevronLeft,
  ChevronDown,
  BookOpen,
  Code,
  HelpCircle,
} from "lucide-react";
import { clsx } from "clsx";
import { motion, AnimatePresence } from "framer-motion";

export const LessonView: React.FC = () => {
  const { moduleId, lessonId } = useParams<{
    moduleId: string;
    lessonId?: string;
  }>();
  const navigate = useNavigate();
  const { completeModule, completeLesson, addXp } = useGameStore();

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

  const currentLesson = module?.lessons[currentLessonIndex];
  const isFirstLesson = currentLessonIndex === 0;
  const isLastLesson =
    module && currentLessonIndex === module.lessons.length - 1;

  // Reset completion state when lesson changes
  useEffect(() => {
    setQuizCompleted(false);
    setLabCompleted(false);
  }, [currentLessonIndex]);

  if (!module || !currentLesson) return <div>Module not found</div>;

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

  const handleNext = () => {
    // Mark current lesson as complete
    completeLesson(currentLesson.id, module.id);

    if (isLastLesson) {
      completeModule(module.id);
      // Pass moduleId to apply difficulty multiplier
      addXp(module.xpReward, module.id);
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
      setTimeout(() => navigate("/modules"), 1000);
    } else {
      setCurrentLessonIndex((prev) => prev + 1);
    }
  };

  const handlePrev = () => {
    if (!isFirstLesson) {
      setCurrentLessonIndex((prev) => prev - 1);
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-88px)] -mx-4 -my-4 md:-mx-6 md:-my-6">
      <div className="border-b border-border/70 bg-card/92 backdrop-blur px-4 py-3 md:px-6 flex items-center justify-between gap-4">
        <div>
          <span className="ui-label">{module.title}</span>
          <h2 className="text-h4 flex items-center gap-2">
            {currentLesson.title}
            <span className="ui-chip border-primary/30 bg-primary/10 text-primary capitalize">
              {currentLesson.type}
            </span>
          </h2>
        </div>
        <div className="flex items-center gap-2 md:gap-3">
          <div className="relative">
            <button
              onClick={() => setShowLessonMenu(!showLessonMenu)}
              className="h-9 inline-flex items-center gap-2 text-body-sm font-medium text-muted-foreground hover:text-foreground transition-colors px-3 rounded-[var(--radius-sm)] hover:bg-muted/40"
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
                  className="absolute right-0 top-full mt-2 w-80 max-w-[88vw] ui-card ui-card-elevated z-50 py-2 max-h-80 overflow-auto"
                  role="menu"
                  aria-label="Lesson navigation"
                >
                  {module.lessons.map((lesson, idx) => {
                    const Icon = getLessonIcon(lesson.type);
                    const isCurrent = idx === currentLessonIndex;
                    return (
                      <button
                        key={lesson.id}
                        onClick={() => jumpToLesson(idx)}
                        role="menuitem"
                        className={clsx(
                          "w-full text-left px-4 py-2.5 flex items-center gap-3 hover:bg-muted/40 transition-colors",
                          isCurrent && "bg-primary/10 text-primary",
                        )}
                      >
                        <span
                          className={clsx(
                            "w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold",
                            isCurrent
                              ? "bg-primary text-primary-foreground"
                              : "bg-muted text-muted-foreground",
                          )}
                        >
                          {idx + 1}
                        </span>
                        <Icon
                          className="w-4 h-4 text-muted-foreground"
                          aria-hidden="true"
                        />
                        <span className="flex-1 truncate text-sm">
                          {lesson.title}
                        </span>
                        <span className="text-xs text-muted-foreground capitalize">
                          {lesson.type}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </>
            )}
          </div>
          <Progress
            className="hidden md:block w-36"
            value={currentLessonIndex + 1}
            min={1}
            max={module.lessons.length}
            aria-label={`Lesson progress: step ${currentLessonIndex + 1} of ${module.lessons.length}`}
          />
        </div>
      </div>

      <div className="flex-1 overflow-hidden relative">
        <AnimatePresence mode="wait">
          <motion.div
            key={currentLesson.id}
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }}
            transition={{ duration: 0.3 }}
            className="h-full overflow-auto px-4 py-6 md:px-8 md:py-8"
          >
            {currentLesson.type === "theory" && (
              <TheoryView content={currentLesson.content || ""} />
            )}

            {currentLesson.type === "quiz" && currentLesson.quiz && (
              <QuizView
                key={currentLesson.id}
                quiz={currentLesson.quiz}
                onComplete={() => setQuizCompleted(true)}
              />
            )}

            {currentLesson.type === "lab" && currentLesson.lab && (
              <LabView
                key={currentLesson.id}
                lab={currentLesson.lab}
                lessonId={currentLesson.id}
                onSuccess={() => setLabCompleted(true)}
              />
            )}
          </motion.div>
        </AnimatePresence>
      </div>

      <nav
        className="border-t border-border/70 bg-card/92 backdrop-blur px-4 py-3 md:px-6 flex justify-between items-center"
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

        <Button
          onClick={handleNext}
          disabled={
            (currentLesson.type === "quiz" && !quizCompleted) ||
            (currentLesson.type === "lab" && !labCompleted)
          }
          variant={isLastLesson ? "accent" : "primary"}
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
    </div>
  );
};
