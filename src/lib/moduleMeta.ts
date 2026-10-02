import type { Lesson, Module } from "../types";

// Estimates are derived from existing content, not stored data:
// theory reads at 200 wpm (min 2), quizzes take 2 min, labs take 10 min.
const WORDS_PER_MINUTE = 200;
const QUIZ_MINUTES = 2;
const LAB_MINUTES = 10;

export type ModuleStatus = "new" | "in-progress" | "done";

export function estimateLessonMinutes(lesson: Lesson): number {
  if (lesson.type === "quiz") return QUIZ_MINUTES;
  if (lesson.type === "lab") return LAB_MINUTES;
  const wordCount = lesson.content.trim().split(/\s+/).filter(Boolean).length;
  return Math.max(2, Math.round(wordCount / WORDS_PER_MINUTE));
}

export function estimateModuleMinutes(module: Module): number {
  return module.lessons.reduce((sum, l) => sum + estimateLessonMinutes(l), 0);
}

export function getRemainingMinutes(
  module: Module,
  completedLessons: readonly string[],
): number {
  return module.lessons
    .filter((l) => !completedLessons.includes(l.id))
    .reduce((sum, l) => sum + estimateLessonMinutes(l), 0);
}

export function formatMinutes(minutes: number): string {
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  return rest === 0 ? `${hours} hr` : `${hours} hr ${rest} min`;
}

export function getLessonMix(module: Module): Record<Lesson["type"], number> {
  const mix: Record<Lesson["type"], number> = { theory: 0, quiz: 0, lab: 0 };
  for (const lesson of module.lessons) mix[lesson.type] += 1;
  return mix;
}

export function getNextLesson(
  module: Module,
  completedLessons: readonly string[],
): Lesson | undefined {
  return module.lessons.find((l) => !completedLessons.includes(l.id));
}

export function getModuleStatus(
  module: Module,
  completedModules: readonly string[],
  completedLessons: readonly string[],
): ModuleStatus {
  if (completedModules.includes(module.id)) return "done";
  if (module.lessons.some((l) => completedLessons.includes(l.id))) {
    return "in-progress";
  }
  return "new";
}
