export interface Module {
  id: string;
  title: string;
  description: string;
  difficulty: "Beginner" | "Intermediate" | "Advanced";
  xpReward: number;
  lessons: Lesson[];
  locked: boolean;
}

export interface Lesson {
  id: string;
  title: string;
  type: "theory" | "quiz" | "lab";
  content: string; // Markdown content for theory
  quiz?: QuizQuestion;
  lab?: LabConfig;
}

export interface QuizQuestion {
  question: string;
  options: string[];
  correctAnswer: number; // Index of the correct option
  explanation: string;
}

export interface LabConfig {
  initialCode: string;
  solutionCode: string;
  instructions: string;
}

export interface Badge {
  id: string;
  name: string;
  description: string;
  icon: string; // Lucide icon name or image path
  condition: string; // Description of how to unlock
}

export interface UserState {
  xp: number;
  level: number;
  completedModules: string[];
  completedLessons: string[];
  badges: string[];
  currentModuleId: string | null;
  streakDays: number;
  lastLoginDate: string | null;
  // Daily Challenge
  dailyChallengeId: string | null;
  dailyChallengeDate: string | null;
  dailyChallengeCompleted: boolean;
  // Spaced Repetition
  lessonReviews: Record<string, LessonReview>;
  // Learning Paths
  completedPaths: string[];
  // CTF Challenges
  ctfProgress: Record<string, CTFProgressState>;
  ctfTotalPoints: number;
}

export interface CTFProgressState {
  challengeId: string;
  solved: boolean;
  hintsRevealed: string[];
  attempts: number;
  solvedAt?: string;
  pointsEarned?: number;
}

export interface AchievementNotification {
  id: string;
  type: "badge" | "streak" | "module_complete" | "daily_challenge" | "review";
  title: string;
  message: string;
}

export interface LessonReview {
  lessonId: string;
  lastReviewDate: string; // ISO date string
  nextReviewDate: string; // ISO date string
  interval: number; // days until next review
  // FSRS-specific fields (for accurate scheduling)
  stability?: number; // Memory stability in days
  difficulty?: number; // Card difficulty (1-10)
  reps?: number; // Successful review count
  lapses?: number; // Times forgotten (rated Again)
  state?: number; // Card state (0=New, 1=Learning, 2=Review, 3=Relearning)
  // Legacy SM-2 fields (kept for backward compatibility)
  easeFactor: number; // SM-2 ease factor (default 2.5)
  reviewCount: number; // times reviewed
}

export interface LearningPath {
  id: string;
  title: string;
  codename: string; // Spy theme name
  description: string;
  difficulty: "Beginner" | "Intermediate" | "Advanced";
  modules: string[]; // Ordered module IDs
  certificateXp: number; // Bonus XP on completion
  icon: string; // Lucide icon name
  requiredCompletions?: number; // Modules needed to unlock
}

// CTF Challenge Types (re-exported from lib/ctf.ts for convenience)
export type { CTFCategory, CTFHint, CTFChallenge, CTFSubmission, CTFProgress } from '../lib/ctf';
