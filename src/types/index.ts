export interface Module {
    id: string;
    title: string;
    description: string;
    difficulty: 'Beginner' | 'Intermediate' | 'Advanced';
    xpReward: number;
    lessons: Lesson[];
    locked: boolean;
}

export interface Lesson {
    id: string;
    title: string;
    type: 'theory' | 'quiz' | 'lab';
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
    badges: string[];
    currentModuleId: string | null;
    streakDays: number;
    lastLoginDate: string | null;
}
