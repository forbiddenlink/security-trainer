import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { MODULES } from '../data/modules';
import { CodeEditor } from '../components/CodeEditor';
import { useGameStore } from '../store/gameStore';
import { verifyLabSubmission } from '../utils/labVerification';
import { ChevronRight, ChevronLeft, CheckCircle, XCircle, Play, AlertTriangle } from 'lucide-react';
import { clsx } from 'clsx';
import { motion, AnimatePresence } from 'framer-motion';

export const LessonView: React.FC = () => {
    const { moduleId } = useParams<{ moduleId: string }>();
    const navigate = useNavigate();
    const { completeModule, addXp } = useGameStore();

    const module = MODULES.find(m => m.id === moduleId);
    const [currentLessonIndex, setCurrentLessonIndex] = useState(0);
    const [code, setCode] = useState('');
    const [labOutput, setLabOutput] = useState<{ type: 'success' | 'error' | 'info'; message: string } | null>(null);
    const [quizSelectedOption, setQuizSelectedOption] = useState<number | null>(null);
    const [quizSubmitted, setQuizSubmitted] = useState(false);

    const currentLesson = module?.lessons[currentLessonIndex];
    const isFirstLesson = currentLessonIndex === 0;
    const isLastLesson = module && currentLessonIndex === module.lessons.length - 1;

    useEffect(() => {
        if (!currentLesson) return;

        if (currentLesson.type === 'lab' && currentLesson.lab) {
            setCode(currentLesson.lab.initialCode);
            setLabOutput(null);
        } else if (currentLesson.type === 'quiz') {
            setQuizSelectedOption(null);
            setQuizSubmitted(false);
        }
    }, [currentLessonIndex, currentLesson]);

    // Keyboard handler for quiz options
    const handleQuizKeyDown = useCallback((e: React.KeyboardEvent, idx: number) => {
        if (quizSubmitted) return;
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setQuizSelectedOption(idx);
        }
    }, [quizSubmitted]);

    if (!module || !currentLesson) return <div>Module not found</div>;

    const handleNext = () => {
        if (isLastLesson) {
            completeModule(module.id);
            addXp(module.xpReward);
            import('canvas-confetti')
                .then((confetti) => {
                    confetti.default({
                        particleCount: 100,
                        spread: 70,
                        origin: { y: 0.6 }
                    });
                })
                .catch(() => {
                    // Confetti animation failed to load - not critical
                });
            setTimeout(() => navigate('/modules'), 1000);
        } else {
            setCurrentLessonIndex(prev => prev + 1);
        }
    };

    const handlePrev = () => {
        if (!isFirstLesson) {
            setCurrentLessonIndex(prev => prev - 1);
        }
    };

    const handleVerifyLab = () => {
        if (!currentLesson.lab) return;

        try {
            // Use the secure verification registry instead of eval
            const isCorrect = verifyLabSubmission(currentLesson.id, code);

            if (isCorrect) {
                setLabOutput({ type: 'success', message: 'Vulnerability Patched! Excellent work.' });
            } else {
                setLabOutput({ type: 'error', message: 'Vulnerability still present. Review the code.' });
            }
        } catch {
            setLabOutput({ type: 'error', message: 'Syntax Error or Runtime Exception' });
        }
    };

    return (
        <div className="flex flex-col h-[calc(100vh-100px)] -m-6">
            {/* Context Header */}
            <div className="bg-card border-b border-border p-4 flex items-center justify-between">
                <div>
                    <span className="text-xs text-muted-foreground uppercase tracking-wider font-bold">{module.title}</span>
                    <h2 className="text-lg font-bold flex items-center gap-2">
                        {currentLesson.title}
                        <span className="text-xs font-normal px-2 py-0.5 rounded-full bg-primary/10 text-primary capitalize">
                            {currentLesson.type}
                        </span>
                    </h2>
                </div>
                <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-muted-foreground" aria-live="polite">
                        Step {currentLessonIndex + 1} of {module.lessons.length}
                    </span>
                    <div
                        className="w-32 h-2 bg-muted rounded-full overflow-hidden"
                        role="progressbar"
                        aria-valuenow={currentLessonIndex + 1}
                        aria-valuemin={1}
                        aria-valuemax={module.lessons.length}
                        aria-label={`Lesson progress: step ${currentLessonIndex + 1} of ${module.lessons.length}`}
                    >
                        <div
                            className="h-full bg-primary transition-all duration-300"
                            style={{ width: `${((currentLessonIndex + 1) / module.lessons.length) * 100}%` }}
                        />
                    </div>
                </div>
            </div>

            {/* Main Content Area */}
            <div className="flex-1 overflow-hidden relative">
                <AnimatePresence mode="wait">
                    <motion.div
                        key={currentLesson.id}
                        initial={{ opacity: 0, x: 20 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: -20 }}
                        transition={{ duration: 0.3 }}
                        className="h-full overflow-auto p-8"
                    >
                        {/* THEORY VIEW */}
                        {currentLesson.type === 'theory' && (
                            <div className="max-w-3xl mx-auto prose prose-invert">
                                <div className="whitespace-pre-wrap font-sans text-lg leading-relaxed">
                                    {currentLesson.content}
                                </div>
                            </div>
                        )}

                        {/* QUIZ VIEW */}
                        {currentLesson.type === 'quiz' && currentLesson.quiz && (
                            <div className="max-w-2xl mx-auto mt-10">
                                <div className="bg-card border border-border rounded-xl p-8 shadow-sm" role="form" aria-labelledby="quiz-question">
                                    <h3 id="quiz-question" className="text-xl font-bold mb-6">{currentLesson.quiz.question}</h3>
                                    <div className="space-y-3" role="radiogroup" aria-label="Quiz options">
                                        {currentLesson.quiz.options.map((option, idx) => (
                                            <button
                                                key={idx}
                                                onClick={() => !quizSubmitted && setQuizSelectedOption(idx)}
                                                onKeyDown={(e) => handleQuizKeyDown(e, idx)}
                                                role="radio"
                                                aria-checked={quizSelectedOption === idx}
                                                aria-disabled={quizSubmitted}
                                                tabIndex={0}
                                                className={clsx(
                                                    "w-full text-left p-4 rounded-lg border transition-all flex items-center justify-between",
                                                    quizSelectedOption === idx ? "border-primary bg-primary/5" : "border-border hover:bg-muted/50",
                                                    quizSubmitted && idx === currentLesson.quiz!.correctAnswer ? "border-emerald-500 bg-emerald-500/10" : "",
                                                    quizSubmitted && quizSelectedOption === idx && idx !== currentLesson.quiz!.correctAnswer ? "border-destructive bg-destructive/10" : ""
                                                )}
                                            >
                                                <span>{option}</span>
                                                {quizSubmitted && idx === currentLesson.quiz!.correctAnswer && (
                                                    <>
                                                        <CheckCircle className="w-5 h-5 text-emerald-500" aria-hidden="true" />
                                                        <span className="sr-only">Correct answer</span>
                                                    </>
                                                )}
                                                {quizSubmitted && quizSelectedOption === idx && idx !== currentLesson.quiz!.correctAnswer && (
                                                    <>
                                                        <XCircle className="w-5 h-5 text-destructive" aria-hidden="true" />
                                                        <span className="sr-only">Incorrect answer</span>
                                                    </>
                                                )}
                                            </button>
                                        ))}
                                    </div>

                                    {!quizSubmitted ? (
                                        <button
                                            onClick={() => setQuizSubmitted(true)}
                                            disabled={quizSelectedOption === null}
                                            className="mt-6 w-full py-3 bg-primary text-primary-foreground font-bold rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
                                            aria-label="Submit your selected answer"
                                        >
                                            Submit Answer
                                        </button>
                                    ) : (
                                        <div
                                            className={clsx(
                                                "mt-6 p-4 rounded-lg border",
                                                quizSelectedOption === currentLesson.quiz.correctAnswer ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-500" : "bg-destructive/10 border-destructive/20 text-destructive"
                                            )}
                                            role="alert"
                                            aria-live="polite"
                                        >
                                            <p className="font-bold flex items-center gap-2">
                                                {quizSelectedOption === currentLesson.quiz.correctAnswer ? "Correct!" : "Incorrect"}
                                            </p>
                                            <p className="text-sm mt-1 text-foreground">{currentLesson.quiz.explanation}</p>
                                        </div>
                                    )}
                                </div>
                            </div>
                        )}

                        {/* LAB VIEW */}
                        {currentLesson.type === 'lab' && currentLesson.lab && (
                            <div className="flex flex-col lg:flex-row h-full gap-4">
                                <div className="lg:w-1/3 flex flex-col gap-4 overflow-auto pb-8">
                                    <div className="bg-card border border-border rounded-xl p-6">
                                        <h3 className="font-bold flex items-center gap-2 mb-2">
                                            <AlertTriangle className="w-5 h-5 text-yellow-500" aria-hidden="true" />
                                            Mission Objective
                                        </h3>
                                        <p className="text-muted-foreground">{currentLesson.lab.instructions}</p>
                                    </div>
                                    <div className="bg-muted/20 border border-border rounded-xl p-6 flex-1" aria-live="polite">
                                        <p className="text-sm font-mono text-muted-foreground opacity-50">Virtual Environment Active</p>
                                        {labOutput && (
                                            <div
                                                className={clsx(
                                                    "mt-4 p-4 rounded-lg border animate-in fade-in slide-in-from-bottom-2",
                                                    labOutput.type === 'success' ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-500" : "bg-destructive/10 border-destructive/20 text-destructive"
                                                )}
                                                role="alert"
                                            >
                                                <div className="font-bold flex items-center gap-2">
                                                    {labOutput.type === 'success' ? <CheckCircle className="w-4 h-4" aria-hidden="true" /> : <XCircle className="w-4 h-4" aria-hidden="true" />}
                                                    {labOutput.type === 'success' ? 'System Secured' : 'Vulnerability Detected'}
                                                </div>
                                                <p className="text-sm mt-1">{labOutput.message}</p>
                                            </div>
                                        )}
                                    </div>
                                </div>
                                <div className="lg:w-2/3 flex flex-col gap-2 h-full">
                                    <div className="flex-1 min-h-[400px]" aria-label="Code editor">
                                        <CodeEditor
                                            initialCode={code}
                                            onChange={(val) => setCode(val || '')}
                                        />
                                    </div>
                                    <div className="flex justify-end">
                                        <button
                                            onClick={handleVerifyLab}
                                            className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-700 text-white px-6 py-2 rounded-lg font-bold transition-colors"
                                            aria-label="Deploy patch and verify your code fix"
                                        >
                                            <Play className="w-4 h-4" aria-hidden="true" /> Deploy Patch
                                        </button>
                                    </div>
                                </div>
                            </div>
                        )}
                    </motion.div>
                </AnimatePresence>
            </div>

            {/* Footer Navigation */}
            <nav className="bg-card border-t border-border p-4 flex justify-between items-center" aria-label="Lesson navigation">
                <button
                    onClick={handlePrev}
                    disabled={isFirstLesson}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg hover:bg-muted disabled:opacity-50 disabled:cursor-not-allowed"
                    aria-label="Go to previous lesson"
                >
                    <ChevronLeft className="w-4 h-4" aria-hidden="true" /> Back
                </button>

                <button
                    onClick={handleNext}
                    disabled={(currentLesson.type === 'quiz' && !quizSubmitted) || (currentLesson.type === 'lab' && labOutput?.type !== 'success')}
                    className={clsx(
                        "flex items-center gap-2 px-6 py-2 rounded-lg font-bold transition-all disabled:opacity-50 disabled:cursor-not-allowed",
                        isLastLesson ? "bg-emerald-500 text-white hover:bg-emerald-600" : "bg-primary text-primary-foreground hover:bg-primary/90"
                    )}
                    aria-label={isLastLesson ? 'Complete this mission and return to modules' : 'Go to next lesson step'}
                >
                    {isLastLesson ? 'Complete Mission' : 'Next Step'} <ChevronRight className="w-4 h-4" aria-hidden="true" />
                </button>
            </nav>
        </div>
    );
};
