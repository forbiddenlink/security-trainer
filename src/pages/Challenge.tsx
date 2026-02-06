import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Timer, AlertTriangle, Skull, CheckCircle } from 'lucide-react';
import { MODULES } from '../data/modules';
import { useGameStore } from '../store/gameStore';
import type { QuizQuestion } from '../types';

export const Challenge: React.FC = () => {
    const navigate = useNavigate();
    const { unlockBadge, addXp } = useGameStore();
    const [questions, setQuestions] = useState<(QuizQuestion & { moduleId: string })[]>([]);
    const [currentIndex, setCurrentIndex] = useState(0);
    const [timeLeft, setTimeLeft] = useState(60);
    const [gameOver, setGameOver] = useState(false);
    const [userWon, setUserWon] = useState(false);
    const [gameStarted, setGameStarted] = useState(false);

    // Initialize game
    useEffect(() => {
        const pool: (QuizQuestion & { moduleId: string })[] = [];
        MODULES.forEach(mod => {
            mod.lessons.forEach(lesson => {
                if (lesson.type === 'quiz' && lesson.quiz) {
                    pool.push({ ...lesson.quiz, moduleId: mod.id });
                }
            });
        });

        // Shuffle and pick 5
        const shuffled = pool.sort(() => 0.5 - Math.random());
        setQuestions(shuffled.slice(0, 5));
    }, []);

    // Timer logic
    useEffect(() => {
        if (!gameStarted || gameOver || userWon) return;

        const timer = setInterval(() => {
            setTimeLeft(prev => {
                if (prev <= 1) {
                    setGameOver(true);
                    return 0;
                }
                return prev - 1;
            });
        }, 1000);

        return () => clearInterval(timer);
    }, [gameStarted, gameOver, userWon]);

    const handleAnswer = (optionIndex: number) => {
        const currentQuestion = questions[currentIndex];

        if (optionIndex !== currentQuestion.correctAnswer) {
            setGameOver(true); // Permadeath
        } else {
            if (currentIndex === questions.length - 1) {
                setUserWon(true);
                addXp(1000);
                unlockBadge('badge-elite');
                import('canvas-confetti').then((confetti) => {
                    confetti.default({ particleCount: 200, spread: 100 });
                });
            } else {
                setCurrentIndex(prev => prev + 1);
            }
        }
    };

    if (!gameStarted) {
        return (
            <div className="flex flex-col items-center justify-center h-full max-w-2xl mx-auto text-center space-y-8 animate-in fade-in zoom-in duration-500">
                <div className="p-8 rounded-full bg-red-500/10 border-4 border-red-500/50 animate-pulse">
                    <AlertTriangle className="w-24 h-24 text-red-500" />
                </div>
                <h1 className="text-5xl font-black text-transparent bg-clip-text bg-gradient-to-r from-red-500 to-orange-500">
                    FINAL EXAM
                </h1>
                <p className="text-xl text-muted-foreground">
                    60 Seconds. 5 Random Questions. <br />
                    <span className="text-red-400 font-bold">One mistake ends the run.</span>
                </p>
                <button
                    onClick={() => setGameStarted(true)}
                    className="px-8 py-4 bg-red-600 hover:bg-red-700 text-white font-bold rounded-xl text-lg transition-all transform hover:scale-105 shadow-lg shadow-red-900/20"
                >
                    INITIATE PROTOCOL
                </button>
            </div>
        );
    }

    if (gameOver) {
        return (
            <div className="flex flex-col items-center justify-center h-full text-center space-y-6">
                <Skull className="w-32 h-32 text-red-600" />
                <h1 className="text-4xl font-bold text-red-500">MISSION FAILED</h1>
                <p className="text-muted-foreground">The vulnerability remains unpatched.</p>
                <button
                    onClick={() => navigate('/')}
                    className="px-6 py-2 border border-border rounded-lg hover:bg-muted transition-colors"
                >
                    Return to Base
                </button>
            </div>
        );
    }

    if (userWon) {
        return (
            <div className="flex flex-col items-center justify-center h-full text-center space-y-6">
                <CheckCircle className="w-32 h-32 text-emerald-500" />
                <h1 className="text-4xl font-bold text-emerald-400">MISSION ACCOMPLISHED</h1>
                <p className="text-xl">You have earned the <span className="font-bold text-yellow-400">Elite Hacker</span> Status.</p>
                <button
                    onClick={() => navigate('/profile')}
                    className="px-6 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 transition-colors"
                >
                    View Status
                </button>
            </div>
        );
    }

    const question = questions[currentIndex];

    return (
        <div className="max-w-3xl mx-auto h-full flex flex-col justify-center">
            {/* HUD */}
            <div className="flex justify-between items-center mb-8 bg-card border border-border p-4 rounded-xl">
                <div className="flex items-center gap-2 text-2xl font-mono font-bold text-red-500">
                    <Timer className="w-8 h-8" />
                    {timeLeft}s
                </div>
                <div className="text-muted-foreground">
                    Question {currentIndex + 1} / {questions.length}
                </div>
            </div>

            {/* Question Card */}
            <motion.div
                key={currentIndex}
                initial={{ opacity: 0, x: 50 }}
                animate={{ opacity: 1, x: 0 }}
                className="bg-card border border-border p-8 rounded-2xl shadow-xl"
            >
                <h2 className="text-2xl font-bold mb-8">{question.question}</h2>
                <div className="space-y-4">
                    {question.options.map((option, idx) => (
                        <button
                            key={idx}
                            onClick={() => handleAnswer(idx)}
                            className="w-full text-left p-4 rounded-lg bg-muted/50 hover:bg-primary/20 border-2 border-transparent hover:border-primary transition-all group"
                        >
                            <span className="font-mono text-primary mr-4 opacity-50 group-hover:opacity-100">{String.fromCharCode(65 + idx)}.</span>
                            {option}
                        </button>
                    ))}
                </div>
            </motion.div>
        </div>
    );
};
