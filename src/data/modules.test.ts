import { describe, it, expect } from 'vitest';
import { MODULES } from './modules';
import { labVerifiers } from '../utils/labVerification';

describe('MODULES data', () => {
    it('has at least 5 training modules', () => {
        expect(MODULES.length).toBeGreaterThanOrEqual(5);
    });

    it('all modules have required fields', () => {
        for (const module of MODULES) {
            expect(module).toHaveProperty('id');
            expect(module).toHaveProperty('title');
            expect(module).toHaveProperty('description');
            expect(module).toHaveProperty('difficulty');
            expect(module).toHaveProperty('xpReward');
            expect(module).toHaveProperty('lessons');
            expect(module.lessons.length).toBeGreaterThan(0);
        }
    });

    it('all module IDs are unique', () => {
        const ids = MODULES.map(m => m.id);
        const uniqueIds = new Set(ids);
        expect(uniqueIds.size).toBe(ids.length);
    });

    it('all lesson IDs are unique within modules', () => {
        for (const module of MODULES) {
            const lessonIds = module.lessons.map(l => l.id);
            const uniqueIds = new Set(lessonIds);
            expect(uniqueIds.size).toBe(lessonIds.length);
        }
    });

    it('all labs have corresponding verifiers', () => {
        const labLessons = MODULES.flatMap(m =>
            m.lessons.filter(l => l.type === 'lab')
        );

        for (const lab of labLessons) {
            expect(
                labVerifiers[lab.id],
                `Missing verifier for lab: ${lab.id}`
            ).toBeDefined();
        }
    });

    it('all quizzes have valid structure', () => {
        const quizLessons = MODULES.flatMap(m =>
            m.lessons.filter(l => l.type === 'quiz')
        );

        for (const quiz of quizLessons) {
            expect(quiz.quiz).toBeDefined();
            expect(quiz.quiz!.question).toBeTruthy();
            expect(quiz.quiz!.options.length).toBeGreaterThanOrEqual(2);
            expect(quiz.quiz!.correctAnswer).toBeGreaterThanOrEqual(0);
            expect(quiz.quiz!.correctAnswer).toBeLessThan(quiz.quiz!.options.length);
            expect(quiz.quiz!.explanation).toBeTruthy();
        }
    });

    it('difficulty values are valid', () => {
        const validDifficulties = ['Beginner', 'Intermediate', 'Advanced'];

        for (const module of MODULES) {
            expect(validDifficulties).toContain(module.difficulty);
        }
    });

    it('XP rewards are positive numbers', () => {
        for (const module of MODULES) {
            expect(module.xpReward).toBeGreaterThan(0);
        }
    });
});
