import { describe, it, expect } from 'vitest';
import { MODULES } from './modules';
import { labVerifiers, verifyLabSubmission } from '../utils/labVerification';

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

describe('CSRF Module', () => {
    const csrfModule = MODULES.find(m => m.id === 'csrf-attacks');

    it('exists in the modules list', () => {
        expect(csrfModule).toBeDefined();
    });

    it('has correct structure', () => {
        expect(csrfModule!.title).toBe('Cross-Site Request Forgery (CSRF)');
        expect(csrfModule!.difficulty).toBe('Intermediate');
        expect(csrfModule!.xpReward).toBe(350);
        expect(csrfModule!.locked).toBe(false);
    });

    it('has theory, quiz, and lab lessons', () => {
        const lessonTypes = csrfModule!.lessons.map(l => l.type);
        expect(lessonTypes).toContain('theory');
        expect(lessonTypes).toContain('quiz');
        expect(lessonTypes).toContain('lab');
    });

    it('has exactly 6 lessons (1 theory, 4 quizzes, 1 lab)', () => {
        expect(csrfModule!.lessons.length).toBe(6);
        expect(csrfModule!.lessons.filter(l => l.type === 'theory').length).toBe(1);
        expect(csrfModule!.lessons.filter(l => l.type === 'quiz').length).toBe(4);
        expect(csrfModule!.lessons.filter(l => l.type === 'lab').length).toBe(1);
    });

    it('has a registered lab verifier', () => {
        expect(labVerifiers['csrf-lab']).toBeDefined();
    });
});

describe('CSRF Lab Verifier', () => {
    const vulnerableCode = `
function handleTransfer(req, res) {
  const { to, amount } = req.body;

  if (!req.session.userId) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  const result = transferFunds(req.session.userId, to, amount);
  return res.json({ success: true, result });
}
    `;

    const secureCode = `
function handleTransfer(req, res) {
  const { to, amount, csrfToken } = req.body;

  if (!req.session.userId) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  if (!csrfToken || csrfToken !== req.session.csrfToken) {
    return res.status(403).json({ error: "Invalid CSRF token" });
  }

  const result = transferFunds(req.session.userId, to, amount);
  return res.json({ success: true, result });
}
    `;

    const partialFix = `
function handleTransfer(req, res) {
  const { to, amount, csrfToken } = req.body;

  if (!req.session.userId) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  // Missing actual validation logic
  const result = transferFunds(req.session.userId, to, amount);
  return res.json({ success: true, result });
}
    `;

    it('rejects vulnerable code without CSRF protection', () => {
        expect(verifyLabSubmission('csrf-lab', vulnerableCode)).toBe(false);
    });

    it('accepts properly secured code with CSRF token validation', () => {
        expect(verifyLabSubmission('csrf-lab', secureCode)).toBe(true);
    });

    it('rejects partial fix that only extracts token but does not validate', () => {
        expect(verifyLabSubmission('csrf-lab', partialFix)).toBe(false);
    });
});
