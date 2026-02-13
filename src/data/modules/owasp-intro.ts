import type { Module } from '../../types';

export const owaspIntro: Module = {
    id: 'owasp-intro',
    title: 'Introduction to OWASP',
    description: 'Learn about the Open Web Application Security Project and the Top 10 vulnerabilities.',
    difficulty: 'Beginner',
    xpReward: 100,
    locked: false,
    lessons: [
        {
            id: 'owasp-1',
            title: 'What is OWASP?',
            type: 'theory',
            content: `
# What is OWASP?

The **Open Web Application Security Project (OWASP)** is a non-profit foundation that works to improve the security of software.

It is best known for the **OWASP Top 10**, a regularly updated report outlining security concerns for web application security, focusing on the 10 most critical risks.

## Why it matters
Understanding these vulnerabilities is crucial for developers because they are frequently exploited by attackers to steal data, take over accounts, or compromise systems.
        `
        },
        {
            id: 'owasp-quiz-1',
            title: 'Knowledge Check',
            type: 'quiz',
            content: '',
            quiz: {
                question: "What does OWASP stand for?",
                options: [
                    "Open Web Application Security Project",
                    "Online Website Assessment Security Protocol",
                    "Official Web Authorization Security Platform",
                    "Only Web Apps Stay Private"
                ],
                correctAnswer: 0,
                explanation: "OWASP stands for the Open Web Application Security Project, a global non-profit dedicated to software security."
            }
        }
    ]
};
