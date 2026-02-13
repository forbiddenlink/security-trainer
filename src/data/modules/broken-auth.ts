import type { Module } from '../../types';

export const brokenAuth: Module = {
    id: 'broken-auth',
    title: 'Broken Authentication',
    description: 'Understand the risks of weak session management and credential stuffing.',
    difficulty: 'Advanced',
    xpReward: 300,
    locked: false,
    lessons: [
        {
            id: 'auth-theory',
            title: 'Authentication Failures',
            type: 'theory',
            content: `
# Broken Authentication

Authentication vulnerabilities allowed attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users' identities temporarily or permanently.

## Common Issues
1. **Credential Stuffing**: Attackers use lists of compromised username/password pairs.
2. **Weak Passwords**: Allowing "password123" or default credentials.
3. **Session Hijacking**: Exposing session IDs in URLs or not invalidating them after logout.

## Best Practices
- Implement Multi-Factor Authentication (MFA).
- Enforce strong password complexity.
- Limit failed login attempts.
            `
        },
        {
            id: 'auth-quiz',
            title: 'Auth Logic Challenge',
            type: 'quiz',
            content: '',
            quiz: {
                question: "You notice an application allows you to try logging in an unlimited number of times without any delay. What vulnerability is this?",
                options: [
                    "Session Fixation",
                    "Lack of Rate Limiting (Brute Force Susceptibility)",
                    "SQL Injection",
                    "Cross-Site Request Forgery"
                ],
                correctAnswer: 1,
                explanation: "Unlimited login attempts allow attackers to brute-force passwords using automated scripts. Implementing rate limiting or account lockouts is the defense."
            }
        }
    ]
};
