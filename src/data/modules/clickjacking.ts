import type { Module } from '../../types';

export const clickjacking: Module = {
    id: 'clickjacking',
    title: 'Clickjacking (UI Redressing)',
    description: 'Learn how attackers trick users into clicking hidden elements and how to defend with frame protection.',
    difficulty: 'Beginner',
    xpReward: 250,
    locked: false,
    lessons: [
        {
            id: 'clickjacking-theory',
            title: 'Understanding Clickjacking',
            type: 'theory',
            content: `
# Clickjacking (UI Redressing)

Clickjacking is a technique where an attacker tricks users into clicking something different from what they perceive. The attacker overlays invisible or disguised elements over legitimate UI components.

## Mission Briefing: The Attack Vector

Imagine a malicious page that shows a "Win a Prize!" button. Hidden beneath it is an invisible iframe containing your bank's "Transfer $1000" button, perfectly positioned so your click lands on it instead.

\`\`\`html
<!-- Attacker's page -->
<style>
  iframe {
    position: absolute;
    opacity: 0;        /* Invisible! */
    z-index: 2;        /* On top */
  }
  .fake-button {
    position: absolute;
    z-index: 1;        /* Below iframe */
  }
</style>

<button class="fake-button">Click to Win!</button>
<iframe src="https://bank.com/transfer"></iframe>
\`\`\`

When you click "Win a Prize!", you're actually clicking the bank's transfer button.

## Real-World Intel

**Case File #1: Facebook Like Button (2010)**
Attackers embedded invisible Facebook iframes to harvest "likes" without users knowing—called "Likejacking."

**Case File #2: Twitter (2009)**
A clickjacking worm spread by tricking users into clicking a hidden "tweet" button, spreading malicious links.

**Case File #3: Adobe Flash Settings (2008)**
Researchers demonstrated clickjacking could enable webcam/microphone access through Adobe's settings panel.

## The Defense: Frame Protection

Prevent your site from being embedded in malicious iframes using:

1. **X-Frame-Options Header** (Legacy but still works)
   - \`DENY\` - Never allow framing
   - \`SAMEORIGIN\` - Only same-origin frames allowed

2. **Content-Security-Policy** (Modern approach)
   - \`frame-ancestors 'none'\` - Equivalent to X-Frame-Options: DENY
   - \`frame-ancestors 'self'\` - Equivalent to SAMEORIGIN
            `
        },
        {
            id: 'clickjacking-quiz-1',
            title: 'Attack Recognition',
            type: 'quiz',
            content: '',
            quiz: {
                question: "What is the core technique behind clickjacking attacks?",
                options: [
                    "Injecting malicious scripts into a page",
                    "Overlaying invisible or disguised elements to hijack user clicks",
                    "Stealing session cookies through cross-site requests",
                    "Exploiting SQL queries to access databases"
                ],
                correctAnswer: 1,
                explanation: "Clickjacking works by positioning elements (usually invisible iframes) over legitimate UI, so when users think they're clicking one thing, they're actually clicking something else entirely."
            }
        },
        {
            id: 'clickjacking-quiz-2',
            title: 'Defense Mechanisms',
            type: 'quiz',
            content: '',
            quiz: {
                question: "Which HTTP header prevents a page from being embedded in an iframe on other sites?",
                options: [
                    "Content-Type: text/html",
                    "X-Frame-Options: DENY",
                    "X-XSS-Protection: 1",
                    "Strict-Transport-Security: max-age=31536000"
                ],
                correctAnswer: 1,
                explanation: "X-Frame-Options: DENY tells browsers to never allow this page to be loaded in a frame. SAMEORIGIN allows framing only from the same origin. This is the primary defense against clickjacking."
            }
        },
        {
            id: 'clickjacking-quiz-3',
            title: 'Modern Protection',
            type: 'quiz',
            content: '',
            quiz: {
                question: "What is the modern CSP directive that replaces X-Frame-Options?",
                options: [
                    "script-src 'self'",
                    "default-src 'none'",
                    "frame-ancestors 'self'",
                    "sandbox allow-scripts"
                ],
                correctAnswer: 2,
                explanation: "The frame-ancestors directive in Content-Security-Policy is the modern replacement for X-Frame-Options. It offers more flexibility, allowing you to specify multiple allowed origins (e.g., frame-ancestors 'self' https://trusted.com)."
            }
        },
        {
            id: 'clickjacking-lab',
            title: 'Implement Frame Protection',
            type: 'lab',
            content: 'The server configuration below serves sensitive pages but has no clickjacking protection. Your mission: Add proper frame protection headers.',
            lab: {
                initialCode: `
function configureSecurityHeaders(app) {
  // VULNERABLE: No clickjacking protection!

  app.use((req, res, next) => {
    // Basic security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');

    // TODO: Add frame protection

    next();
  });
}
                `,
                solutionCode: `
function configureSecurityHeaders(app) {
  app.use((req, res, next) => {
    // Basic security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');

    // SECURE: Clickjacking protection
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "frame-ancestors 'none'");

    next();
  });
}
                `,
                instructions: "Add clickjacking protection: 1) Set X-Frame-Options header to 'DENY', 2) Set Content-Security-Policy with frame-ancestors 'none' for modern browser support."
            }
        }
    ]
};
