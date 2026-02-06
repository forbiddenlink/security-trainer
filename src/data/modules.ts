import type { Module } from '../types';

export const MODULES: Module[] = [
    {
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
    },
    {
        id: 'sql-injection',
        title: 'SQL Injection (SQLi)',
        description: 'Understand how attackers interfere with application database queries.',
        difficulty: 'Intermediate',
        xpReward: 300,
        locked: false,
        lessons: [
            {
                id: 'sqli-theory',
                title: 'Understanding SQL Injection',
                type: 'theory',
                content: `
# SQL Injection

SQL Injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database.

## How it works
Untrusted user input is directly concatenated into a SQL query string without validation or escaping.

\`\`\`sql
SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1';
\`\`\`

By inputting \`' OR '1'='1\`, the attacker makes the condition always true, bypassing authentication.
        `
            },
            {
                id: 'sqli-lab',
                title: 'Fix the Vulnerability',
                type: 'lab',
                content: 'The code below constructs a query using string concatenation. This is vulnerable to SQL Injection. Refactor it to use parameterized queries (prepared statements).',
                lab: {
                    initialCode: `
function getUser(username) {
  // VULNERABLE: Direct concatenation
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  
  return db.execute(query);
}
            `,
                    solutionCode: `
function getUser(username) {
  // SECURE: Parameterized query
  const query = "SELECT * FROM users WHERE username = ?";
  
  return db.execute(query, [username]);
}
            `,
                    instructions: "Modify the code to use a parameterized query with '?' placeholder instead of string concatenation."
                }
            }
        ]
    },
    {
        id: 'xss-basics',
        title: 'Cross-Site Scripting (XSS)',
        description: 'Learn how attackers inject malicious scripts and how to prevent it in React.',
        difficulty: 'Intermediate',
        xpReward: 350,
        locked: false,
        lessons: [
            {
                id: 'xss-theory',
                title: 'What is XSS?',
                type: 'theory',
                content: `
# Cross-Site Scripting (XSS)

XSS occurs when an application includes untrusted data in a web page without proper validation or escaping. This allows attackers to execute malicious scripts in the victim's browser.

## The React Defense
By default, React escapes variables embedded in JSX, which protects against most XSS attacks.

\`\`\`jsx
// Safe by default
<div>{userInput}</div>
\`\`\`

## The Danger Zone
React provides an escape hatch called \`dangerouslySetInnerHTML\`. As the name implies, it is dangerous.

\`\`\`jsx
// VULNERABLE
<div dangerouslySetInnerHTML={{ __html: userInput }} />
\`\`\`

Using this property with unsanitized input opens your app to XSS.
                `
            },
            {
                id: 'xss-quiz',
                title: 'XSS Knowledge Check',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "Which React prop is explicitly named to warn developers about potential XSS risks?",
                    options: [
                        "unsafeRenderHTML",
                        "dangerouslySetInnerHTML",
                        "innerHtmlUnsafe",
                        "allowScripts"
                    ],
                    correctAnswer: 1,
                    explanation: "dangerouslySetInnerHTML is React's replacement for using innerHTML in the browser DOM. It is deliberately named to remind you of the security risks."
                }
            },
            {
                id: 'xss-lab',
                title: 'Patch the XSS Vulnerability',
                type: 'lab',
                content: 'The component below renders user comments safely, except for one line where `dangerouslySetInnerHTML` is used. Fix it by using standard JSX rendering, which auto-escapes content.',
                lab: {
                    initialCode: `
function Comment({ userComment }) {
  return (
    <div className="comment">
      <h3>User says:</h3>
      {/* VULNERABLE: Parsing HTML directly */}
      <div dangerouslySetInnerHTML={{ __html: userComment }} />
    </div>
  );
}
                    `,
                    solutionCode: `
function Comment({ userComment }) {
  return (
    <div className="comment">
      <h3>User says:</h3>
      {/* SECURE: React escapes this context automatically */}
      <div>{userComment}</div>
    </div>
  );
}
                    `,
                    instructions: "Remove the unsafe HTML rendering and render the comment as a standard child of the div tag."
                }
            }
        ]
    },
    {
        id: 'idor-basics',
        title: 'Insecure Direct Object Reference (IDOR)',
        description: 'Learn how attackers access unauthorized data by manipulating IDs.',
        difficulty: 'Advanced',
        xpReward: 400,
        locked: false,
        lessons: [
            {
                id: 'idor-theory',
                title: 'What is IDOR?',
                type: 'theory',
                content: `
# Insecure Direct Object References (IDOR)

IDOR occurs when an application provides direct access to objects based on user-supplied input. As a result of this vulnerability, attackers can bypass authorization and access resources in the system directly, for example database records or files.

## The Scenario
Imagine a URL like this:
\`https://api.example.com/invoices?id=1234\`

If you change \`1234\` to \`1235\` and see someone else's invoice, that's IDOR. The system failed to check if *you* (the logged-in user) are actually authorized to see invoice \`1235\`.

## Prevention
Always validate that the current user has permission to access the requested resource.
                `
            },
            {
                id: 'idor-quiz',
                title: 'IDOR Knowledge Check',
                type: 'quiz',
                content: '',
                quiz: {
                    question: "Which of the following is the best defense against IDOR?",
                    options: [
                        "Obfuscating IDs (using UUIDs instead of numbers)",
                        "Implementing proper access control checks on every request",
                        "Using HTTPS for all requests",
                        "Disabling API access"
                    ],
                    correctAnswer: 1,
                    explanation: "While using UUIDs makes guessing harder, it doesn't solve the underlying permission issue. You must enforce access control checks on the server."
                }
            },
            {
                id: 'idor-lab',
                title: 'Prevent Unauthorized Access',
                type: 'lab',
                content: 'The function below fetches a document based on an ID provided in the request. It currently returns any document found. Secure it by checking if the document belongs to the requesting user.',
                lab: {
                    initialCode: `
function getDocument(user, docId) {
  // VULNERABLE: No ownership check
  const doc = db.findDocument(docId);
  
  if (!doc) {
    return { error: "Not found" };
  }
  
  return doc;
}
                    `,
                    solutionCode: `
function getDocument(user, docId) {
  const doc = db.findDocument(docId);
  
  if (!doc) {
    return { error: "Not found" };
  }

  // SECURE: Check ownership
  if (doc.ownerId !== user.id) {
    return { error: "Unauthorized" };
  }
  
  return doc;
}
                    `,
                    instructions: "Add a check to ensure `doc.ownerId` matches `user.id`. Return `{ error: 'Unauthorized' }` if they don't match."
                }
            }
        ]
    },
    {
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
    }
];
