import type { Module } from "../../types";

export const sessionManagement: Module = {
  id: "session-management",
  title: "Session Management",
  description:
    "Learn how to securely manage user sessions, prevent session fixation, and implement proper logout functionality.",
  difficulty: "Intermediate",
  xpReward: 350,
  locked: false,
  lessons: [
    {
      id: "session-theory",
      title: "Understanding Session Security",
      type: "theory",
      content: `
# Secure Session Management

Sessions are the foundation of web authentication. A compromised session gives attackers complete access to a user's account without needing their credentials.

## Mission Briefing: The Session Lifecycle

A session consists of:
1. **Session ID**: A unique token stored in a cookie
2. **Server-side data**: User info, permissions, state
3. **Expiration**: When the session becomes invalid

\`\`\`
Login → Create Session → Issue Cookie → Validate on Requests → Logout/Expire
\`\`\`

## Real-World Intel

**Case File #1: GitHub (2012)**
Session fixation vulnerability allowed attackers to hijack accounts by setting a known session ID before the victim logged in.

**Case File #2: Slack (2022)**
Session tokens were not properly invalidated after password changes, allowing attackers with stolen tokens to maintain access.

## Session Fixation Attack

\`\`\`mermaid
sequenceDiagram
    participant Attacker
    participant Victim
    participant Server

    Attacker->>Server: Get session ID ABC
    Attacker->>Victim: Trick into using ABC
    Victim->>Server: Login with session ABC
    Note over Server: No regeneration - same ID
    Attacker->>Server: Use ABC - now authenticated!
\`\`\`

The attacker:
1. Gets a valid session ID from the target site
2. Tricks the victim into using that session ID (via URL or cookie)
3. Waits for the victim to log in
4. Uses the now-authenticated session

**Defense**: Regenerate session ID after login!

::video[https://www.youtube.com/watch?v=UYLie3JEV2Y]{title="Session Fixation Explained" caption="How session fixation works and how to prevent it"}

## Secure Cookie Attributes

\`\`\`mermaid
flowchart TB
    C[Session Cookie] --> H[HttpOnly - no JS access]
    C --> S[Secure - HTTPS only]
    C --> SS[SameSite - no cross-site send]
    C --> E[maxAge - auto expire]

    style H fill:#22c55e,color:#fff
    style S fill:#22c55e,color:#fff
    style SS fill:#22c55e,color:#fff
    style E fill:#22c55e,color:#fff
\`\`\`

\`\`\`javascript
// SECURE session cookie
res.cookie('sessionId', token, {
  httpOnly: true,    // No JavaScript access
  secure: true,      // HTTPS only
  sameSite: 'Strict', // No cross-site sending
  maxAge: 3600000    // 1 hour expiry
});
\`\`\`

## Proper Logout

Logout must:
1. Destroy the server-side session
2. Clear the session cookie
3. Invalidate any refresh tokens
            `,
    },
    {
      id: "session-quiz-1",
      title: "Session Fixation",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "What is the primary defense against session fixation attacks?",
        options: [
          "Using longer session IDs",
          "Regenerating the session ID after successful authentication",
          "Storing session IDs in localStorage instead of cookies",
          "Encrypting the session ID",
        ],
        correctAnswer: 1,
        explanation:
          "Regenerating the session ID after login invalidates any session ID the attacker may have planted. The attacker's known session ID becomes useless, and the victim gets a new, unknown session ID after authenticating.",
      },
    },
    {
      id: "session-quiz-2",
      title: "Cookie Security",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "Which cookie attribute prevents JavaScript from accessing the session cookie?",
        options: ["Secure", "SameSite", "HttpOnly", "Path"],
        correctAnswer: 2,
        explanation:
          "The HttpOnly flag prevents client-side JavaScript from reading the cookie via document.cookie. This mitigates XSS attacks that attempt to steal session tokens. The Secure flag ensures HTTPS-only transmission, which is a different protection.",
      },
    },
    {
      id: "session-quiz-3",
      title: "Session Expiration",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "A user changes their password after suspecting account compromise. What should happen to their existing sessions?",
        options: [
          "Sessions should remain active for user convenience",
          "Only the current session should be invalidated",
          "All existing sessions should be invalidated immediately",
          "Sessions should expire naturally based on their original timeout",
        ],
        correctAnswer: 2,
        explanation:
          "When a password change occurs (especially for security reasons), all existing sessions should be invalidated. An attacker who stole a session token should not retain access after the password is changed. The user can simply log in again with the new password.",
      },
    },
    {
      id: "session-quiz-4",
      title: "Logout Security",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "Which of the following is an INCOMPLETE logout implementation?",
        options: [
          "Delete the session cookie and destroy server-side session data",
          "Clear the cookie on the client side only",
          "Destroy server session, clear cookie, and invalidate refresh tokens",
          "Regenerate session ID to a new invalid value and destroy old session",
        ],
        correctAnswer: 1,
        explanation:
          "Only clearing the cookie client-side is insufficient because the server-side session remains valid. An attacker who has the session ID can still use it. Proper logout must destroy the server-side session data and ideally clear the cookie as well.",
      },
    },
    {
      id: "session-lab",
      title: "Implement Secure Session Handling",
      type: "lab",
      content:
        "The login handler below has session fixation and insecure cookie vulnerabilities. Your mission: Implement secure session handling with proper cookie attributes.",
      lab: {
        initialCode: `
function handleLogin(req, res) {
  const { username, password } = req.body;

  const user = authenticateUser(username, password);
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // VULNERABLE: No session regeneration!
  // Uses existing session ID (potential fixation)
  req.session.userId = user.id;
  req.session.role = user.role;

  // VULNERABLE: Insecure cookie settings!
  res.cookie('sessionId', req.sessionID);

  return res.json({ success: true });
}
                `,
        solutionCode: `
function handleLogin(req, res) {
  const { username, password } = req.body;

  const user = authenticateUser(username, password);
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // SECURE: Regenerate session ID to prevent fixation
  req.session.regenerate((err) => {
    if (err) {
      return res.status(500).json({ error: "Session error" });
    }

    req.session.userId = user.id;
    req.session.role = user.role;

    // SECURE: Set proper cookie attributes
    res.cookie('sessionId', req.sessionID, {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      maxAge: 3600000
    });

    return res.json({ success: true });
  });
}
                `,
        instructions:
          "Fix the session vulnerabilities: 1) Call req.session.regenerate() after successful authentication to prevent session fixation, 2) Add secure cookie attributes: httpOnly, secure, sameSite: 'Strict', and maxAge.",
      },
    },
  ],
};
