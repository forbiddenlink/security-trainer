import type { Module } from "../../types";

export const brokenAuth: Module = {
  id: "broken-auth",
  title: "Broken Authentication",
  description:
    "Understand the risks of weak session management and credential stuffing.",
  difficulty: "Advanced",
  xpReward: 300,
  locked: false,
  lessons: [
    {
      id: "auth-theory",
      title: "Authentication Failures",
      type: "theory",
      content: `
# Broken Authentication

Authentication vulnerabilities allowed attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users' identities temporarily or permanently.

## The Authentication Attack Surface

\`\`\`mermaid
flowchart TB
    subgraph Attacks
        A1[Credential Stuffing]
        A2[Brute Force]
        A3[Session Hijacking]
        A4[Weak Passwords]
    end

    subgraph Defenses
        D1[Rate Limiting]
        D2[MFA]
        D3[Secure Sessions]
        D4[Strong Policies]
    end

    A1 --> D1
    A1 --> D2
    A2 --> D1
    A3 --> D3
    A4 --> D4

    style A1 fill:#ef4444,color:#fff
    style A2 fill:#ef4444,color:#fff
    style A3 fill:#ef4444,color:#fff
    style A4 fill:#ef4444,color:#fff
    style D1 fill:#22c55e,color:#fff
    style D2 fill:#22c55e,color:#fff
    style D3 fill:#22c55e,color:#fff
    style D4 fill:#22c55e,color:#fff
\`\`\`

## Mission Briefing: The Threat Landscape

Authentication is the front door to your application. When compromised, attackers gain full access to user accounts, sensitive data, and potentially administrative functions.

## Common Attack Vectors

### 1. Credential Stuffing
Attackers use lists of compromised username/password pairs from other breaches. Since users often reuse passwords, this is highly effective.

### 2. Brute Force Attacks
Without rate limiting, attackers can try thousands of password combinations per second until they find the right one.

### 3. Weak Password Policies
Allowing passwords like "password123" or "admin" makes accounts trivially compromisable.

### 4. Session Hijacking
- Exposing session IDs in URLs
- Not invalidating sessions after logout
- Using predictable session tokens
- Missing Secure/HttpOnly cookie flags

## Real-World Intel

**Case File: Dropbox (2012)**
68 million user credentials were exposed when an employee reused their LinkedIn password (compromised in a separate breach) for internal systems.

**Case File: GitHub (2019)**
An attacker used credential stuffing to access user accounts, then generated personal access tokens to maintain persistence even after password resets.

## Best Practices
- Implement Multi-Factor Authentication (MFA)
- Enforce strong password complexity
- Limit failed login attempts (rate limiting)
- Use secure, random session tokens
- Invalidate sessions on logout and password change
- Set Secure, HttpOnly, and SameSite flags on cookies
            `,
    },
    {
      id: "auth-quiz-1",
      title: "Auth Logic Challenge",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "You notice an application allows you to try logging in an unlimited number of times without any delay. What vulnerability is this?",
        options: [
          "Session Fixation",
          "Lack of Rate Limiting (Brute Force Susceptibility)",
          "SQL Injection",
          "Cross-Site Request Forgery",
        ],
        correctAnswer: 1,
        explanation:
          "Unlimited login attempts allow attackers to brute-force passwords using automated scripts. Implementing rate limiting or account lockouts is the defense.",
      },
    },
    {
      id: "auth-quiz-2",
      title: "Session Security Assessment",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "A website includes the session ID in the URL like: https://example.com/dashboard?sid=abc123. Why is this dangerous?",
        options: [
          "The session ID is too short",
          "URLs are logged in browser history, server logs, and can be shared accidentally",
          "It makes the page load slower",
          "Search engines will index the session",
        ],
        correctAnswer: 1,
        explanation:
          "Session IDs in URLs get stored in browser history, bookmarks, Referer headers sent to other sites, and server access logs. Anyone with access to these can hijack the session. Always use cookies with Secure and HttpOnly flags instead.",
      },
    },
    {
      id: "auth-quiz-3",
      title: "Credential Stuffing Defense",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "Which combination provides the BEST defense against credential stuffing attacks?",
        options: [
          "CAPTCHA on login page only",
          "Rate limiting + MFA + breached password detection",
          "Strong password policy + account lockout",
          "IP-based blocking + session timeout",
        ],
        correctAnswer: 1,
        explanation:
          "Rate limiting slows attackers, MFA ensures stolen passwords alone aren't enough, and breached password detection (like HaveIBeenPwned integration) prevents users from using known-compromised credentials. This layered approach is most effective.",
      },
    },
    {
      id: "auth-lab",
      title: "Implement Rate Limiting",
      type: "lab",
      content:
        "The login handler below has no protection against brute force attacks. Your mission: Add rate limiting to block attackers after too many failed attempts.",
      lab: {
        initialCode: `
const loginAttempts = new Map(); // Track attempts per IP

function handleLogin(req, res) {
  const { username, password } = req.body;
  const ip = req.ip;

  // VULNERABLE: No rate limiting!

  // Verify credentials
  const user = authenticate(username, password);

  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // Create session
  req.session.userId = user.id;
  return res.json({ success: true });
}
                `,
        solutionCode: `
const loginAttempts = new Map(); // Track attempts per IP
const MAX_ATTEMPTS = 5;
const LOCKOUT_TIME = 15 * 60 * 1000; // 15 minutes

function handleLogin(req, res) {
  const { username, password } = req.body;
  const ip = req.ip;

  // SECURE: Check rate limit
  const attempts = loginAttempts.get(ip) || { count: 0, lastAttempt: 0 };
  const now = Date.now();

  if (attempts.count >= MAX_ATTEMPTS && now - attempts.lastAttempt < LOCKOUT_TIME) {
    return res.status(429).json({ error: "Too many attempts. Try again later." });
  }

  // Verify credentials
  const user = authenticate(username, password);

  if (!user) {
    // Track failed attempt
    loginAttempts.set(ip, { count: attempts.count + 1, lastAttempt: now });
    return res.status(401).json({ error: "Invalid credentials" });
  }

  // Reset attempts on success
  loginAttempts.delete(ip);

  // Create session
  req.session.userId = user.id;
  return res.json({ success: true });
}
                `,
        instructions:
          "Add rate limiting: 1) Define MAX_ATTEMPTS (5) and LOCKOUT_TIME (15 minutes in ms), 2) Check if IP has exceeded MAX_ATTEMPTS within LOCKOUT_TIME, 3) Return 429 status with 'Too many attempts' error if locked out, 4) Track failed attempts, 5) Clear attempts on successful login.",
      },
    },
  ],
};
