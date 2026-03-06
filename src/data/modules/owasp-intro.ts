import type { Module } from "../../types";

export const owaspIntro: Module = {
  id: "owasp-intro",
  title: "Introduction to OWASP",
  description:
    "Learn about the Open Web Application Security Project and the Top 10 vulnerabilities.",
  difficulty: "Beginner",
  xpReward: 100,
  locked: false,
  lessons: [
    {
      id: "owasp-1",
      title: "What is OWASP?",
      type: "theory",
      content: `
# What is OWASP?

The **Open Web Application Security Project (OWASP)** is a non-profit foundation that works to improve the security of software.

It is best known for the **OWASP Top 10**, a regularly updated report outlining security concerns for web application security, focusing on the 10 most critical risks.

::video[https://www.youtube.com/watch?v=mnBFkrS4ZDI]{title="OWASP Top 10 Overview" caption="Introduction to the OWASP Top 10 vulnerabilities"}

## Why it matters
Understanding these vulnerabilities is crucial for developers because they are frequently exploited by attackers to steal data, take over accounts, or compromise systems.

## The OWASP Top 10 Categories

\`\`\`mermaid
mindmap
  root((OWASP Top 10))
    Injection
      SQL Injection
      NoSQL Injection
      Command Injection
    Authentication
      Session Hijacking
      Credential Stuffing
    Data Exposure
      Weak Encryption
      Clear Text Storage
    Access Control
      IDOR
      Privilege Escalation
    XSS
      Reflected
      Stored
      DOM-based
    Misconfiguration
      Default Credentials
      Verbose Errors
\`\`\`

1. **Injection** - SQL, NoSQL, OS command injection
2. **Broken Authentication** - Session hijacking, credential stuffing
3. **Sensitive Data Exposure** - Unencrypted data, weak algorithms
4. **XML External Entities (XXE)** - Malicious XML processing
5. **Broken Access Control** - IDOR, privilege escalation
6. **Security Misconfiguration** - Default credentials, verbose errors
7. **Cross-Site Scripting (XSS)** - Reflected, stored, DOM-based
8. **Insecure Deserialization** - Object manipulation attacks
9. **Using Components with Known Vulnerabilities** - Outdated libraries
10. **Insufficient Logging & Monitoring** - Undetected breaches
        `,
    },
    {
      id: "owasp-quiz-1",
      title: "Knowledge Check",
      type: "quiz",
      content: "",
      quiz: {
        question: "What does OWASP stand for?",
        options: [
          "Open Web Application Security Project",
          "Online Website Assessment Security Protocol",
          "Official Web Authorization Security Platform",
          "Only Web Apps Stay Private",
        ],
        correctAnswer: 0,
        explanation:
          "OWASP stands for the Open Web Application Security Project, a global non-profit dedicated to software security.",
      },
    },
    {
      id: "owasp-lab",
      title: "Identify the Vulnerabilities",
      type: "lab",
      content:
        "The code below contains three different security vulnerabilities. Your task is to identify each one by adding the correct OWASP category as a comment. Replace the TODO comments with the vulnerability type.",
      lab: {
        initialCode: `// Vulnerable Code Examples
// Identify each vulnerability by replacing TODO with the correct type

function login(username, password) {
  // TODO: What vulnerability is this?
  const query = "SELECT * FROM users WHERE name='" + username + "'";
  return db.execute(query);
}

function displayComment(userInput) {
  // TODO: What vulnerability is this?
  document.getElementById('output').innerHTML = userInput;
}

function getDocument(docId) {
  // TODO: What vulnerability is this?
  return db.documents.findById(docId);
  // Note: No check if user owns the document
}
`,
        solutionCode: `// Vulnerable Code Examples
// Identify each vulnerability by replacing TODO with the correct type

function login(username, password) {
  // INJECTION: SQL Injection via string concatenation
  const query = "SELECT * FROM users WHERE name='" + username + "'";
  return db.execute(query);
}

function displayComment(userInput) {
  // XSS: Cross-Site Scripting via innerHTML
  document.getElementById('output').innerHTML = userInput;
}

function getDocument(docId) {
  // IDOR: Insecure Direct Object Reference
  return db.documents.findById(docId);
  // Note: No check if user owns the document
}
`,
        instructions:
          "Replace each TODO comment with the correct OWASP vulnerability category: INJECTION, XSS, or IDOR. Include a brief description of why it's vulnerable.",
      },
    },
  ],
};
