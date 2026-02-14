import type { Module } from "../../types";

export const sqlInjection: Module = {
  id: "sql-injection",
  title: "SQL Injection (SQLi)",
  description:
    "Understand how attackers interfere with application database queries.",
  difficulty: "Intermediate",
  xpReward: 300,
  locked: false,
  lessons: [
    {
      id: "sqli-theory",
      title: "Understanding SQL Injection",
      type: "theory",
      content: `
# SQL Injection

SQL Injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database.

## How it works
Untrusted user input is directly concatenated into a SQL query string without validation or escaping.

\`\`\`sql
SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1';
\`\`\`

By inputting \`' OR '1'='1\`, the attacker makes the condition always true, bypassing authentication.
            `,
    },
    {
      id: "sqli-quiz-1",
      title: "Injection Vector Analysis",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "Which input would successfully bypass this login query?\n\nSELECT * FROM users WHERE username = '[INPUT]' AND password = 'test'",
        options: [
          "admin'; DROP TABLE users; --",
          "admin' OR '1'='1' --",
          "admin AND password='test'",
          "<script>alert(1)</script>",
        ],
        correctAnswer: 1,
        explanation:
          "The input admin' OR '1'='1' -- closes the username string, adds a condition that's always true (1=1), and comments out the rest of the query with --. This bypasses the password check entirely.",
      },
    },
    {
      id: "sqli-quiz-2",
      title: "Defense Mechanism Knowledge",
      type: "quiz",
      content: "",
      quiz: {
        question: "What is the PRIMARY defense against SQL injection?",
        options: [
          "Input validation with a blocklist of dangerous characters",
          "Encoding user input before display",
          "Parameterized queries (prepared statements)",
          "Using an ORM instead of raw SQL",
        ],
        correctAnswer: 2,
        explanation:
          "Parameterized queries separate SQL code from data, making injection impossible. The database treats parameters as literal values, not executable code. ORMs often use parameterized queries internally, but they're not foolproof if raw queries are still allowed.",
      },
    },
    {
      id: "sqli-quiz-3",
      title: "Attack Type Classification",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "An attacker uses UNION SELECT to append their own query results to the original query. What type of SQL injection is this?",
        options: [
          "Blind SQL injection",
          "Error-based SQL injection",
          "Union-based SQL injection",
          "Time-based SQL injection",
        ],
        correctAnswer: 2,
        explanation:
          "Union-based SQL injection uses the UNION operator to combine results from the attacker's query with the original. This requires the attacker to match the number of columns and compatible data types in both queries.",
      },
    },
    {
      id: "sqli-quiz-4",
      title: "Real-World Impact Assessment",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "Beyond stealing data, what else can SQL injection enable in some database configurations?",
        options: [
          "Only reading data from the database",
          "Remote code execution on the database server",
          "Cross-site scripting attacks",
          "Denial of service only",
        ],
        correctAnswer: 1,
        explanation:
          "Some databases (like SQL Server with xp_cmdshell or MySQL with INTO OUTFILE) allow command execution or file operations. A SQL injection vulnerability can escalate to complete server compromise if these features are enabled.",
      },
    },
    {
      id: "sqli-lab",
      title: "Fix the Vulnerability",
      type: "lab",
      content:
        "The code below constructs a query using string concatenation. This is vulnerable to SQL Injection. Refactor it to use parameterized queries (prepared statements).",
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
        instructions:
          "Modify the code to use a parameterized query with '?' placeholder instead of string concatenation.",
      },
    },
  ],
};
