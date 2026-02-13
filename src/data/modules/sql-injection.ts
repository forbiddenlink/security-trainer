import type { Module } from '../../types';

export const sqlInjection: Module = {
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
};
