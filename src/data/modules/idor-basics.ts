import type { Module } from '../../types';

export const idorBasics: Module = {
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
};
