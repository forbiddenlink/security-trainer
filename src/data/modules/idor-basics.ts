import type { Module } from "../../types";

export const idorBasics: Module = {
  id: "idor-basics",
  title: "Insecure Direct Object Reference (IDOR)",
  description:
    "Learn how attackers access unauthorized data by manipulating IDs.",
  difficulty: "Advanced",
  xpReward: 400,
  locked: false,
  lessons: [
    {
      id: "idor-theory",
      title: "What is IDOR?",
      type: "theory",
      content: `
# Insecure Direct Object References (IDOR)

IDOR occurs when an application provides direct access to objects based on user-supplied input. As a result of this vulnerability, attackers can bypass authorization and access resources in the system directly, for example database records or files.

## IDOR Attack vs Proper Authorization

\`\`\`mermaid
flowchart TB
    subgraph Attack["IDOR Attack"]
        A1[GET /invoices?id=1234] --> A2[Fetch invoice 1234]
        A2 --> A3[Return data - no check]
        A4[Change id to 1235] --> A5[Fetch invoice 1235]
        A5 --> A6[Return someone else's data!]
    end

    subgraph Secure["Proper Authorization"]
        B1[GET /invoices?id=1235] --> B2[Fetch invoice 1235]
        B2 --> B3{ownerId matches user?}
        B3 -->|Yes| B4[Return invoice]
        B3 -->|No| B5[403 Unauthorized]
    end

    style A3 fill:#ef4444,color:#fff
    style A6 fill:#ef4444,color:#fff
    style B4 fill:#22c55e,color:#fff
    style B5 fill:#22c55e,color:#fff
\`\`\`

::video[https://www.youtube.com/watch?v=JopQ38v-LYQ]{title="IDOR Explained" caption="Insecure Direct Object References and how to fix them"}

## The Scenario
Imagine a URL like this:
\`https://api.example.com/invoices?id=1234\`

If you change \`1234\` to \`1235\` and see someone else's invoice, that's IDOR. The system failed to check if *you* (the logged-in user) are actually authorized to see invoice \`1235\`.

## Prevention
Always validate that the current user has permission to access the requested resource.
            `,
    },
    {
      id: "idor-quiz",
      title: "IDOR Knowledge Check",
      type: "quiz",
      content: "",
      quiz: {
        question: "Which of the following is the best defense against IDOR?",
        options: [
          "Obfuscating IDs (using UUIDs instead of numbers)",
          "Implementing proper access control checks on every request",
          "Using HTTPS for all requests",
          "Disabling API access",
        ],
        correctAnswer: 1,
        explanation:
          "While using UUIDs makes guessing harder, it doesn't solve the underlying permission issue. You must enforce access control checks on the server.",
      },
    },
    {
      id: "idor-lab",
      title: "Prevent Unauthorized Access",
      type: "lab",
      content:
        "The function below fetches a document based on an ID provided in the request. It currently returns any document found. Secure it by checking if the document belongs to the requesting user.",
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
        instructions:
          "Add a check to ensure `doc.ownerId` matches `user.id`. Return `{ error: 'Unauthorized' }` if they don't match.",
      },
    },
  ],
};
