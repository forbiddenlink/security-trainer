import type { Module } from "../../types";

export const xssBasics: Module = {
  id: "xss-basics",
  title: "Cross-Site Scripting (XSS)",
  description:
    "Learn how attackers inject malicious scripts and how to prevent it in React.",
  difficulty: "Intermediate",
  xpReward: 350,
  locked: false,
  lessons: [
    {
      id: "xss-theory",
      title: "What is XSS?",
      type: "theory",
      content: `
# Cross-Site Scripting (XSS)

XSS occurs when an application includes untrusted data in a web page without proper validation or escaping. This allows attackers to execute malicious scripts in the victim's browser.

## How XSS Attacks Work

\`\`\`mermaid
sequenceDiagram
    participant Attacker
    participant Website
    participant Victim
    participant Browser as Victim's Browser

    Attacker->>Website: 1. Inject malicious script
    Note over Website: Script stored in database
    Victim->>Website: 2. Request page
    Website->>Browser: 3. Page with malicious script
    Browser->>Browser: 4. Execute attacker's script
    Browser->>Attacker: 5. Send stolen cookies/data
\`\`\`

::video[https://www.youtube.com/watch?v=L5l9lSnNMxg]{title="XSS Explained" caption="Learn how cross-site scripting attacks work"}

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
            `,
    },
    {
      id: "xss-quiz",
      title: "XSS Knowledge Check",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "Which React prop is explicitly named to warn developers about potential XSS risks?",
        options: [
          "unsafeRenderHTML",
          "dangerouslySetInnerHTML",
          "innerHtmlUnsafe",
          "allowScripts",
        ],
        correctAnswer: 1,
        explanation:
          "dangerouslySetInnerHTML is React's replacement for using innerHTML in the browser DOM. It is deliberately named to remind you of the security risks.",
      },
    },
    {
      id: "xss-lab",
      title: "Patch the XSS Vulnerability",
      type: "lab",
      content:
        "The component below renders user comments safely, except for one line where `dangerouslySetInnerHTML` is used. Fix it by using standard JSX rendering, which auto-escapes content.",
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
        instructions:
          "Remove the unsafe HTML rendering and render the comment as a standard child of the div tag.",
      },
    },
  ],
};
