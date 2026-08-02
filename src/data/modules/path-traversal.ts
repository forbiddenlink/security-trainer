import type { Module } from "../../types";

export const pathTraversal: Module = {
  id: "path-traversal",
  title: "Path Traversal",
  description:
    "Understand how attackers escape intended directories to access unauthorized files on the server.",
  difficulty: "Intermediate",
  xpReward: 350,
  locked: false,
  lessons: [
    {
      id: "path-theory",
      title: "Understanding Path Traversal",
      type: "theory",
      content: `
# Path Traversal (Directory Traversal)

Path traversal vulnerabilities allow attackers to access files and directories outside the intended location by manipulating file path inputs.

## Mission Briefing: The Attack Vector

When an application uses user input to construct file paths without proper validation, attackers can use special characters to navigate the filesystem.

\`\`\`mermaid
flowchart LR
    A[Input: ../../../etc/passwd] --> B[join with /uploads/]
    B --> C[/var/www/uploads/../../../etc/passwd]
    C --> D[Resolves to /etc/passwd]
    D --> E[(Sensitive file leaked!)]

    A2[Input: ../../../etc/passwd] --> B2[path.resolve + prefix check]
    B2 --> F{Within /uploads/?}
    F -->|No| G[403 Access denied]
    F -->|Yes| H[Safe file read]

    style A fill:#ef4444,color:#fff
    style E fill:#ef4444,color:#fff
    style G fill:#22c55e,color:#fff
    style H fill:#22c55e,color:#fff
\`\`\`

::video[https://www.youtube.com/watch?v=bTtUidpFDos]{title="Path Traversal Explained" caption="How directory traversal attacks escape intended folders"}

\`\`\`javascript
// VULNERABLE: User controls the filename
const file = req.query.file;
res.sendFile('/var/www/uploads/' + file);

// Attacker input: "../../../etc/passwd"
// Resolved path: /etc/passwd (escaped the uploads directory!)
\`\`\`

## The Magic Sequence: ../

The \`../\` sequence means "go up one directory level." By chaining multiple sequences, attackers climb up the directory tree and then descend into sensitive areas.

### Common Targets
- \`/etc/passwd\` - User accounts (Unix)
- \`/etc/shadow\` - Password hashes (requires root)
- \`~/.ssh/id_rsa\` - SSH private keys
- \`/var/log/\` - Application logs with secrets
- \`web.config\` / \`.env\` - Configuration with credentials
- Windows: \`C:\\Windows\\System32\\config\\SAM\`

## Bypass Techniques

Attackers use encoding to evade simple filters:

| Technique | Example |
|-----------|---------|
| URL encoding | \`%2e%2e%2f\` = \`../\` |
| Double encoding | \`%252e%252e%252f\` |
| Unicode | \`..%c0%af\` or \`..%ef%bc%8f\` |
| Null byte | \`../../../etc/passwd%00.png\` |
| Backslash (Windows) | \`..\\..\\..\\windows\\win.ini\` |

## Real-World Intel

**Case File: Fortinet VPN (2019)**
A path traversal vulnerability (CVE-2018-13379) in Fortinet's SSL VPN allowed unauthenticated attackers to download system files, including session tokens. Over 50,000 vulnerable devices were exposed.

**Case File: Apache HTTP Server (2021)**
CVE-2021-41773 allowed path traversal via URL-encoded sequences, enabling file disclosure and RCE on misconfigured servers.

## Defense Strategies

1. **Canonicalize paths** - Resolve the full path and verify it's within allowed directory
2. **Use allowlists** - Only permit known, safe filenames
3. **Avoid user input in paths** - Use indirect references (IDs mapped to files)
4. **Chroot/sandbox** - Restrict application's filesystem view
5. **Validate after decoding** - Check path AFTER URL decoding
            `,
    },
    {
      id: "path-quiz-1",
      title: "Attack Pattern Recognition",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "An application serves files from /var/www/files/. Which input accesses /etc/passwd?",
        options: [
          "/etc/passwd",
          "etc/passwd",
          "../../../etc/passwd",
          "..\\..\\..\\etc\\passwd",
        ],
        correctAnswer: 2,
        explanation:
          "Starting from /var/www/files/, you need 3 '../' sequences: ../=>/var/www, ../../=>/var, ../../../=>/, then etc/passwd. Absolute paths are typically blocked, and backslashes are for Windows systems.",
      },
    },
    {
      id: "path-quiz-2",
      title: "Filter Bypass Knowledge",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "A developer filters out '../' from user input. How might an attacker bypass this?",
        options: [
          "Impossible - filtering ../ is sufficient",
          "Use URL encoding: %2e%2e%2f",
          "Use single dots: ./././",
          "Use spaces: . . /",
        ],
        correctAnswer: 1,
        explanation:
          "URL encoding %2e%2e%2f decodes to '../' AFTER the filter runs. Double encoding (%252e%252e%252f) can bypass filters that decode once then check. Always validate AFTER full URL decoding and path canonicalization.",
      },
    },
    {
      id: "path-quiz-3",
      title: "Secure Validation Pattern",
      type: "quiz",
      content: "",
      quiz: {
        question: "What is the MOST reliable way to prevent path traversal?",
        options: [
          "Strip '../' from the input string",
          "Check if input contains '..' and reject it",
          "Resolve the canonical path and verify it starts with the allowed directory",
          "Only allow alphanumeric filenames",
        ],
        correctAnswer: 2,
        explanation:
          "Canonicalizing (resolving to absolute path with symlinks resolved) then checking the prefix is the most reliable approach. It handles all encoding tricks and edge cases. Alphanumeric-only is too restrictive for many use cases; string checks can be bypassed.",
      },
    },
    {
      id: "path-quiz-4",
      title: "Null Byte Injection",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "In older systems, what does the null byte (%00) do in '../../../etc/passwd%00.png'?",
        options: [
          "Makes the file invisible",
          "Truncates the string, so the .png extension is ignored",
          "Converts the file to PNG format",
          "Creates a backup of the file",
        ],
        correctAnswer: 1,
        explanation:
          "In C-based systems and older PHP/Java, null byte terminates strings. The application sees '.png' extension but the filesystem stops at %00, reading /etc/passwd. Modern languages handle this better, but legacy systems remain vulnerable.",
      },
    },
    {
      id: "path-lab",
      title: "Secure the File Download",
      type: "lab",
      content:
        "The code below serves user-requested files but is vulnerable to path traversal. Your mission: Add proper validation to ensure users can only access files within the uploads directory.",
      lab: {
        initialCode: `
const path = require('path');
const fs = require('fs');

const UPLOADS_DIR = '/var/www/uploads';

function serveFile(req, res) {
  const filename = req.query.file;

  // VULNERABLE: No path validation!
  const filePath = path.join(UPLOADS_DIR, filename);

  fs.readFile(filePath, (err, data) => {
    if (err) {
      return res.status(404).send('File not found');
    }
    res.send(data);
  });
}
                `,
        solutionCode: `
const path = require('path');
const fs = require('fs');

const UPLOADS_DIR = '/var/www/uploads';

function serveFile(req, res) {
  const filename = req.query.file;

  // SECURE: Resolve canonical path and validate
  const filePath = path.join(UPLOADS_DIR, filename);
  const canonicalPath = path.resolve(filePath);

  // Check that resolved path is within uploads directory
  if (!canonicalPath.startsWith(UPLOADS_DIR)) {
    return res.status(403).send('Access denied');
  }

  fs.readFile(canonicalPath, (err, data) => {
    if (err) {
      return res.status(404).send('File not found');
    }
    res.send(data);
  });
}
                `,
        instructions:
          "Fix the vulnerability: 1) Use path.resolve() to get the canonical (absolute) path, 2) Check that the canonical path starts with UPLOADS_DIR, 3) Return 403 'Access denied' if the path escapes the allowed directory.",
      },
    },
  ],
};
