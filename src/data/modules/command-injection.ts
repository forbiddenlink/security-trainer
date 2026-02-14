import type { Module } from "../../types";

export const commandInjection: Module = {
  id: "command-injection",
  title: "OS Command Injection",
  description:
    "Learn how attackers exploit applications to execute arbitrary system commands and how to defend against it.",
  difficulty: "Advanced",
  xpReward: 400,
  locked: false,
  lessons: [
    {
      id: "cmdi-theory",
      title: "Understanding Command Injection",
      type: "theory",
      content: `
# OS Command Injection

OS Command Injection (also known as shell injection) is a critical vulnerability that allows attackers to execute arbitrary operating system commands on the server that hosts the application.

## Mission Briefing: The Attack Vector

When an application passes unsafe user data to a system shell, attackers can inject additional commands. Unlike SQL injection (which targets databases), command injection targets the **operating system itself**.

\`\`\`javascript
// VULNERABLE: User input passed directly to shell
const filename = req.query.file;
exec('cat /uploads/' + filename);

// Attacker input: "; rm -rf / #"
// Executed: cat /uploads/; rm -rf / #
\`\`\`

## Common Injection Points

1. **File operations**: Converting, compressing, or analyzing files
2. **System utilities**: Ping, nslookup, whois lookups
3. **PDF/Image generation**: Tools like wkhtmltopdf, ImageMagick
4. **Git operations**: Clone, pull commands with user-supplied URLs

## Real-World Intel

**Case File: Equifax Breach (2017)**
A command injection vulnerability in Apache Struts allowed attackers to execute arbitrary commands, leading to the exposure of 147 million customer records.

**Case File: Shellshock (2014)**
The Bash shell vulnerability allowed attackers to execute commands via environment variables, affecting millions of servers, routers, and IoT devices.

## Command Separators

Attackers use these characters to chain commands:
- \`;\` - Command separator (Unix)
- \`&\` - Background execution
- \`|\` - Pipe output to another command
- \`&&\` - Execute if previous succeeded
- \`||\` - Execute if previous failed
- \`\n\` - Newline (new command)
- \`\`\` \` \`\`\` - Command substitution
- \`$()\` - Command substitution

## Defense Strategies

1. **Never use shell commands with user input** - Use language-native libraries instead
2. **If unavoidable, use parameterized execution** - Pass arguments as arrays, not strings
3. **Input validation** - Allowlist acceptable characters (alphanumeric only)
4. **Escape special characters** - Use proper escaping for the target shell
5. **Least privilege** - Run applications with minimal OS permissions
            `,
    },
    {
      id: "cmdi-quiz-1",
      title: "Attack Vector Recognition",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "An application runs: exec('ping -c 4 ' + userInput). Which input would execute a second command?",
        options: [
          "192.168.1.1 -c 100",
          "192.168.1.1; cat /etc/passwd",
          "$(192.168.1.1)",
          "<script>alert(1)</script>",
        ],
        correctAnswer: 1,
        explanation:
          "The semicolon (;) acts as a command separator in Unix shells. The input '192.168.1.1; cat /etc/passwd' would execute ping first, then read the password file. The other options either change ping parameters, are invalid syntax, or attempt XSS (wrong attack type).",
      },
    },
    {
      id: "cmdi-quiz-2",
      title: "Defense Strategy Assessment",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "What is the MOST effective defense against command injection?",
        options: [
          "Blacklisting dangerous characters like ; and |",
          "Using language-native APIs instead of shell commands",
          "Running the application as root for better control",
          "Encoding user input before passing to the shell",
        ],
        correctAnswer: 1,
        explanation:
          "The safest approach is to avoid shell commands entirely. Use language-native libraries (e.g., Node's fs module instead of exec('cat file')). Blacklists are easily bypassed, encoding can be incomplete, and running as root increases damage potential.",
      },
    },
    {
      id: "cmdi-quiz-3",
      title: "Secure Coding Pattern",
      type: "quiz",
      content: "",
      quiz: {
        question: "Which code pattern is SECURE against command injection?",
        options: [
          "exec('convert ' + filename + ' output.png')",
          "exec('convert \"' + filename + '\" output.png')",
          "execFile('convert', [filename, 'output.png'])",
          "exec('convert ' + escape(filename) + ' output.png')",
        ],
        correctAnswer: 2,
        explanation:
          "execFile() passes arguments as an array, not through a shell, so command separators have no special meaning. The other options still use shell interpretation where quotes can be escaped, and escape functions may miss edge cases.",
      },
    },
    {
      id: "cmdi-quiz-4",
      title: "Blind Command Injection",
      type: "quiz",
      content: "",
      quiz: {
        question:
          "An application doesn't show command output. How might an attacker confirm command injection exists?",
        options: [
          "It's impossible without seeing output",
          "Use time-based techniques like 'sleep 10' and measure response delay",
          "Inject JavaScript to see the result",
          "Try SQL injection instead",
        ],
        correctAnswer: 1,
        explanation:
          "Time-based blind injection uses commands like 'sleep 10' or 'ping -c 10 localhost'. If the response takes ~10 seconds longer, command execution is confirmed. Attackers can then exfiltrate data via DNS queries or out-of-band channels.",
      },
    },
    {
      id: "cmdi-lab",
      title: "Fix the Vulnerable Code",
      type: "lab",
      content:
        "The code below uses shell execution with user input to convert images. This is vulnerable to command injection. Your mission: Refactor it to use safe, parameterized execution.",
      lab: {
        initialCode: `
const { exec } = require('child_process');

function convertImage(inputFile, outputFormat) {
  // VULNERABLE: Shell command with user input
  const command = 'convert ' + inputFile + ' output.' + outputFormat;

  exec(command, (error, stdout, stderr) => {
    if (error) {
      console.error('Conversion failed:', error);
      return;
    }
    console.log('Conversion complete');
  });
}
                `,
        solutionCode: `
const { execFile } = require('child_process');

function convertImage(inputFile, outputFormat) {
  // SECURE: Parameterized execution without shell
  const args = [inputFile, 'output.' + outputFormat];

  // Validate format is alphanumeric only
  if (!/^[a-zA-Z0-9]+$/.test(outputFormat)) {
    console.error('Invalid format');
    return;
  }

  execFile('convert', args, (error, stdout, stderr) => {
    if (error) {
      console.error('Conversion failed:', error);
      return;
    }
    console.log('Conversion complete');
  });
}
                `,
        instructions:
          "Fix the vulnerability: 1) Replace exec() with execFile() from child_process, 2) Pass arguments as an array instead of string concatenation, 3) Add input validation to ensure outputFormat contains only alphanumeric characters.",
      },
    },
  ],
};
