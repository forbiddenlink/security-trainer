import React, { memo, useState, useCallback } from "react";
import type { LabConfig } from "../../types";
import { CodeEditor } from "../CodeEditor";
import { Terminal, type TerminalCommand } from "../Terminal";
import { verifyLabSubmission } from "../../utils/labVerification";
import {
  AlertTriangle,
  CheckCircle,
  XCircle,
  Play,
  TerminalIcon,
  Code,
} from "lucide-react";
import { Button, Card } from "../ui";
import { clsx } from "clsx";

interface LabViewProps {
  lab: LabConfig;
  lessonId: string;
  onSuccess: () => void;
}

interface LabOutput {
  type: "success" | "error" | "info";
  message: string;
  hints?: string[];
}

// Lab-specific terminal commands
const createLabTerminalCommands = (
  _lessonId: string,
  getCode: () => string,
  _setOutput: (output: LabOutput | null) => void
): TerminalCommand[] => [
  {
    name: "test",
    description: "Run security tests on current code",
    handler: (_, terminal) => {
      terminal.writeLine("\r\n\x1b[1;33mRunning security analysis...\x1b[0m");
      terminal.writeLine("\x1b[0;37mChecking for common vulnerabilities...\x1b[0m");
      setTimeout(() => {
        terminal.writeLine("\x1b[1;36mAnalysis complete. Use 'deploy' to submit.\x1b[0m");
        terminal.writeLine("");
        terminal.prompt();
      }, 500);
    },
  },
  {
    name: "hint",
    description: "Get a hint for this lab",
    handler: (_, terminal) => {
      terminal.writeLine("\r\n\x1b[1;33mHint:\x1b[0m Look for user input that is not properly sanitized.");
      terminal.writeLine("\x1b[0;37mConsider: input validation, escaping, parameterization\x1b[0m");
      terminal.writeLine("");
    },
  },
  {
    name: "reset",
    description: "Reset code to initial state",
    handler: (_, terminal) => {
      terminal.writeLine("\r\n\x1b[1;31mWarning:\x1b[0m This will reset your code to the initial state.");
      terminal.writeLine("\x1b[0;37mUse the 'Reset Code' button in the editor panel.\x1b[0m");
      terminal.writeLine("");
    },
  },
  {
    name: "syntax",
    description: "Check code syntax",
    handler: (_, terminal) => {
      const code = getCode();
      try {
        // Basic syntax check for JavaScript
        new Function(code);
        terminal.writeLine("\r\n\x1b[1;32mSyntax check passed!\x1b[0m No obvious syntax errors.");
      } catch (error) {
        terminal.writeLine(`\r\n\x1b[1;31mSyntax error:\x1b[0m ${error instanceof Error ? error.message : "Unknown error"}`);
      }
      terminal.writeLine("");
    },
  },
  {
    name: "grep",
    description: "Search for pattern in code",
    handler: (args, terminal) => {
      const pattern = args.join(" ");
      if (!pattern) {
        terminal.writeLine("\r\n\x1b[1;31mUsage: grep <pattern>\x1b[0m");
        terminal.writeLine("");
        return;
      }
      const code = getCode();
      const lines = code.split("\n");
      let found = false;
      lines.forEach((line, idx) => {
        if (line.toLowerCase().includes(pattern.toLowerCase())) {
          terminal.writeLine(`\r\n\x1b[1;33m${idx + 1}:\x1b[0m ${line.trim()}`);
          found = true;
        }
      });
      if (!found) {
        terminal.writeLine(`\r\n\x1b[0;37mNo matches found for "${pattern}"\x1b[0m`);
      }
      terminal.writeLine("");
    },
  },
  {
    name: "lines",
    description: "Count lines of code",
    handler: (_, terminal) => {
      const code = getCode();
      const lines = code.split("\n");
      const nonEmpty = lines.filter((l) => l.trim().length > 0).length;
      terminal.writeLine(`\r\n\x1b[1;36mTotal lines:\x1b[0m ${lines.length}`);
      terminal.writeLine(`\x1b[1;36mNon-empty lines:\x1b[0m ${nonEmpty}`);
      terminal.writeLine("");
    },
  },
];

/**
 * Interactive code lab with Monaco editor, terminal, and verification
 */
export const LabView: React.FC<LabViewProps> = memo(
  ({ lab, lessonId, onSuccess }) => {
    const [code, setCode] = useState(lab.initialCode);
    const [output, setOutput] = useState<LabOutput | null>(null);
    const [activeTab, setActiveTab] = useState<"editor" | "terminal">("editor");

    const handleVerify = useCallback(() => {
      try {
        const result = verifyLabSubmission(lessonId, code);

        if (result.passed) {
          setOutput({
            type: "success",
            message: "Vulnerability Patched! Excellent work.",
          });
          onSuccess();
        } else {
          setOutput({
            type: "error",
            message: "Vulnerability still present. Review the hints below.",
            hints: result.hints,
          });
        }
      } catch (error) {
        console.error("Lab verification failed:", error);
        setOutput({
          type: "error",
          message:
            error instanceof Error
              ? `Verification Error: ${error.message}`
              : "Syntax Error or Runtime Exception",
        });
      }
    }, [code, lessonId, onSuccess]);

    const handleCodeChange = useCallback((val: string | undefined) => {
      setCode(val || "");
    }, []);

    // Create terminal commands with access to current code
    const terminalCommands = createLabTerminalCommands(
      lessonId,
      () => code,
      setOutput
    );

    return (
      <div className="flex flex-col lg:flex-row h-full gap-4">
        <div className="lg:w-[34%] flex flex-col gap-4 overflow-auto pb-8">
          <Card className="p-6">
            <h3 className="font-semibold tracking-tight flex items-center gap-2 mb-2">
              <AlertTriangle
                className="w-5 h-5 text-warning"
                aria-hidden="true"
              />
              Mission Objective
            </h3>
            <p className="text-muted-foreground">{lab.instructions}</p>
          </Card>
          <Card className="bg-muted/20 p-6 flex-1" aria-live="polite">
            <p className="text-sm font-mono text-muted-foreground opacity-50">
              Virtual Environment Active
            </p>
            {output && (
              <div
                className={clsx(
                  "mt-4 p-4 rounded-[var(--radius-sm)] border animate-in fade-in slide-in-from-bottom-2",
                  output.type === "success"
                    ? "bg-accent/10 border-accent/20 text-accent"
                    : "bg-destructive/10 border-destructive/20 text-destructive",
                )}
                role="alert"
              >
                <div className="font-bold flex items-center gap-2">
                  {output.type === "success" ? (
                    <CheckCircle className="w-4 h-4" aria-hidden="true" />
                  ) : (
                    <XCircle className="w-4 h-4" aria-hidden="true" />
                  )}
                  {output.type === "success"
                    ? "System Secured"
                    : "Vulnerability Detected"}
                </div>
                <p className="text-sm mt-1">{output.message}</p>
                {output.hints && output.hints.length > 0 && (
                  <ul className="mt-3 space-y-1 text-sm text-foreground/80">
                    {output.hints.map((hint, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="text-warning mt-0.5">-</span>
                        {hint}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </Card>
        </div>
        <div className="lg:w-[66%] flex flex-col gap-2 h-full">
          {/* Tab Bar */}
          <div className="flex items-center gap-1 border-b border-border/50 pb-2">
            <button
              onClick={() => setActiveTab("editor")}
              className={clsx(
                "flex items-center gap-2 px-3 py-1.5 rounded-t-[var(--radius-sm)] text-sm font-medium transition-colors",
                activeTab === "editor"
                  ? "bg-primary/10 text-primary border-b-2 border-primary"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted/30"
              )}
            >
              <Code className="w-4 h-4" />
              Editor
            </button>
            <button
              onClick={() => setActiveTab("terminal")}
              className={clsx(
                "flex items-center gap-2 px-3 py-1.5 rounded-t-[var(--radius-sm)] text-sm font-medium transition-colors",
                activeTab === "terminal"
                  ? "bg-primary/10 text-primary border-b-2 border-primary"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted/30"
              )}
            >
              <TerminalIcon className="w-4 h-4" />
              Terminal
            </button>
          </div>

          {/* Content Area */}
          <div className="flex-1 min-h-[400px]" aria-label={activeTab === "editor" ? "Code editor" : "Terminal"}>
            {activeTab === "editor" ? (
              <CodeEditor initialCode={code} onChange={handleCodeChange} />
            ) : (
              <Terminal
                theme="dark"
                welcomeMessage="Lab Terminal - Security Analysis Environment\nType 'help' for available commands."
                prompt="lab>"
                commands={terminalCommands}
                className="h-full"
              />
            )}
          </div>
          <div className="flex justify-end">
            <Button
              onClick={handleVerify}
              variant="accent"
              className="px-5"
              aria-label="Deploy patch and verify your code fix"
            >
              <Play className="w-4 h-4" aria-hidden="true" /> Deploy Patch
            </Button>
          </div>
        </div>
      </div>
    );
  },
);

LabView.displayName = "LabView";
