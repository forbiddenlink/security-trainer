import React, {
  memo,
  useState,
  useCallback,
  useMemo,
  useRef,
  useEffect,
} from "react";
import type { LabConfig } from "../../types";
import { CodeEditor } from "../CodeEditor";
import { Terminal, type TerminalCommand } from "../Terminal";
import { verifyLabSubmission } from "../../utils/labVerification";
import { buildLabTutorChallenge } from "../../lib/labTutorContext";
import { useSocraticTutor } from "../../lib/useSocraticTutor";
import {
  AlertTriangle,
  CheckCircle,
  XCircle,
  Play,
  TerminalIcon,
  Code,
  Lightbulb,
  MessageCircleQuestion,
  RotateCcw,
} from "lucide-react";
import { Button, Card, Chip } from "../ui";
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

/**
 * Interactive code lab with Monaco editor, terminal, verification, and Socratic tutor
 */
export const LabView: React.FC<LabViewProps> = memo(
  ({ lab, lessonId, onSuccess }) => {
    const [code, setCode] = useState(lab.initialCode);
    const [editorKey, setEditorKey] = useState(0);
    const [output, setOutput] = useState<LabOutput | null>(null);
    const [activeTab, setActiveTab] = useState<"editor" | "terminal">("editor");
    const [patched, setPatched] = useState(false);

    const challenge = useMemo(
      () => buildLabTutorChallenge(lessonId, lab),
      [lessonId, lab],
    );

    const {
      getHint,
      hints,
      hintLevel,
      isLoading: tutorLoading,
      isExhausted,
      resetHints,
    } = useSocraticTutor(challenge);

    // Keep latest values available to terminal command handlers
    const codeRef = useRef(code);
    const getHintRef = useRef(getHint);
    const hintsRef = useRef(hints);
    const lessonIdRef = useRef(lessonId);
    codeRef.current = code;
    getHintRef.current = getHint;
    hintsRef.current = hints;
    lessonIdRef.current = lessonId;

    // Reset editor state when switching labs
    useEffect(() => {
      setCode(lab.initialCode);
      setOutput(null);
      setPatched(false);
      setActiveTab("editor");
      setEditorKey((k) => k + 1);
    }, [lessonId, lab.initialCode]);

    const handleVerify = useCallback(() => {
      try {
        const result = verifyLabSubmission(lessonId, code);

        if (result.passed) {
          setPatched(true);
          setOutput({
            type: "success",
            message:
              "Vulnerability patched. Clearance upgraded — excellent work, Agent.",
          });
          onSuccess();
        } else {
          setOutput({
            type: "error",
            message:
              "Vulnerability still present. Request an Intel Hint or review the checks below.",
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

    const handleResetCode = useCallback(() => {
      setCode(lab.initialCode);
      setOutput(null);
      setPatched(false);
      resetHints();
      setEditorKey((k) => k + 1);
    }, [lab.initialCode, resetHints]);

    const handleRequestHint = useCallback(async () => {
      const hint = await getHint();
      if (hint) {
        setOutput({
          type: "info",
          message: `Intel Hint L${hint.level}: ${hint.question}`,
          hints: hint.conceptPointer ? [hint.conceptPointer] : undefined,
        });
      }
    }, [getHint]);

    const terminalCommands: TerminalCommand[] = useMemo(
      () => [
        {
          name: "test",
          description: "Run verifier checks on current code (dry-run)",
          handler: (_, terminal) => {
            terminal.writeLine("\r\n\x1b[1;33mRunning lab verifier...\x1b[0m");
            const result = verifyLabSubmission(
              lessonIdRef.current,
              codeRef.current,
            );
            if (result.passed) {
              terminal.writeLine(
                "\x1b[1;32mPASS\x1b[0m — Patch looks solid. Use Deploy Patch to submit.",
              );
            } else {
              terminal.writeLine(
                "\x1b[1;31mFAIL\x1b[0m — Vulnerability still present.",
              );
              result.hints.slice(0, 4).forEach((h, i) => {
                terminal.writeLine(`\x1b[0;37m  ${i + 1}. ${h}\x1b[0m`);
              });
              if (result.hints.length === 0) {
                terminal.writeLine(
                  "\x1b[0;37m  No specific checks failed — review the mission brief.\x1b[0m",
                );
              }
              terminal.writeLine(
                "\x1b[1;36mTip:\x1b[0m type \x1b[1mhint\x1b[0m for a Socratic nudge.",
              );
            }
            terminal.writeLine("");
            terminal.prompt();
          },
        },
        {
          name: "hint",
          description: "Request next Socratic intel hint (max 3)",
          handler: async (_, terminal) => {
            terminal.writeLine("\r\n\x1b[1;33mRequesting intel hint...\x1b[0m");
            const hint = await getHintRef.current();
            if (!hint) {
              const revealed = hintsRef.current.length;
              if (revealed >= 3) {
                terminal.writeLine(
                  "\x1b[1;31mAll 3 hints exhausted.\x1b[0m Re-read the mission brief and try `test`.",
                );
              } else {
                terminal.writeLine(
                  "\x1b[0;37mHint unavailable right now — try again.\x1b[0m",
                );
              }
              terminal.writeLine("");
              terminal.prompt();
              return;
            }
            terminal.writeLine(
              `\x1b[1;36mL${hint.level}/3\x1b[0m  ${hint.question}`,
            );
            if (hint.conceptPointer) {
              terminal.writeLine(
                `\x1b[0;37mResearch:\x1b[0m ${hint.conceptPointer}`,
              );
            }
            terminal.writeLine("");
            terminal.prompt();
          },
        },
        {
          name: "hints",
          description: "Show all revealed intel hints",
          handler: (_, terminal) => {
            const revealed = hintsRef.current;
            if (revealed.length === 0) {
              terminal.writeLine(
                "\r\n\x1b[0;37mNo hints revealed yet. Type `hint` to request one.\x1b[0m",
              );
            } else {
              terminal.writeLine("\r\n\x1b[1;33mRevealed intel:\x1b[0m");
              revealed.forEach((h) => {
                terminal.writeLine(
                  `\x1b[1;36mL${h.level}\x1b[0m  ${h.question}`,
                );
              });
            }
            terminal.writeLine("");
          },
        },
        {
          name: "reset",
          description: "Instructions to reset lab code",
          handler: (_, terminal) => {
            terminal.writeLine(
              "\r\n\x1b[1;31mWarning:\x1b[0m Use the Reset Code button in the mission panel.",
            );
            terminal.writeLine("");
          },
        },
        {
          name: "syntax",
          description: "Check JavaScript syntax of current code",
          handler: (_, terminal) => {
            const current = codeRef.current;
            try {
              new Function(current);
              terminal.writeLine(
                "\r\n\x1b[1;32mSyntax check passed.\x1b[0m No obvious syntax errors.",
              );
            } catch (error) {
              terminal.writeLine(
                `\r\n\x1b[1;31mSyntax error:\x1b[0m ${
                  error instanceof Error ? error.message : "Unknown error"
                }`,
              );
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
            const lines = codeRef.current.split("\n");
            let found = false;
            lines.forEach((line, idx) => {
              if (line.toLowerCase().includes(pattern.toLowerCase())) {
                terminal.writeLine(
                  `\r\n\x1b[1;33m${idx + 1}:\x1b[0m ${line.trim()}`,
                );
                found = true;
              }
            });
            if (!found) {
              terminal.writeLine(
                `\r\n\x1b[0;37mNo matches for "${pattern}"\x1b[0m`,
              );
            }
            terminal.writeLine("");
          },
        },
        {
          name: "lines",
          description: "Count lines of code",
          handler: (_, terminal) => {
            const lines = codeRef.current.split("\n");
            const nonEmpty = lines.filter((l) => l.trim().length > 0).length;
            terminal.writeLine(
              `\r\n\x1b[1;36mTotal lines:\x1b[0m ${lines.length}`,
            );
            terminal.writeLine(`\x1b[1;36mNon-empty lines:\x1b[0m ${nonEmpty}`);
            terminal.writeLine("");
          },
        },
      ],
      [],
    );

    return (
      <div className="flex flex-col lg:flex-row h-full gap-4">
        <div className="lg:w-[34%] flex flex-col gap-4 overflow-auto pb-8">
          <Card className="p-6 border-l-[3px] border-l-warning">
            <h3 className="font-semibold tracking-tight flex items-center gap-2 mb-2">
              <AlertTriangle
                className="w-5 h-5 text-warning"
                aria-hidden="true"
              />
              Mission Objective
            </h3>
            <p className="text-muted-foreground text-body-sm">
              {lab.instructions}
            </p>
            <div className="mt-4 flex flex-wrap gap-2">
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={handleResetCode}
                aria-label="Reset code to initial state"
              >
                <RotateCcw className="w-3.5 h-3.5" aria-hidden="true" />
                Reset Code
              </Button>
            </div>
          </Card>

          {/* Socratic Intel Tutor */}
          <Card className="p-6" aria-label="Intel tutor">
            <div className="flex items-start justify-between gap-3 mb-3">
              <div>
                <h3 className="font-semibold tracking-tight flex items-center gap-2">
                  <MessageCircleQuestion
                    className="w-5 h-5 text-primary"
                    aria-hidden="true"
                  />
                  Intel Briefing
                </h3>
                <p className="text-caption text-muted-foreground mt-1 normal-case tracking-normal">
                  Socratic hints — discover the fix, don&apos;t copy it
                </p>
              </div>
              <Chip tone="primary">{hintLevel}/3</Chip>
            </div>

            {hints.length === 0 ? (
              <p className="text-body-sm text-muted-foreground mb-4">
                Stuck? Request a probing question that points you at the concept
                without spoiling the patch.
              </p>
            ) : (
              <ol className="space-y-3 mb-4">
                {hints.map((h) => (
                  <li
                    key={h.level}
                    className="rounded-[var(--radius-sm)] border border-border/70 bg-muted/30 p-3"
                  >
                    <p className="ui-label mb-1">Hint L{h.level}</p>
                    <p className="text-body-sm text-foreground">{h.question}</p>
                    {h.conceptPointer && (
                      <p className="text-caption text-muted-foreground mt-2 normal-case tracking-normal">
                        Research: {h.conceptPointer}
                      </p>
                    )}
                  </li>
                ))}
              </ol>
            )}

            <Button
              type="button"
              variant={isExhausted ? "secondary" : "outline"}
              size="sm"
              className="w-full"
              onClick={handleRequestHint}
              disabled={tutorLoading || isExhausted || patched}
              aria-label={
                isExhausted
                  ? "All hints exhausted"
                  : "Request next Socratic hint"
              }
            >
              <Lightbulb className="w-3.5 h-3.5" aria-hidden="true" />
              {tutorLoading
                ? "Consulting intel…"
                : isExhausted
                  ? "Hints exhausted"
                  : `Request Hint L${hintLevel + 1}`}
            </Button>
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
                    : output.type === "info"
                      ? "bg-primary/8 border-primary/25 text-foreground"
                      : "bg-destructive/10 border-destructive/20 text-destructive",
                )}
                role="alert"
              >
                <div className="font-bold flex items-center gap-2">
                  {output.type === "success" ? (
                    <CheckCircle className="w-4 h-4" aria-hidden="true" />
                  ) : output.type === "info" ? (
                    <Lightbulb
                      className="w-4 h-4 text-primary"
                      aria-hidden="true"
                    />
                  ) : (
                    <XCircle className="w-4 h-4" aria-hidden="true" />
                  )}
                  {output.type === "success"
                    ? "System Secured"
                    : output.type === "info"
                      ? "Intel Update"
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
          <div className="flex items-center gap-1 border-b border-border/50 pb-2">
            <button
              type="button"
              onClick={() => setActiveTab("editor")}
              className={clsx(
                "flex items-center gap-2 px-3 py-1.5 rounded-t-[var(--radius-sm)] text-sm font-medium transition-colors",
                activeTab === "editor"
                  ? "bg-primary/10 text-primary border-b-2 border-primary"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted/30",
              )}
            >
              <Code className="w-4 h-4" />
              Editor
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("terminal")}
              className={clsx(
                "flex items-center gap-2 px-3 py-1.5 rounded-t-[var(--radius-sm)] text-sm font-medium transition-colors",
                activeTab === "terminal"
                  ? "bg-primary/10 text-primary border-b-2 border-primary"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted/30",
              )}
            >
              <TerminalIcon className="w-4 h-4" />
              Terminal
            </button>
          </div>

          <div
            className="flex-1 min-h-[400px]"
            aria-label={activeTab === "editor" ? "Code editor" : "Terminal"}
          >
            {activeTab === "editor" ? (
              <CodeEditor
                key={editorKey}
                initialCode={code}
                onChange={handleCodeChange}
              />
            ) : (
              <Terminal
                theme="amber"
                welcomeMessage={`Lab Terminal — ${challenge.title}\nCommands: test | hint | hints | grep | syntax | lines | help`}
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
              disabled={patched}
              aria-label="Deploy patch and verify your code fix"
            >
              <Play className="w-4 h-4" aria-hidden="true" />{" "}
              {patched ? "Patch Deployed" : "Deploy Patch"}
            </Button>
          </div>
        </div>
      </div>
    );
  },
);

LabView.displayName = "LabView";
