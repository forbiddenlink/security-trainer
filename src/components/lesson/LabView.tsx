import React, { memo, useState, useCallback } from "react";
import type { LabConfig } from "../../types";
import { CodeEditor } from "../CodeEditor";
import { verifyLabSubmission } from "../../utils/labVerification";
import { AlertTriangle, CheckCircle, XCircle, Play } from "lucide-react";
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

/**
 * Interactive code lab with Monaco editor and verification
 */
export const LabView: React.FC<LabViewProps> = memo(
  ({ lab, lessonId, onSuccess }) => {
    const [code, setCode] = useState(lab.initialCode);
    const [output, setOutput] = useState<LabOutput | null>(null);

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
          <div className="flex-1 min-h-[400px]" aria-label="Code editor">
            <CodeEditor initialCode={code} onChange={handleCodeChange} />
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
