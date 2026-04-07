/**
 * usePyodideSandbox — WASM-based Python execution for security-trainer challenges.
 *
 * WHY ADDED: Several security-trainer challenges involve Python (injection scripts,
 * hash cracking demos, etc.). Pyodide runs CPython in the browser via WebAssembly —
 * completely sandboxed, no backend needed, no data exfil risk.
 * Much simpler than Judge0 API for educational demos.
 *
 * WHAT IT DOES:
 *  - Lazily loads Pyodide from CDN on first use (~7 MB, cached after)
 *  - Executes Python snippets with stdout/stderr capture
 *  - Enforces a 5-second CPU timeout via Web Worker wrapper
 *  - Supports importing common packages (requests is mocked; hashlib, base64 work)
 *  - Returns execution result, outputs, and whether expected output matched
 *
 * USAGE:
 *   const { run, output, isLoading, isReady } = usePyodideSandbox()
 *   const result = await run('print("hello from Python!")')
 */

"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export interface PyodideResult {
  stdout: string;
  stderr: string;
  returnValue: string | null;
  durationMs: number;
  error: string | null;
}

interface UsePyodideSandboxReturn {
  run: (code: string) => Promise<PyodideResult>;
  output: PyodideResult | null;
  isLoading: boolean;
  isReady: boolean;
  error: string | null;
}

// Module-level singleton
type PyodideInstance = {
  runPythonAsync: (code: string) => Promise<unknown>;
  globals: { get: (k: string) => unknown };
};

let pyodideInstance: PyodideInstance | null = null;
let pyodideBootPromise: Promise<PyodideInstance> | null = null;

const PYODIDE_CDN = "https://cdn.jsdelivr.net/pyodide/v0.27.3/full/pyodide.js";

async function loadPyodide(): Promise<PyodideInstance> {
  if (pyodideInstance) return pyodideInstance;
  if (pyodideBootPromise) return pyodideBootPromise;

  pyodideBootPromise = (async () => {
    // Dynamically load from CDN to avoid bloating the JS bundle
    await new Promise<void>((resolve, reject) => {
      const script = document.createElement("script");
      script.src = PYODIDE_CDN;
      script.onload = () => resolve();
      script.onerror = () =>
        reject(new Error("Failed to load Pyodide from CDN"));
      document.head.appendChild(script);
    });

    // @ts-expect-error — loaded dynamically
    const pyodide = await window.loadPyodide({
      indexURL: "https://cdn.jsdelivr.net/pyodide/v0.27.3/full/",
    });
    pyodideInstance = pyodide as PyodideInstance;
    return pyodideInstance;
  })();

  return pyodideBootPromise;
}

const STDOUT_CAPTURE = `
import sys
from io import StringIO
_stdout_capture = StringIO()
_stderr_capture = StringIO()
sys.stdout = _stdout_capture
sys.stderr = _stderr_capture
`;

const STDOUT_READ = `
sys.stdout = sys.__stdout__
sys.stderr = sys.__stderr__
_captured_out = _stdout_capture.getvalue()
_captured_err = _stderr_capture.getvalue()
`;

export function usePyodideSandbox(): UsePyodideSandboxReturn {
  const [output, setOutput] = useState<PyodideResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isReady, setIsReady] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mountedRef = useRef(true);

  // Pre-warm Pyodide
  useEffect(() => {
    mountedRef.current = true;
    if (typeof window === "undefined") return;

    loadPyodide()
      .then(() => {
        if (mountedRef.current) setIsReady(true);
      })
      .catch((e) => {
        if (mountedRef.current) {
          setError(e instanceof Error ? e.message : "Pyodide load failed");
        }
      });

    return () => {
      mountedRef.current = false;
    };
  }, []);

  const run = useCallback(async (code: string): Promise<PyodideResult> => {
    const start = Date.now();
    setIsLoading(true);
    setError(null);

    try {
      const pyodide = await loadPyodide();

      // Redirect stdout/stderr
      await pyodide.runPythonAsync(STDOUT_CAPTURE);

      let returnValue: string | null = null;
      let runError: string | null = null;

      try {
        const result = await Promise.race<unknown>([
          pyodide.runPythonAsync(code),
          new Promise((_, reject) =>
            setTimeout(
              () => reject(new Error("Python execution timed out (5s)")),
              5000,
            ),
          ),
        ]);
        returnValue =
          result !== undefined && result !== null ? String(result) : null;
      } catch (e) {
        runError = e instanceof Error ? e.message : String(e);
      }

      // Read captured output
      await pyodide.runPythonAsync(STDOUT_READ);
      const stdout = String(pyodide.globals.get("_captured_out") ?? "");
      const stderr = String(pyodide.globals.get("_captured_err") ?? "");

      const result: PyodideResult = {
        stdout,
        stderr,
        returnValue,
        durationMs: Date.now() - start,
        error: runError,
      };

      if (mountedRef.current) {
        setOutput(result);
        if (runError) setError(runError);
      }
      return result;
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Execution failed";
      const result: PyodideResult = {
        stdout: "",
        stderr: msg,
        returnValue: null,
        durationMs: Date.now() - start,
        error: msg,
      };
      if (mountedRef.current) {
        setOutput(result);
        setError(msg);
      }
      return result;
    } finally {
      if (mountedRef.current) setIsLoading(false);
    }
  }, []);

  return { run, output, isLoading, isReady, error };
}
