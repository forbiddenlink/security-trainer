import React, { useEffect, useRef, useCallback, useState, memo } from "react";
import { Terminal as XTerm } from "xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import "xterm/css/xterm.css";
import { cn } from "../lib/cn";

export interface TerminalCommand {
  name: string;
  description: string;
  handler: (args: string[], terminal: TerminalRef) => void | Promise<void>;
}

export interface TerminalRef {
  write: (text: string) => void;
  writeLine: (text: string) => void;
  clear: () => void;
  prompt: () => void;
  setPrompt: (prompt: string) => void;
}

interface TerminalProps {
  className?: string;
  commands?: TerminalCommand[];
  welcomeMessage?: string;
  prompt?: string;
  onCommand?: (command: string, args: string[]) => void;
  readOnly?: boolean;
  fontSize?: number;
  theme?: "dark" | "matrix" | "amber" | "cyber";
}

// Terminal color themes
const themes = {
  dark: {
    background: "#0d1117",
    foreground: "#c9d1d9",
    cursor: "#58a6ff",
    cursorAccent: "#0d1117",
    selectionBackground: "#264f78",
    black: "#484f58",
    red: "#ff7b72",
    green: "#3fb950",
    yellow: "#d29922",
    blue: "#58a6ff",
    magenta: "#bc8cff",
    cyan: "#39c5cf",
    white: "#b1bac4",
    brightBlack: "#6e7681",
    brightRed: "#ffa198",
    brightGreen: "#56d364",
    brightYellow: "#e3b341",
    brightBlue: "#79c0ff",
    brightMagenta: "#d2a8ff",
    brightCyan: "#56d4dd",
    brightWhite: "#f0f6fc",
  },
  matrix: {
    background: "#0a0a0a",
    foreground: "#00ff41",
    cursor: "#00ff41",
    cursorAccent: "#0a0a0a",
    selectionBackground: "#003300",
    black: "#0a0a0a",
    red: "#ff0000",
    green: "#00ff41",
    yellow: "#ffff00",
    blue: "#00ffff",
    magenta: "#ff00ff",
    cyan: "#00ff41",
    white: "#00ff41",
    brightBlack: "#333333",
    brightRed: "#ff5555",
    brightGreen: "#55ff55",
    brightYellow: "#ffff55",
    brightBlue: "#55ffff",
    brightMagenta: "#ff55ff",
    brightCyan: "#55ff55",
    brightWhite: "#ffffff",
  },
  amber: {
    background: "#1a1200",
    foreground: "#ffb000",
    cursor: "#ffb000",
    cursorAccent: "#1a1200",
    selectionBackground: "#3d2e00",
    black: "#1a1200",
    red: "#ff6600",
    green: "#ffcc00",
    yellow: "#ffb000",
    blue: "#ff9900",
    magenta: "#ff7700",
    cyan: "#ffcc00",
    white: "#ffb000",
    brightBlack: "#4d3600",
    brightRed: "#ff8833",
    brightGreen: "#ffdd33",
    brightYellow: "#ffc233",
    brightBlue: "#ffaa33",
    brightMagenta: "#ff9933",
    brightCyan: "#ffdd33",
    brightWhite: "#ffe0a0",
  },
  cyber: {
    background: "#0c0c1e",
    foreground: "#00f5ff",
    cursor: "#ff00ff",
    cursorAccent: "#0c0c1e",
    selectionBackground: "#1a1a3e",
    black: "#0c0c1e",
    red: "#ff3860",
    green: "#00ff9f",
    yellow: "#ffd700",
    blue: "#00f5ff",
    magenta: "#ff00ff",
    cyan: "#00f5ff",
    white: "#ffffff",
    brightBlack: "#2d2d5e",
    brightRed: "#ff5c7c",
    brightGreen: "#33ffb2",
    brightYellow: "#ffe033",
    brightBlue: "#33f7ff",
    brightMagenta: "#ff33ff",
    brightCyan: "#33f7ff",
    brightWhite: "#ffffff",
  },
};

// Default built-in commands
const defaultCommands: TerminalCommand[] = [
  {
    name: "help",
    description: "Show available commands",
    handler: (_args, terminal) => {
      terminal.writeLine("\r\n\x1b[1;36mAvailable Commands:\x1b[0m\r\n");
      terminal.writeLine("  \x1b[1;33mhelp\x1b[0m     - Show this help message");
      terminal.writeLine("  \x1b[1;33mclear\x1b[0m    - Clear the terminal");
      terminal.writeLine("  \x1b[1;33mwhoami\x1b[0m   - Display current user");
      terminal.writeLine("  \x1b[1;33mdate\x1b[0m     - Show current date/time");
      terminal.writeLine("  \x1b[1;33mecho\x1b[0m     - Print arguments to terminal");
      terminal.writeLine("");
    },
  },
  {
    name: "clear",
    description: "Clear terminal",
    handler: (_args, terminal) => {
      terminal.clear();
    },
  },
  {
    name: "whoami",
    description: "Display current user",
    handler: (_, terminal) => {
      terminal.writeLine("\r\nagent@sectrainer");
      terminal.writeLine("");
    },
  },
  {
    name: "date",
    description: "Show current date/time",
    handler: (_, terminal) => {
      terminal.writeLine(`\r\n${new Date().toLocaleString()}`);
      terminal.writeLine("");
    },
  },
  {
    name: "echo",
    description: "Print text",
    handler: (args, terminal) => {
      terminal.writeLine(`\r\n${args.join(" ")}`);
      terminal.writeLine("");
    },
  },
];

/**
 * Interactive Terminal component using xterm.js
 *
 * Features:
 * - Full terminal emulation with command history
 * - Multiple color themes (dark, matrix, amber, cyber)
 * - Custom command support
 * - Auto-resize on window changes
 * - Click-able links
 *
 * @example
 * <Terminal
 *   theme="matrix"
 *   welcomeMessage="Welcome to SecTrainer Terminal"
 *   commands={[
 *     { name: 'scan', description: 'Scan target', handler: (args, term) => { ... } }
 *   ]}
 * />
 */
export const Terminal: React.FC<TerminalProps> = memo(
  ({
    className,
    commands = [],
    welcomeMessage,
    prompt: initialPrompt = "agent@sectrainer:~$",
    onCommand,
    readOnly = false,
    fontSize = 14,
    theme = "dark",
  }) => {
    const terminalRef = useRef<HTMLDivElement>(null);
    const xtermRef = useRef<XTerm | null>(null);
    const fitAddonRef = useRef<FitAddon | null>(null);
    const [_currentLine, setCurrentLine] = useState("");
    const [_commandHistory, setCommandHistory] = useState<string[]>([]);
    const [_historyIndex, setHistoryIndex] = useState(-1);
    const promptRef = useRef(initialPrompt);
    const cursorPositionRef = useRef(0);

    // Create terminal ref API for commands
    const terminalApi = useRef<TerminalRef>({
      write: (text: string) => xtermRef.current?.write(text),
      writeLine: (text: string) => xtermRef.current?.writeln(text),
      clear: () => {
        xtermRef.current?.clear();
        xtermRef.current?.write(`\r\n${promptRef.current} `);
      },
      prompt: () => xtermRef.current?.write(`\r\n${promptRef.current} `),
      setPrompt: (newPrompt: string) => {
        promptRef.current = newPrompt;
      },
    });

    // Merge default commands with custom commands
    const allCommands = [...defaultCommands, ...commands];

    const executeCommand = useCallback(
      async (commandLine: string) => {
        const parts = commandLine.trim().split(/\s+/);
        const commandName = parts[0]?.toLowerCase();
        const args = parts.slice(1);

        if (!commandName) {
          terminalApi.current.prompt();
          return;
        }

        // Call onCommand callback if provided
        onCommand?.(commandName, args);

        // Find and execute the command
        const command = allCommands.find(
          (cmd) => cmd.name.toLowerCase() === commandName
        );

        if (command) {
          try {
            await command.handler(args, terminalApi.current);
          } catch (error) {
            terminalApi.current.writeLine(
              `\r\n\x1b[1;31mError executing command: ${error instanceof Error ? error.message : "Unknown error"}\x1b[0m`
            );
            terminalApi.current.writeLine("");
          }
        } else {
          terminalApi.current.writeLine(
            `\r\n\x1b[1;31mCommand not found: ${commandName}\x1b[0m`
          );
          terminalApi.current.writeLine(
            '\x1b[0;37mType "help" for available commands.\x1b[0m'
          );
          terminalApi.current.writeLine("");
        }

        terminalApi.current.prompt();
      },
      [allCommands, onCommand]
    );

    // Initialize terminal
    useEffect(() => {
      if (!terminalRef.current) return;

      const xterm = new XTerm({
        cursorBlink: true,
        cursorStyle: "block",
        fontSize,
        fontFamily: '"Fira Code", "JetBrains Mono", Menlo, Monaco, monospace',
        theme: themes[theme],
        allowProposedApi: true,
        scrollback: 1000,
        convertEol: true,
      });

      const fitAddon = new FitAddon();
      const webLinksAddon = new WebLinksAddon();

      xterm.loadAddon(fitAddon);
      xterm.loadAddon(webLinksAddon);
      xterm.open(terminalRef.current);

      // Initial fit
      setTimeout(() => {
        fitAddon.fit();
      }, 0);

      xtermRef.current = xterm;
      fitAddonRef.current = fitAddon;

      // Display welcome message
      if (welcomeMessage) {
        xterm.writeln(`\x1b[1;32m${welcomeMessage}\x1b[0m`);
        xterm.writeln("");
      } else {
        xterm.writeln("\x1b[1;36m=================================\x1b[0m");
        xterm.writeln("\x1b[1;33m   SecTrainer Terminal v1.0.0    \x1b[0m");
        xterm.writeln("\x1b[1;36m=================================\x1b[0m");
        xterm.writeln("");
        xterm.writeln('\x1b[0;37mType "help" for available commands.\x1b[0m');
        xterm.writeln("");
      }

      xterm.write(`${promptRef.current} `);

      // Handle input
      if (!readOnly) {
        xterm.onKey(({ key, domEvent }) => {
          const keyCode = domEvent.keyCode;

          // Enter key
          if (keyCode === 13) {
            setCurrentLine((line) => {
              const trimmed = line.trim();
              if (trimmed) {
                setCommandHistory((prev) => [...prev, trimmed]);
              }
              setHistoryIndex(-1);
              executeCommand(line);
              return "";
            });
            cursorPositionRef.current = 0;
            return;
          }

          // Backspace
          if (keyCode === 8) {
            setCurrentLine((line) => {
              if (cursorPositionRef.current > 0) {
                const newLine =
                  line.slice(0, cursorPositionRef.current - 1) +
                  line.slice(cursorPositionRef.current);
                cursorPositionRef.current--;
                // Rewrite line
                xterm.write("\b \b");
                const afterCursor = line.slice(cursorPositionRef.current + 1);
                if (afterCursor) {
                  xterm.write(afterCursor + " ");
                  xterm.write(
                    "\b".repeat(afterCursor.length + 1)
                  );
                }
                return newLine;
              }
              return line;
            });
            return;
          }

          // Tab for autocomplete
          if (keyCode === 9) {
            domEvent.preventDefault();
            setCurrentLine((line) => {
              const parts = line.split(/\s+/);
              if (parts.length === 1) {
                const partial = parts[0].toLowerCase();
                const matches = allCommands.filter((cmd) =>
                  cmd.name.toLowerCase().startsWith(partial)
                );
                if (matches.length === 1) {
                  const completion = matches[0].name.slice(partial.length);
                  xterm.write(completion);
                  cursorPositionRef.current += completion.length;
                  return line + completion;
                } else if (matches.length > 1) {
                  xterm.writeln("");
                  xterm.writeln(
                    matches.map((m) => `  ${m.name}`).join("  ")
                  );
                  xterm.write(`${promptRef.current} ${line}`);
                }
              }
              return line;
            });
            return;
          }

          // Up arrow - command history
          if (keyCode === 38) {
            domEvent.preventDefault();
            setCommandHistory((history) => {
              if (history.length === 0) return history;

              setHistoryIndex((idx) => {
                const newIdx = Math.min(idx + 1, history.length - 1);
                const cmd = history[history.length - 1 - newIdx];
                if (cmd) {
                  setCurrentLine((line) => {
                    // Clear current line
                    xterm.write("\r" + " ".repeat(promptRef.current.length + 1 + line.length));
                    xterm.write(`\r${promptRef.current} ${cmd}`);
                    cursorPositionRef.current = cmd.length;
                    return cmd;
                  });
                }
                return newIdx;
              });
              return history;
            });
            return;
          }

          // Down arrow - command history
          if (keyCode === 40) {
            domEvent.preventDefault();
            setCommandHistory((history) => {
              setHistoryIndex((idx) => {
                if (idx <= 0) {
                  setCurrentLine((line) => {
                    xterm.write("\r" + " ".repeat(promptRef.current.length + 1 + line.length));
                    xterm.write(`\r${promptRef.current} `);
                    cursorPositionRef.current = 0;
                    return "";
                  });
                  return -1;
                }

                const newIdx = idx - 1;
                const cmd = history[history.length - 1 - newIdx];
                if (cmd) {
                  setCurrentLine((line) => {
                    xterm.write("\r" + " ".repeat(promptRef.current.length + 1 + line.length));
                    xterm.write(`\r${promptRef.current} ${cmd}`);
                    cursorPositionRef.current = cmd.length;
                    return cmd;
                  });
                }
                return newIdx;
              });
              return history;
            });
            return;
          }

          // Left arrow
          if (keyCode === 37) {
            if (cursorPositionRef.current > 0) {
              cursorPositionRef.current--;
              xterm.write(key);
            }
            return;
          }

          // Right arrow
          if (keyCode === 39) {
            setCurrentLine((line) => {
              if (cursorPositionRef.current < line.length) {
                cursorPositionRef.current++;
                xterm.write(key);
              }
              return line;
            });
            return;
          }

          // Ctrl+C
          if (domEvent.ctrlKey && keyCode === 67) {
            setCurrentLine("");
            cursorPositionRef.current = 0;
            xterm.writeln("^C");
            xterm.write(`${promptRef.current} `);
            return;
          }

          // Ctrl+L - clear screen
          if (domEvent.ctrlKey && keyCode === 76) {
            xterm.clear();
            xterm.write(`${promptRef.current} `);
            setCurrentLine("");
            cursorPositionRef.current = 0;
            return;
          }

          // Printable characters
          if (key.length === 1 && !domEvent.ctrlKey && !domEvent.altKey && !domEvent.metaKey) {
            setCurrentLine((line) => {
              const newLine =
                line.slice(0, cursorPositionRef.current) +
                key +
                line.slice(cursorPositionRef.current);
              const afterCursor = line.slice(cursorPositionRef.current);
              xterm.write(key + afterCursor);
              if (afterCursor) {
                xterm.write("\b".repeat(afterCursor.length));
              }
              cursorPositionRef.current++;
              return newLine;
            });
          }
        });
      }

      // Handle resize
      const handleResize = () => {
        fitAddon.fit();
      };
      window.addEventListener("resize", handleResize);

      return () => {
        window.removeEventListener("resize", handleResize);
        xterm.dispose();
      };
    }, [executeCommand, fontSize, theme, welcomeMessage, readOnly, allCommands]);

    // Update theme when changed
    useEffect(() => {
      if (xtermRef.current) {
        xtermRef.current.options.theme = themes[theme];
      }
    }, [theme]);

    return (
      <div
        className={cn(
          "h-full w-full overflow-hidden rounded-[var(--radius-sm)] border border-border",
          "bg-[#0d1117]",
          theme === "matrix" && "bg-[#0a0a0a]",
          theme === "amber" && "bg-[#1a1200]",
          theme === "cyber" && "bg-[#0c0c1e]",
          className
        )}
      >
        <div
          ref={terminalRef}
          className="h-full w-full p-2"
          style={{
            background: themes[theme].background,
          }}
        />
      </div>
    );
  }
);

Terminal.displayName = "Terminal";
