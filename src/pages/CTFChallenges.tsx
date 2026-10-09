import React, { useState, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { motion, AnimatePresence } from "framer-motion";
import { prefersReducedMotion } from "../utils/prefersReducedMotion";
import { clsx } from "clsx";
import {
  Flag,
  Lock,
  Search,
  ChevronDown,
  Lightbulb,
  AlertCircle,
  CheckCircle,
  Trophy,
  Globe,
  Binary,
  Eye,
  Puzzle,
  Skull,
  TerminalIcon,
  ChevronUp,
} from "lucide-react";
import { Button, EmptyState, Input } from "../components/ui";
import { LiveLabTargets } from "../components/LiveLabTargets";
import { Terminal, type TerminalCommand } from "../components/Terminal";
import { useGameStore } from "../store/gameStore";
import { CTF_CHALLENGES, getChallengeById } from "../data/ctfChallenges";
import {
  getCategoryLabel,
  CTF_CATEGORIES,
  normalizeFlag,
  isValidFlagFormat,
  type CTFCategory,
  type CTFChallenge,
} from "../lib/ctf";

// Category icon mapping
const categoryIcons: Record<
  CTFCategory,
  React.ComponentType<{ className?: string }>
> = {
  web: Globe,
  crypto: Lock,
  forensics: Search,
  pwn: Skull,
  misc: Puzzle,
  reverse: Binary,
  osint: Eye,
};

// Difficulty colors
const difficultyColors = {
  easy: "text-accent",
  medium: "text-warning",
  hard: "text-destructive",
  insane: "text-stamp",
};

interface ChallengeCardProps {
  challenge: CTFChallenge;
  onSelect: (id: string) => void;
  isSelected: boolean;
}

const ChallengeCard: React.FC<ChallengeCardProps> = ({
  challenge,
  onSelect,
  isSelected,
}) => {
  const { isCTFSolved, getCTFProgress } = useGameStore();
  const solved = isCTFSolved(challenge.id);
  const progress = getCTFProgress(challenge.id);
  const Icon = categoryIcons[challenge.category];

  return (
    <button
      type="button"
      onClick={() => onSelect(challenge.id)}
      aria-current={isSelected ? "true" : undefined}
      className={clsx(
        "group w-full text-left px-4 py-3 flex items-center gap-3 border-l-[3px] transition-colors",
        isSelected
          ? "bg-muted border-l-primary"
          : "border-l-transparent hover:bg-muted/60",
      )}
    >
      <span
        className={clsx(
          "grid h-8 w-8 shrink-0 place-items-center rounded-[var(--radius-xs)]",
          solved ? "bg-foreground text-background" : "border border-border",
        )}
        aria-hidden="true"
      >
        {solved ? (
          <CheckCircle className="w-4 h-4" />
        ) : (
          <Icon className="w-4 h-4 text-muted-foreground" />
        )}
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate font-semibold text-body-sm">
          {challenge.title}
        </span>
        <span className="mt-0.5 flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.1em]">
          <span className={difficultyColors[challenge.difficulty || "easy"]}>
            {challenge.difficulty || "easy"}
          </span>
          <span className="text-muted-foreground">
            {getCategoryLabel(challenge.category)}
          </span>
          {solved && <span className="text-muted-foreground">· Solved</span>}
        </span>
      </span>
      <span className="font-mono text-body-sm tabular-nums text-muted-foreground group-hover:text-foreground">
        {solved ? progress?.pointsEarned : challenge.points}
        <span className="text-[11px]"> pts</span>
      </span>
    </button>
  );
};

interface ChallengeDetailProps {
  challenge: CTFChallenge;
}

// Terminal commands for CTF challenges
const createCTFTerminalCommands = (
  challenge: CTFChallenge,
  onFlagSubmit: (flag: string) => void,
): TerminalCommand[] => [
  {
    name: "submit",
    description: "Submit a flag",
    handler: (args, terminal) => {
      const flag = args.join(" ");
      if (!flag) {
        terminal.writeLine("\r\n\x1b[1;31mUsage: submit FLAG{...}\x1b[0m");
        terminal.writeLine("");
        return;
      }
      terminal.writeLine(`\r\n\x1b[1;33mSubmitting flag...\x1b[0m`);
      onFlagSubmit(flag);
    },
  },
  {
    name: "info",
    description: "Show challenge info",
    handler: (_, terminal) => {
      terminal.writeLine("\r\n\x1b[1;36m=== Challenge Info ===\x1b[0m");
      terminal.writeLine(`\x1b[1;33mTitle:\x1b[0m ${challenge.title}`);
      terminal.writeLine(
        `\x1b[1;33mCategory:\x1b[0m ${getCategoryLabel(challenge.category)}`,
      );
      terminal.writeLine(`\x1b[1;33mPoints:\x1b[0m ${challenge.points}`);
      terminal.writeLine(
        `\x1b[1;33mDifficulty:\x1b[0m ${challenge.difficulty || "easy"}`,
      );
      terminal.writeLine("");
    },
  },
  {
    name: "decode",
    description: "Decode base64 string",
    handler: (args, terminal) => {
      const input = args.join(" ");
      if (!input) {
        terminal.writeLine(
          "\r\n\x1b[1;31mUsage: decode <base64_string>\x1b[0m",
        );
        terminal.writeLine("");
        return;
      }
      try {
        const decoded = atob(input);
        terminal.writeLine(`\r\n\x1b[1;32mDecoded:\x1b[0m ${decoded}`);
      } catch {
        terminal.writeLine("\r\n\x1b[1;31mError: Invalid base64 string\x1b[0m");
      }
      terminal.writeLine("");
    },
  },
  {
    name: "encode",
    description: "Encode string to base64",
    handler: (args, terminal) => {
      const input = args.join(" ");
      if (!input) {
        terminal.writeLine("\r\n\x1b[1;31mUsage: encode <string>\x1b[0m");
        terminal.writeLine("");
        return;
      }
      const encoded = btoa(input);
      terminal.writeLine(`\r\n\x1b[1;32mEncoded:\x1b[0m ${encoded}`);
      terminal.writeLine("");
    },
  },
  {
    name: "hex",
    description: "Convert hex to ASCII",
    handler: (args, terminal) => {
      const input = args
        .join("")
        .replace(/\\x/g, "")
        .replace(/0x/g, "")
        .replace(/\s/g, "");
      if (!input) {
        terminal.writeLine("\r\n\x1b[1;31mUsage: hex <hex_string>\x1b[0m");
        terminal.writeLine("\x1b[0;37mExample: hex 464c4147\x1b[0m");
        terminal.writeLine("");
        return;
      }
      try {
        let result = "";
        for (let i = 0; i < input.length; i += 2) {
          result += String.fromCharCode(parseInt(input.substr(i, 2), 16));
        }
        terminal.writeLine(`\r\n\x1b[1;32mASCII:\x1b[0m ${result}`);
      } catch {
        terminal.writeLine("\r\n\x1b[1;31mError: Invalid hex string\x1b[0m");
      }
      terminal.writeLine("");
    },
  },
  {
    name: "rot13",
    description: "Apply ROT13 cipher",
    handler: (args, terminal) => {
      const input = args.join(" ");
      if (!input) {
        terminal.writeLine("\r\n\x1b[1;31mUsage: rot13 <text>\x1b[0m");
        terminal.writeLine("");
        return;
      }
      const result = input.replace(/[a-zA-Z]/g, (c) => {
        const base = c <= "Z" ? 65 : 97;
        return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
      });
      terminal.writeLine(`\r\n\x1b[1;32mResult:\x1b[0m ${result}`);
      terminal.writeLine("");
    },
  },
  {
    name: "caesar",
    description: "Caesar cipher shift",
    handler: (args, terminal) => {
      if (args.length < 2) {
        terminal.writeLine("\r\n\x1b[1;31mUsage: caesar <shift> <text>\x1b[0m");
        terminal.writeLine("\x1b[0;37mExample: caesar -3 IODJ\x1b[0m");
        terminal.writeLine("");
        return;
      }
      const shift = parseInt(args[0], 10);
      const input = args.slice(1).join(" ");
      if (isNaN(shift)) {
        terminal.writeLine(
          "\r\n\x1b[1;31mError: Shift must be a number\x1b[0m",
        );
        terminal.writeLine("");
        return;
      }
      const result = input.replace(/[a-zA-Z]/g, (c) => {
        const base = c <= "Z" ? 65 : 97;
        return String.fromCharCode(
          ((c.charCodeAt(0) - base + shift + 26) % 26) + base,
        );
      });
      terminal.writeLine(`\r\n\x1b[1;32mShifted by ${shift}:\x1b[0m ${result}`);
      terminal.writeLine("");
    },
  },
  {
    name: "xor",
    description: "XOR string with key",
    handler: (args, terminal) => {
      if (args.length < 2) {
        terminal.writeLine("\r\n\x1b[1;31mUsage: xor <key> <hex_data>\x1b[0m");
        terminal.writeLine("");
        return;
      }
      const key = args[0];
      const hexData = args.slice(1).join("").replace(/\s/g, "");
      try {
        let result = "";
        for (let i = 0; i < hexData.length; i += 2) {
          const byte = parseInt(hexData.substr(i, 2), 16);
          const keyChar = key.charCodeAt((i / 2) % key.length);
          result += String.fromCharCode(byte ^ keyChar);
        }
        terminal.writeLine(`\r\n\x1b[1;32mXOR Result:\x1b[0m ${result}`);
      } catch {
        terminal.writeLine("\r\n\x1b[1;31mError: Invalid input\x1b[0m");
      }
      terminal.writeLine("");
    },
  },
  {
    name: "tools",
    description: "List available CTF tools",
    handler: (_, terminal) => {
      terminal.writeLine("\r\n\x1b[1;36m=== CTF Tools ===\x1b[0m");
      terminal.writeLine("  \x1b[1;33msubmit\x1b[0m   - Submit a flag");
      terminal.writeLine("  \x1b[1;33minfo\x1b[0m     - Show challenge info");
      terminal.writeLine("  \x1b[1;33mdecode\x1b[0m   - Decode base64");
      terminal.writeLine("  \x1b[1;33mencode\x1b[0m   - Encode to base64");
      terminal.writeLine("  \x1b[1;33mhex\x1b[0m      - Convert hex to ASCII");
      terminal.writeLine("  \x1b[1;33mrot13\x1b[0m    - Apply ROT13 cipher");
      terminal.writeLine("  \x1b[1;33mcaesar\x1b[0m   - Caesar cipher shift");
      terminal.writeLine("  \x1b[1;33mxor\x1b[0m      - XOR with key");
      terminal.writeLine("");
    },
  },
];

const ChallengeDetail: React.FC<ChallengeDetailProps> = ({ challenge }) => {
  const { submitFlag, revealHint, getCTFProgress, isCTFSolved } =
    useGameStore();
  const [flagInput, setFlagInput] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showTerminal, setShowTerminal] = useState(false);
  const [confirmHintId, setConfirmHintId] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{
    type: "success" | "error" | "info";
    message: string;
  } | null>(null);

  const solved = isCTFSolved(challenge.id);
  const progress = getCTFProgress(challenge.id);
  const Icon = categoryIcons[challenge.category];

  // Stabilize hintsRevealed so it doesn't create a new array reference each render
  const hintsRevealed = useMemo(
    () => progress?.hintsRevealed || [],
    [progress?.hintsRevealed],
  );

  // Calculate potential points after hint deductions
  const potentialPoints = useMemo(() => {
    const hintCost = challenge.hints
      .filter((h) => hintsRevealed.includes(h.id))
      .reduce((sum, h) => sum + h.cost, 0);
    return Math.max(0, challenge.points - hintCost);
  }, [challenge, hintsRevealed]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!flagInput.trim() || isSubmitting || solved) return;

    const normalizedFlag = normalizeFlag(flagInput);

    // Validate format first
    if (!isValidFlagFormat(normalizedFlag)) {
      setFeedback({
        type: "info",
        message: "Flag should be in format: FLAG{...}",
      });
      return;
    }

    setIsSubmitting(true);
    setFeedback(null);

    try {
      const result = await submitFlag(challenge.id, normalizedFlag, {
        points: challenge.points,
        hints: challenge.hints.map((h) => ({ id: h.id, cost: h.cost })),
        flag: challenge.flag,
      });

      if (result.correct) {
        setFeedback({
          type: "success",
          message: `Correct! You earned ${result.pointsEarned} points!`,
        });
        setFlagInput("");
        // Trigger confetti
        if (!prefersReducedMotion()) {
          import("canvas-confetti")
            .then((confetti) => {
              confetti.default({
                particleCount: 100,
                spread: 70,
                origin: { y: 0.6 },
              });
            })
            .catch(() => {});
        }
      } else {
        setFeedback({
          type: "error",
          message: "Incorrect flag. Try again!",
        });
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRevealHint = (hintId: string) => {
    if (solved || hintsRevealed.includes(hintId)) return;
    revealHint(challenge.id, hintId);
    setConfirmHintId(null);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.18 }}
      className="flex flex-col max-w-3xl"
    >
      {/* Header */}
      <header className="border-b border-border pb-6 mb-6">
        <p className="range-readout mb-3 flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="range-dot" aria-hidden="true" />
          <span className="flex items-center gap-1.5">
            <Icon className="w-3.5 h-3.5" aria-hidden="true" />
            {getCategoryLabel(challenge.category)}
          </span>
          <span aria-hidden="true">·</span>
          <span className={difficultyColors[challenge.difficulty || "easy"]}>
            {challenge.difficulty || "easy"}
          </span>
          {challenge.author && (
            <>
              <span aria-hidden="true">·</span>
              <span>by {challenge.author}</span>
            </>
          )}
        </p>
        <div className="flex flex-wrap items-end justify-between gap-4">
          <h2 className="text-h1">{challenge.title}</h2>
          <div className="text-right">
            <p className="font-display text-h2 font-extrabold [font-stretch:75%] tabular-nums leading-none">
              {solved ? progress?.pointsEarned : potentialPoints}
              <span className="ml-1 font-mono text-caption font-normal text-muted-foreground">
                pts
              </span>
            </p>
            {!solved && potentialPoints < challenge.points && (
              <p className="mt-1 font-mono text-[11px] uppercase tracking-[0.1em] text-warning">
                -{challenge.points - potentialPoints} from hints
              </p>
            )}
          </div>
        </div>
      </header>

      {/* Solved banner */}
      {solved && (
        <div className="mb-6 border-l-[3px] border-accent pl-4 py-1 flex items-center gap-3">
          <Trophy className="w-5 h-5 text-accent" aria-hidden="true" />
          <div>
            <p className="font-semibold text-accent">Challenge Completed!</p>
            <p className="text-body-sm text-muted-foreground">
              Solved on{" "}
              {progress?.solvedAt
                ? new Date(progress.solvedAt).toLocaleDateString()
                : "N/A"}
              {progress?.attempts &&
                ` in ${progress.attempts} attempt${progress.attempts > 1 ? "s" : ""}`}
            </p>
          </div>
        </div>
      )}

      {/* Description */}
      <section className="mb-8">
        <h3 className="ui-label mb-3">Description</h3>
        <div className="brief-prose max-w-[68ch]">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>
            {challenge.description}
          </ReactMarkdown>
        </div>
        {challenge.tags && challenge.tags.length > 0 && (
          <ul className="flex flex-wrap gap-2 mt-4" aria-label="Tags">
            {challenge.tags.map((tag) => (
              <li
                key={tag}
                className="font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground border border-border rounded-[var(--radius-xs)] px-2 py-0.5"
              >
                {tag}
              </li>
            ))}
          </ul>
        )}
      </section>

      {/* Flag submission sits high: it is the one action that matters */}
      <section className="mb-8 ui-card ui-card-md" aria-label="Submit flag">
        <form onSubmit={handleSubmit}>
          <label htmlFor="ctf-flag-input" className="ui-label mb-2 block">
            Flag
          </label>
          <div className="flex flex-col gap-3 sm:flex-row">
            <div className="flex-1 relative">
              <Flag
                className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground"
                aria-hidden="true"
              />
              <Input
                id="ctf-flag-input"
                type="text"
                autoComplete="off"
                spellCheck={false}
                placeholder="FLAG{...}"
                value={flagInput}
                onChange={(e) => setFlagInput(e.target.value)}
                disabled={solved || isSubmitting}
                className="pl-10 font-mono"
                aria-describedby="ctf-flag-status"
              />
            </div>
            <Button
              type="submit"
              disabled={solved || isSubmitting || !flagInput.trim()}
              variant={solved ? "outline" : "signal"}
              aria-label={solved ? "Challenge solved" : "Submit flag"}
            >
              {isSubmitting ? "Checking..." : solved ? "Solved" : "Submit flag"}
            </Button>
          </div>
        </form>
        <div id="ctf-flag-status" aria-live="polite">
          <AnimatePresence mode="wait">
            {feedback && (
              <motion.p
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                className={clsx(
                  "mt-3 pl-3 border-l-[3px] flex items-center gap-2 text-body-sm",
                  feedback.type === "success" && "border-accent text-accent",
                  feedback.type === "error" &&
                    "border-destructive text-destructive",
                  feedback.type === "info" && "border-primary text-foreground",
                )}
              >
                {feedback.type === "success" ? (
                  <CheckCircle
                    className="w-4 h-4 shrink-0"
                    aria-hidden="true"
                  />
                ) : (
                  <AlertCircle
                    className="w-4 h-4 shrink-0"
                    aria-hidden="true"
                  />
                )}
                {feedback.message}
              </motion.p>
            )}
          </AnimatePresence>
          {progress?.attempts && !solved ? (
            <p className="mt-2 font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground">
              {progress.attempts} attempt{progress.attempts > 1 ? "s" : ""} made
            </p>
          ) : null}
        </div>
      </section>

      {challenge.category === "web" && (
        <div className="mb-8">
          <LiveLabTargets
            tags={[challenge.category, ...(challenge.tags ?? [])]}
          />
        </div>
      )}

      {/* Hints */}
      {challenge.hints.length > 0 && (
        <section className="mb-8">
          <h3 className="ui-label mb-3 flex items-center gap-2">
            <Lightbulb className="w-3.5 h-3.5" aria-hidden="true" />
            Hints ({hintsRevealed.length}/{challenge.hints.length})
          </h3>
          <ol className="divide-y divide-border border-y border-border">
            {challenge.hints.map((hint, idx) => {
              const isRevealed = hintsRevealed.includes(hint.id);
              const isConfirming = confirmHintId === hint.id;
              return (
                <li key={hint.id} className="py-3">
                  {isRevealed ? (
                    <div className="border-l-2 border-warning pl-3">
                      <p className="font-mono text-[11px] uppercase tracking-[0.1em] text-warning mb-1">
                        Hint {idx + 1} (-{hint.cost} pts)
                      </p>
                      <p className="text-body-sm">{hint.text}</p>
                    </div>
                  ) : isConfirming ? (
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <p className="text-body-sm">
                        Reveal hint {idx + 1}? It costs{" "}
                        <span className="font-mono text-destructive">
                          {hint.cost} pts
                        </span>
                        .
                      </p>
                      <div className="flex gap-2">
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          onClick={() => setConfirmHintId(null)}
                        >
                          Cancel
                        </Button>
                        <Button
                          type="button"
                          size="sm"
                          variant="primary"
                          onClick={() => handleRevealHint(hint.id)}
                        >
                          Reveal hint
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <button
                      type="button"
                      onClick={() => setConfirmHintId(hint.id)}
                      disabled={solved}
                      className="w-full flex items-center justify-between text-body-sm text-muted-foreground hover:text-foreground transition-colors disabled:opacity-50"
                    >
                      <span className="flex items-center gap-2">
                        <Lock className="w-4 h-4" aria-hidden="true" />
                        Hint {idx + 1}
                      </span>
                      <span className="font-mono text-[12px]">
                        -{hint.cost} pts
                      </span>
                    </button>
                  )}
                </li>
              );
            })}
          </ol>
        </section>
      )}

      {/* Interactive Terminal */}
      <div className="mb-8">
        <button
          onClick={() => setShowTerminal(!showTerminal)}
          type="button"
          aria-expanded={showTerminal}
          className="w-full flex items-center justify-between gap-3 h-12 px-4 rounded-[var(--radius-sm)] border border-border hover:border-foreground transition-colors"
        >
          <span className="flex items-center gap-2 text-body-sm font-semibold">
            <TerminalIcon className="w-4 h-4" aria-hidden="true" />
            CTF Terminal
            <span className="hidden sm:inline font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground font-normal">
              decode · encode · caesar · xor
            </span>
          </span>
          {showTerminal ? (
            <ChevronUp className="w-4 h-4 text-muted-foreground" />
          ) : (
            <ChevronDown className="w-4 h-4 text-muted-foreground" />
          )}
        </button>

        <AnimatePresence>
          {showTerminal && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 300, opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="overflow-hidden mt-2"
            >
              <Terminal
                theme="signal"
                welcomeMessage={`CTF Terminal - ${challenge.title}\nType "tools" for available commands.`}
                prompt="ctf>"
                commands={createCTFTerminalCommands(challenge, (flag) => {
                  setFlagInput(flag);
                  setFeedback({
                    type: "info",
                    message: "Flag loaded. Click Submit to verify.",
                  });
                })}
                className="h-full"
              />
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
};

const DIFFICULTIES = ["easy", "medium", "hard", "insane"] as const;

export const CTFChallenges: React.FC = () => {
  const { ctfTotalPoints, ctfProgress } = useGameStore();
  // Selection lives in the URL so the command palette and shared links can
  // open a specific challenge, and the browser back button closes it.
  const [searchParams, setSearchParams] = useSearchParams();
  const requested = searchParams.get("challenge");
  const selectedChallenge =
    requested && getChallengeById(requested) ? requested : null;
  const setSelectedChallenge = (id: string | null) => {
    const next = new URLSearchParams(searchParams);
    if (id) next.set("challenge", id);
    else next.delete("challenge");
    setSearchParams(next);
  };
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<CTFCategory | "all">(
    "all",
  );
  const [difficultyFilter, setDifficultyFilter] = useState<string>("all");
  // In the URL too, so a learner working through the board keeps it on reload.
  const hideSolved = searchParams.get("hide") === "solved";
  const setHideSolved = (on: boolean) => {
    const next = new URLSearchParams(searchParams);
    if (on) next.set("hide", "solved");
    else next.delete("hide");
    setSearchParams(next, { replace: true });
  };

  // Stats
  const solvedCount = Object.values(ctfProgress).filter((p) => p.solved).length;
  const totalChallenges = CTF_CHALLENGES.length;
  const totalPoints = CTF_CHALLENGES.reduce((sum, c) => sum + c.points, 0);
  const categoryCounts = useMemo(() => {
    const counts: Partial<Record<CTFCategory, number>> = {};
    CTF_CHALLENGES.forEach((c) => {
      counts[c.category] = (counts[c.category] ?? 0) + 1;
    });
    return counts;
  }, []);

  // Filter challenges
  const filteredChallenges = useMemo(() => {
    return CTF_CHALLENGES.filter((c) => {
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const matchesSearch =
          c.title.toLowerCase().includes(query) ||
          c.description.toLowerCase().includes(query) ||
          c.tags?.some((t) => t.toLowerCase().includes(query));
        if (!matchesSearch) return false;
      }
      if (categoryFilter !== "all" && c.category !== categoryFilter) {
        return false;
      }
      if (difficultyFilter !== "all" && c.difficulty !== difficultyFilter) {
        return false;
      }
      if (hideSolved && ctfProgress[c.id]?.solved) return false;
      return true;
    });
  }, [searchQuery, categoryFilter, difficultyFilter, hideSolved, ctfProgress]);

  // Group by category for display
  const challengesByCategory = useMemo(() => {
    const grouped: Record<string, CTFChallenge[]> = {};
    filteredChallenges.forEach((c) => {
      if (!grouped[c.category]) {
        grouped[c.category] = [];
      }
      grouped[c.category].push(c);
    });
    return grouped;
  }, [filteredChallenges]);

  const selectedChallengeData = selectedChallenge
    ? getChallengeById(selectedChallenge)
    : null;
  const hasFilters =
    searchQuery !== "" ||
    categoryFilter !== "all" ||
    difficultyFilter !== "all" ||
    hideSolved;

  return (
    <div className="flex flex-col lg:flex-row min-h-[calc(100dvh-64px)]">
      {/* Challenge list */}
      <div
        className={clsx(
          "border-r border-border flex-col lg:w-[380px] lg:shrink-0 lg:sticky lg:top-16 lg:h-[calc(100dvh-64px)]",
          selectedChallenge ? "hidden lg:flex" : "flex w-full",
        )}
      >
        <div className="px-4 pt-6 pb-4 border-b border-border space-y-4">
          <div>
            <p className="range-readout mb-2">
              <span className="range-dot" aria-hidden="true" />
              Capture the flag · {solvedCount}/{totalChallenges} solved
            </p>
            <div className="flex items-baseline justify-between gap-3">
              <h1 className="text-h2 whitespace-nowrap">CTF Challenges</h1>
              <p className="font-mono text-body-sm tabular-nums whitespace-nowrap">
                {ctfTotalPoints.toLocaleString()}
                <span className="text-muted-foreground">
                  /{totalPoints.toLocaleString()} pts
                </span>
              </p>
            </div>
          </div>

          <div className="relative">
            <Search
              className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground"
              aria-hidden="true"
            />
            <Input
              type="search"
              placeholder="Search challenges..."
              aria-label="Search challenges"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
            />
          </div>

          <fieldset
            className="min-w-0 -mx-4 px-4 flex gap-1.5 overflow-x-auto [scrollbar-width:none] [&>*]:shrink-0"
            aria-label="Category"
          >
            <button
              type="button"
              className="filter-pill"
              aria-pressed={categoryFilter === "all"}
              onClick={() => setCategoryFilter("all")}
            >
              All
            </button>
            {CTF_CATEGORIES.filter((cat) => categoryCounts[cat]).map((cat) => (
              <button
                key={cat}
                type="button"
                className="filter-pill"
                aria-pressed={categoryFilter === cat}
                onClick={() =>
                  setCategoryFilter(categoryFilter === cat ? "all" : cat)
                }
              >
                {getCategoryLabel(cat)}
                <span className="opacity-60">{categoryCounts[cat]}</span>
              </button>
            ))}
          </fieldset>
          <fieldset
            className="min-w-0 flex flex-wrap items-center gap-1.5"
            aria-label="Difficulty"
          >
            {DIFFICULTIES.map((d) => (
              <button
                key={d}
                type="button"
                className="filter-pill filter-pill-soft !h-8"
                aria-pressed={difficultyFilter === d}
                onClick={() =>
                  setDifficultyFilter(difficultyFilter === d ? "all" : d)
                }
              >
                {d}
              </button>
            ))}
            {solvedCount > 0 && (
              <button
                type="button"
                className="filter-pill filter-pill-soft !h-8"
                aria-pressed={hideSolved}
                onClick={() => setHideSolved(!hideSolved)}
              >
                Hide solved
              </button>
            )}
            {hasFilters && (
              <button
                type="button"
                className="ml-auto font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground underline underline-offset-4 hover:text-foreground"
                onClick={() => {
                  setSearchQuery("");
                  setCategoryFilter("all");
                  setDifficultyFilter("all");
                  setHideSolved(false);
                }}
              >
                Clear
              </button>
            )}
          </fieldset>
        </div>

        <div className="flex-1 lg:overflow-auto pb-6">
          {Object.entries(challengesByCategory).map(
            ([category, challenges]) => (
              <section
                key={category}
                aria-label={getCategoryLabel(category as CTFCategory)}
              >
                <h2 className="sticky top-0 z-[1] bg-background/95 backdrop-blur px-4 pt-4 pb-2 flex items-center justify-between ui-label">
                  {getCategoryLabel(category as CTFCategory)}
                  <span className="tabular-nums">{challenges.length}</span>
                </h2>
                <div className="divide-y divide-border/70">
                  {challenges.map((challenge) => (
                    <ChallengeCard
                      key={challenge.id}
                      challenge={challenge}
                      onSelect={setSelectedChallenge}
                      isSelected={selectedChallenge === challenge.id}
                    />
                  ))}
                </div>
              </section>
            ),
          )}

          {filteredChallenges.length === 0 && (
            <EmptyState
              className="py-12"
              title="No challenges match"
              description="Adjust search or filters to find a mission."
              icon={<Search className="w-7 h-7" />}
            />
          )}
        </div>
      </div>

      {/* Challenge detail */}
      <div
        className={clsx(
          "flex-1 min-w-0 px-4 py-6 md:px-8 md:py-10",
          selectedChallenge ? "block" : "hidden lg:block",
        )}
      >
        <AnimatePresence mode="wait">
          {selectedChallengeData ? (
            <div className="w-full" key={selectedChallengeData.id}>
              <button
                type="button"
                className="lg:hidden mb-6 inline-flex items-center gap-2 font-mono text-caption uppercase tracking-[0.12em] text-muted-foreground hover:text-foreground"
                onClick={() => setSelectedChallenge(null)}
              >
                ← All challenges
              </button>
              <ChallengeDetail
                key={selectedChallengeData.id}
                challenge={selectedChallengeData}
              />
            </div>
          ) : (
            <motion.div
              key="empty"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="max-w-xl pt-6 space-y-8"
            >
              <div>
                <p className="ui-label mb-3">Target Range: Standby</p>
                <p className="text-h2 font-display font-extrabold [font-stretch:80%] leading-tight">
                  Pick a target from the board. Read the brief, use the
                  terminal, capture the flag.
                </p>
              </div>

              <div className="relative border border-border bg-card p-6 rounded-[var(--radius-md)] overflow-hidden">
                <svg
                  viewBox="0 0 400 160"
                  className="w-full h-auto text-border"
                  aria-hidden="true"
                >
                  <line
                    x1="100"
                    y1="0"
                    x2="100"
                    y2="160"
                    stroke="currentColor"
                    strokeDasharray="3 3"
                  />
                  <line
                    x1="200"
                    y1="0"
                    x2="200"
                    y2="160"
                    stroke="currentColor"
                    strokeDasharray="3 3"
                  />
                  <line
                    x1="300"
                    y1="0"
                    x2="300"
                    y2="160"
                    stroke="currentColor"
                    strokeDasharray="3 3"
                  />
                  <line
                    x1="0"
                    y1="80"
                    x2="400"
                    y2="80"
                    stroke="currentColor"
                    strokeDasharray="3 3"
                  />

                  <circle
                    cx="200"
                    cy="80"
                    r="60"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                  />
                  <circle
                    cx="200"
                    cy="80"
                    r="35"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1"
                  />
                  <circle
                    cx="200"
                    cy="80"
                    r="15"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1"
                  />

                  <line
                    x1="200"
                    y1="10"
                    x2="200"
                    y2="150"
                    stroke="var(--color-foreground)"
                    strokeOpacity="0.4"
                  />
                  <line
                    x1="130"
                    y1="80"
                    x2="270"
                    y2="80"
                    stroke="var(--color-foreground)"
                    strokeOpacity="0.4"
                  />

                  <path
                    d="M200 45 A35 35 0 0 1 235 80 H200 Z"
                    fill="var(--color-signal)"
                    fillOpacity="0.8"
                  />
                  <circle
                    cx="200"
                    cy="80"
                    r="3"
                    fill="var(--color-foreground)"
                  />

                  <text
                    x="16"
                    y="24"
                    className="font-mono text-[9px]"
                    fill="var(--color-muted-foreground)"
                    letterSpacing="1.5"
                  >
                    {"RANGE STATUS // STANDBY"}
                  </text>
                  <text
                    x="384"
                    y="24"
                    textAnchor="end"
                    className="font-mono text-[9px]"
                    fill="var(--color-signal)"
                    letterSpacing="1.5"
                  >
                    {"GRID 0x29 ACTIVE"}
                  </text>
                  <text
                    x="16"
                    y="146"
                    className="font-mono text-[9px]"
                    fill="var(--color-muted-foreground)"
                    letterSpacing="1.5"
                  >
                    {"SYS: ARMED"}
                  </text>
                  <text
                    x="384"
                    y="146"
                    textAnchor="end"
                    className="font-mono text-[9px]"
                    fill="var(--color-muted-foreground)"
                    letterSpacing="1.5"
                  >
                    {"TARGET: UNASSIGNED"}
                  </text>
                </svg>
              </div>

              <dl className="grid grid-cols-3 border-t border-border pt-6">
                {[
                  ["Challenges", totalChallenges],
                  ["Solved", solvedCount],
                  ["Points", ctfTotalPoints],
                ].map(([label, value]) => (
                  <div key={label}>
                    <dt className="ui-label">{label}</dt>
                    <dd className="mt-1 font-display text-display font-extrabold [font-stretch:75%] tabular-nums leading-none">
                      {value}
                    </dd>
                  </div>
                ))}
              </dl>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
};
