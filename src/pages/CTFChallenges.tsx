import React, { useState, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { clsx } from "clsx";
import {
  Flag,
  Lock,
  Search,
  Filter,
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
import { Button, Card, EmptyState, Input } from "../components/ui";
import { LiveLabTargets } from "../components/LiveLabTargets";
import { Terminal, type TerminalCommand } from "../components/Terminal";
import { useGameStore } from "../store/gameStore";
import { CTF_CHALLENGES, getChallengeById } from "../data/ctfChallenges";
import {
  getCategoryColor,
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

const difficultyBgColors = {
  easy: "bg-accent/10 border-accent/30",
  medium: "bg-warning/10 border-warning/30",
  hard: "bg-destructive/10 border-destructive/30",
  insane: "bg-stamp/10 border-stamp/30",
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
  const colorClass = getCategoryColor(challenge.category);

  return (
    <button
      onClick={() => onSelect(challenge.id)}
      className={clsx(
        "w-full text-left p-4 rounded-[var(--radius-sm)] border transition-all duration-200",
        isSelected
          ? "bg-primary/10 border-primary/50"
          : "bg-card/60 border-border/50 hover:border-primary/30 hover:bg-card/80 mission-card",
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <div
            className={clsx(
              "w-10 h-10 rounded-[var(--radius-sm)] flex items-center justify-center",
              solved ? "bg-accent/20" : "bg-muted/60",
            )}
          >
            {solved ? (
              <CheckCircle className="w-5 h-5 text-accent" />
            ) : (
              <Icon className={clsx("w-5 h-5", colorClass)} />
            )}
          </div>
          <div>
            <h3
              className={clsx(
                "font-semibold text-sm",
                solved
                  ? "text-muted-foreground line-through"
                  : "text-foreground",
              )}
            >
              {challenge.title}
            </h3>
            <div className="flex items-center gap-2 mt-1">
              <span
                className={clsx(
                  "text-xs px-2 py-0.5 rounded-full border",
                  difficultyBgColors[challenge.difficulty || "easy"],
                  difficultyColors[challenge.difficulty || "easy"],
                )}
              >
                {challenge.difficulty || "easy"}
              </span>
              <span className="text-xs text-muted-foreground">
                {getCategoryLabel(challenge.category)}
              </span>
            </div>
          </div>
        </div>
        <div className="text-right">
          <div
            className={clsx(
              "font-mono font-bold",
              solved ? "text-accent" : "text-primary",
            )}
          >
            {solved ? progress?.pointsEarned : challenge.points} pts
          </div>
          {challenge.solveCount !== undefined && (
            <div className="text-xs text-muted-foreground mt-1">
              {challenge.solveCount} solves
            </div>
          )}
        </div>
      </div>
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
  const [feedback, setFeedback] = useState<{
    type: "success" | "error" | "info";
    message: string;
  } | null>(null);

  const solved = isCTFSolved(challenge.id);
  const progress = getCTFProgress(challenge.id);
  const Icon = categoryIcons[challenge.category];
  const colorClass = getCategoryColor(challenge.category);

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
        import("canvas-confetti")
          .then((confetti) => {
            confetti.default({
              particleCount: 100,
              spread: 70,
              origin: { y: 0.6 },
            });
          })
          .catch(() => {});
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

    const hint = challenge.hints.find((h) => h.id === hintId);
    if (
      hint &&
      window.confirm(
        `Revealing this hint will cost ${hint.cost} points. Continue?`,
      )
    ) {
      revealHint(challenge.id, hintId);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, x: 20 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 20 }}
      className="h-full flex flex-col"
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div
            className={clsx(
              "w-12 h-12 rounded-[var(--radius-sm)] flex items-center justify-center",
              solved ? "bg-accent/20" : "bg-muted/60",
            )}
          >
            {solved ? (
              <CheckCircle className="w-6 h-6 text-accent" />
            ) : (
              <Icon className={clsx("w-6 h-6", colorClass)} />
            )}
          </div>
          <div>
            <h2 className="text-h3">{challenge.title}</h2>
            <div className="flex items-center gap-2 mt-1">
              <span
                className={clsx(
                  "text-xs px-2 py-0.5 rounded-full border",
                  difficultyBgColors[challenge.difficulty || "easy"],
                  difficultyColors[challenge.difficulty || "easy"],
                )}
              >
                {challenge.difficulty || "easy"}
              </span>
              <span className={clsx("text-sm", colorClass)}>
                {getCategoryLabel(challenge.category)}
              </span>
              {challenge.author && (
                <span className="text-xs text-muted-foreground">
                  by {challenge.author}
                </span>
              )}
            </div>
          </div>
        </div>
        <div className="text-right">
          <div
            className={clsx(
              "text-h2 font-mono font-bold",
              solved ? "text-accent" : "text-primary",
            )}
          >
            {solved ? progress?.pointsEarned : potentialPoints}
            <span className="text-sm font-normal text-muted-foreground ml-1">
              pts
            </span>
          </div>
          {!solved && potentialPoints < challenge.points && (
            <div className="text-xs text-warning">
              -{challenge.points - potentialPoints} from hints
            </div>
          )}
        </div>
      </div>

      {/* Solved banner */}
      {solved && (
        <div className="mb-6 p-4 rounded-[var(--radius-sm)] bg-accent/10 border border-accent/30 flex items-center gap-3">
          <Trophy className="w-5 h-5 text-accent" />
          <div>
            <div className="font-semibold text-accent">
              Challenge Completed!
            </div>
            <div className="text-sm text-muted-foreground">
              Solved on{" "}
              {progress?.solvedAt
                ? new Date(progress.solvedAt).toLocaleDateString()
                : "N/A"}
              {progress?.attempts &&
                ` in ${progress.attempts} attempt${progress.attempts > 1 ? "s" : ""}`}
            </div>
          </div>
        </div>
      )}

      {/* Description */}
      <Card className="mb-6 flex-shrink-0">
        <h3 className="ui-label mb-3">Description</h3>
        <div className="prose prose-invert prose-sm max-w-none">
          <pre className="whitespace-pre-wrap text-sm text-foreground/90 font-sans leading-relaxed">
            {challenge.description}
          </pre>
        </div>
        {challenge.tags && challenge.tags.length > 0 && (
          <div className="flex flex-wrap gap-2 mt-4 pt-4 border-t border-border/50">
            {challenge.tags.map((tag) => (
              <span
                key={tag}
                className="text-xs px-2 py-1 rounded bg-muted/50 text-muted-foreground"
              >
                #{tag}
              </span>
            ))}
          </div>
        )}
      </Card>

      {challenge.category === "web" && (
        <div className="mb-6">
          <LiveLabTargets
            tags={[challenge.category, ...(challenge.tags ?? [])]}
          />
        </div>
      )}

      {/* Hints */}
      {challenge.hints.length > 0 && (
        <Card className="mb-6 flex-shrink-0">
          <h3 className="ui-label mb-3 flex items-center gap-2">
            <Lightbulb className="w-4 h-4" />
            Hints ({hintsRevealed.length}/{challenge.hints.length})
          </h3>
          <div className="space-y-3">
            {challenge.hints.map((hint, idx) => {
              const isRevealed = hintsRevealed.includes(hint.id);
              return (
                <div
                  key={hint.id}
                  className={clsx(
                    "p-3 rounded-[var(--radius-sm)] border",
                    isRevealed
                      ? "bg-warning/5 border-warning/30"
                      : "bg-muted/30 border-border/50",
                  )}
                >
                  {isRevealed ? (
                    <div>
                      <div className="text-xs text-warning mb-1">
                        Hint {idx + 1} (-{hint.cost} pts)
                      </div>
                      <p className="text-sm">{hint.text}</p>
                    </div>
                  ) : (
                    <button
                      onClick={() => handleRevealHint(hint.id)}
                      disabled={solved}
                      className="w-full flex items-center justify-between text-sm text-muted-foreground hover:text-foreground transition-colors disabled:opacity-50"
                    >
                      <span className="flex items-center gap-2">
                        <Lock className="w-4 h-4" />
                        Hint {idx + 1}
                      </span>
                      <span className="text-destructive font-mono">
                        -{hint.cost} pts
                      </span>
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {/* Interactive Terminal */}
      <div className="mb-6">
        <button
          onClick={() => setShowTerminal(!showTerminal)}
          className={clsx(
            "w-full flex items-center justify-between p-3 rounded-[var(--radius-sm)] border transition-all duration-200",
            showTerminal
              ? "bg-primary/10 border-primary/50"
              : "bg-muted/30 border-border/50 hover:border-primary/30",
          )}
        >
          <span className="flex items-center gap-2 text-sm font-medium">
            <TerminalIcon className="w-4 h-4 text-primary" />
            CTF Terminal
            <span className="text-xs text-muted-foreground font-normal">
              (decode, encode, caesar, xor, and more)
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
                theme="matrix"
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

      {/* Flag submission */}
      <div className="mt-auto">
        <form onSubmit={handleSubmit}>
          <div className="flex gap-3">
            <div className="flex-1 relative">
              <Flag className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                type="text"
                placeholder="FLAG{...}"
                value={flagInput}
                onChange={(e) => setFlagInput(e.target.value)}
                disabled={solved || isSubmitting}
                className="pl-10 font-mono"
              />
            </div>
            <Button
              type="submit"
              disabled={solved || isSubmitting || !flagInput.trim()}
              variant={solved ? "accent" : "primary"}
            >
              {isSubmitting ? "Checking..." : solved ? "Solved" : "Submit"}
            </Button>
          </div>
        </form>

        {/* Feedback */}
        <AnimatePresence mode="wait">
          {feedback && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className={clsx(
                "mt-3 p-3 rounded-[var(--radius-sm)] flex items-center gap-2 text-sm",
                feedback.type === "success" &&
                  "bg-accent/10 border border-accent/30 text-accent",
                feedback.type === "error" &&
                  "bg-destructive/10 border border-destructive/30 text-destructive",
                feedback.type === "info" &&
                  "bg-primary/10 border border-primary/30 text-primary",
              )}
            >
              {feedback.type === "success" && (
                <CheckCircle className="w-4 h-4" />
              )}
              {feedback.type === "error" && <AlertCircle className="w-4 h-4" />}
              {feedback.type === "info" && <AlertCircle className="w-4 h-4" />}
              {feedback.message}
            </motion.div>
          )}
        </AnimatePresence>

        {/* Attempt counter */}
        {progress?.attempts && !solved && (
          <div className="mt-2 text-xs text-muted-foreground">
            {progress.attempts} attempt{progress.attempts > 1 ? "s" : ""} made
          </div>
        )}
      </div>
    </motion.div>
  );
};

export const CTFChallenges: React.FC = () => {
  const { ctfTotalPoints, ctfProgress } = useGameStore();
  const [selectedChallenge, setSelectedChallenge] = useState<string | null>(
    null,
  );
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<CTFCategory | "all">(
    "all",
  );
  const [difficultyFilter, setDifficultyFilter] = useState<string>("all");
  const [showFilters, setShowFilters] = useState(false);

  // Stats
  const solvedCount = Object.values(ctfProgress).filter((p) => p.solved).length;
  const totalChallenges = CTF_CHALLENGES.length;

  // Filter challenges
  const filteredChallenges = useMemo(() => {
    return CTF_CHALLENGES.filter((c) => {
      // Search filter
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const matchesSearch =
          c.title.toLowerCase().includes(query) ||
          c.description.toLowerCase().includes(query) ||
          c.tags?.some((t) => t.toLowerCase().includes(query));
        if (!matchesSearch) return false;
      }

      // Category filter
      if (categoryFilter !== "all" && c.category !== categoryFilter) {
        return false;
      }

      // Difficulty filter
      if (difficultyFilter !== "all" && c.difficulty !== difficultyFilter) {
        return false;
      }

      return true;
    });
  }, [searchQuery, categoryFilter, difficultyFilter]);

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

  return (
    <div className="h-[calc(100vh-88px)] -mx-4 -my-4 md:-mx-6 md:-my-6 flex flex-col lg:flex-row">
      {/* Sidebar - Challenge list */}
      <div
        className={clsx(
          "border-r border-border/70 flex flex-col bg-card/50",
          selectedChallenge ? "hidden lg:flex lg:w-96" : "flex w-full lg:w-96",
        )}
      >
        {/* Header with stats */}
        <div className="p-4 border-b border-border/70">
          <div className="flex items-center justify-between mb-4">
            <h1 className="text-h3 flex items-center gap-2">
              <Flag className="w-5 h-5 text-primary" />
              CTF Challenges
            </h1>
            <div className="text-right">
              <div className="font-mono font-bold text-primary">
                {ctfTotalPoints} pts
              </div>
              <div className="text-xs text-muted-foreground">
                {solvedCount}/{totalChallenges} solved
              </div>
            </div>
          </div>

          {/* Search */}
          <div className="relative mb-3">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              type="text"
              placeholder="Search challenges..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
            />
          </div>

          {/* Filter toggle */}
          <button
            onClick={() => setShowFilters(!showFilters)}
            className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
          >
            <Filter className="w-4 h-4" />
            Filters
            <ChevronDown
              className={clsx(
                "w-4 h-4 transition-transform",
                showFilters && "rotate-180",
              )}
            />
          </button>

          {/* Filters */}
          <AnimatePresence>
            {showFilters && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                className="overflow-hidden"
              >
                <div className="pt-3 space-y-3">
                  {/* Category filter */}
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">
                      Category
                    </label>
                    <select
                      value={categoryFilter}
                      onChange={(e) =>
                        setCategoryFilter(e.target.value as CTFCategory | "all")
                      }
                      className="ui-input w-full"
                    >
                      <option value="all">All Categories</option>
                      {CTF_CATEGORIES.map((cat) => (
                        <option key={cat} value={cat}>
                          {getCategoryLabel(cat)}
                        </option>
                      ))}
                    </select>
                  </div>

                  {/* Difficulty filter */}
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">
                      Difficulty
                    </label>
                    <select
                      value={difficultyFilter}
                      onChange={(e) => setDifficultyFilter(e.target.value)}
                      className="ui-input w-full"
                    >
                      <option value="all">All Difficulties</option>
                      <option value="easy">Easy</option>
                      <option value="medium">Medium</option>
                      <option value="hard">Hard</option>
                      <option value="insane">Insane</option>
                    </select>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Challenge list */}
        <div className="flex-1 overflow-auto p-4 space-y-6">
          {Object.entries(challengesByCategory).map(
            ([category, challenges]) => (
              <div key={category}>
                <div className="flex items-center gap-2 mb-3">
                  {React.createElement(categoryIcons[category as CTFCategory], {
                    className: clsx(
                      "w-4 h-4",
                      getCategoryColor(category as CTFCategory),
                    ),
                  })}
                  <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wide">
                    {getCategoryLabel(category as CTFCategory)}
                  </h3>
                  <span className="text-xs text-muted-foreground">
                    ({challenges.length})
                  </span>
                </div>
                <div className="space-y-2">
                  {challenges.map((challenge) => (
                    <ChallengeCard
                      key={challenge.id}
                      challenge={challenge}
                      onSelect={setSelectedChallenge}
                      isSelected={selectedChallenge === challenge.id}
                    />
                  ))}
                </div>
              </div>
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

      {/* Main content - Challenge detail */}
      <div
        className={clsx(
          "flex-1 p-4 md:p-6 overflow-auto ops-grid-bg",
          selectedChallenge ? "flex" : "hidden lg:flex",
        )}
      >
        <AnimatePresence mode="wait">
          {selectedChallengeData ? (
            <div className="w-full">
              <button
                type="button"
                className="lg:hidden mb-4 text-body-sm text-primary hover:underline"
                onClick={() => setSelectedChallenge(null)}
              >
                ← Back to challenges
              </button>
              <ChallengeDetail
                key={selectedChallengeData.id}
                challenge={selectedChallengeData}
              />
            </div>
          ) : (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="h-full w-full flex flex-col items-center justify-center text-center"
            >
              <EmptyState
                title="Select a Challenge"
                description="Choose a challenge from the list to view its description, hints, and submit your flag."
                icon={<Flag className="w-8 h-8 text-primary" />}
              />
              <div className="mt-2 grid grid-cols-3 gap-6 text-center">
                <div>
                  <div className="text-h1 font-mono text-primary">
                    {totalChallenges}
                  </div>
                  <div className="text-sm text-muted-foreground">
                    Challenges
                  </div>
                </div>
                <div>
                  <div className="text-h1 font-mono text-accent">
                    {solvedCount}
                  </div>
                  <div className="text-sm text-muted-foreground">Solved</div>
                </div>
                <div>
                  <div className="text-h1 font-mono text-warning">
                    {ctfTotalPoints}
                  </div>
                  <div className="text-sm text-muted-foreground">Points</div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
};
