/**
 * CTF (Capture The Flag) Challenge Utilities
 *
 * Provides types and utilities for creating and validating CTF challenges
 * within the security trainer platform.
 */

export type CTFCategory =
  "web" | "crypto" | "forensics" | "pwn" | "misc" | "reverse" | "osint";

export interface CTFHint {
  id: string;
  text: string;
  cost: number; // Points deducted when hint is revealed
}

export interface CTFChallenge {
  id: string;
  title: string;
  category: CTFCategory;
  points: number;
  description: string;
  hints: CTFHint[];
  flag: string; // Hashed flag for secure storage
  author?: string;
  tags?: string[];
  solveCount?: number;
  difficulty?: "easy" | "medium" | "hard" | "insane";
}

export interface CTFSubmission {
  challengeId: string;
  userId: string;
  timestamp: string;
  correct: boolean;
  hintsUsed: string[]; // IDs of hints revealed
  pointsEarned: number;
}

export interface CTFProgress {
  challengeId: string;
  solved: boolean;
  hintsRevealed: string[];
  attempts: number;
  solvedAt?: string;
  pointsEarned?: number;
}

// Default flag format prefix
const DEFAULT_FLAG_PREFIX = "FLAG";

// Flag format regex pattern - matches FLAG{...} format
const FLAG_FORMAT_PATTERN = /^([A-Z]+)\{(.+)\}$/;

/**
 * Hashes a flag string using SHA-256 for secure storage.
 * Uses the Web Crypto API for browser compatibility.
 */
export async function hashFlag(flag: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(flag);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Synchronous hash function using a simple hash algorithm.
 * Use hashFlag() for production security; this is for quick comparisons.
 */
export function hashFlagSync(flag: string): string {
  let hash = 0;
  for (let i = 0; i < flag.length; i++) {
    const char = flag.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  // Convert to hex and pad
  const hexHash = Math.abs(hash).toString(16).padStart(8, "0");
  // Add additional entropy by including length and checksum
  const checksum =
    flag.split("").reduce((sum, c) => sum + c.charCodeAt(0), 0) % 65536;
  return `${hexHash}${checksum.toString(16).padStart(4, "0")}${flag.length.toString(16).padStart(4, "0")}`;
}

/**
 * Validates a user-submitted flag against the stored hashed flag.
 * Returns true if the flag is correct.
 */
export async function validateFlag(
  input: string,
  hashedFlag: string,
): Promise<boolean> {
  const inputHash = await hashFlag(input);
  return inputHash === hashedFlag;
}

/**
 * Synchronous flag validation using the simple hash.
 */
export function validateFlagSync(input: string, hashedFlag: string): boolean {
  return hashFlagSync(input) === hashedFlag;
}

/**
 * Formats a flag string with the standard CTF format.
 * @example formatFlag('d3bug_1s_fun') => 'FLAG{d3bug_1s_fun}'
 */
export function formatFlag(
  flag: string,
  prefix: string = DEFAULT_FLAG_PREFIX,
): string {
  return `${prefix}{${flag}}`;
}

/**
 * Extracts the inner content from a formatted flag.
 * @example extractFlagContent('FLAG{secret}') => 'secret'
 * @example extractFlagContent('CTF{test}', 'CTF') => 'test'
 */
export function extractFlagContent(
  formattedFlag: string,
  expectedPrefix?: string,
): string | null {
  const match = formattedFlag.match(FLAG_FORMAT_PATTERN);
  if (!match) return null;

  const [, prefix, content] = match;
  if (expectedPrefix && prefix !== expectedPrefix) return null;

  return content;
}

/**
 * Validates the format of a flag string.
 * Checks if it matches the expected FLAG{...} pattern.
 */
export function isValidFlagFormat(
  flag: string,
  expectedPrefix: string = DEFAULT_FLAG_PREFIX,
): boolean {
  const match = flag.match(FLAG_FORMAT_PATTERN);
  if (!match) return false;

  const [, prefix, content] = match;
  return prefix === expectedPrefix && content.length > 0;
}

/**
 * Normalizes a flag for comparison (trims whitespace, handles common mistakes).
 */
export function normalizeFlag(flag: string): string {
  return flag
    .trim()
    .replace(/\s+/g, "") // Remove all whitespace
    .replace(/[""]/g, '"') // Normalize quotes
    .replace(/['']/g, "'"); // Normalize apostrophes
}

/**
 * Calculates points earned for a challenge after hint deductions.
 */
export function calculatePoints(
  challenge: CTFChallenge,
  hintsUsed: string[],
): number {
  const hintCost = challenge.hints
    .filter((h) => hintsUsed.includes(h.id))
    .reduce((total, hint) => total + hint.cost, 0);

  return Math.max(0, challenge.points - hintCost);
}

/**
 * Gets the display color for a category (for UI theming).
 */
export function getCategoryColor(category: CTFCategory): string {
  const colors: Record<CTFCategory, string> = {
    web: "text-primary",
    crypto: "text-stamp",
    forensics: "text-accent",
    pwn: "text-destructive",
    misc: "text-muted-foreground",
    reverse: "text-warning",
    osint: "text-terminal",
  };
  return colors[category];
}

/**
 * Gets the display icon name (Lucide) for a category.
 */
export function getCategoryIcon(category: CTFCategory): string {
  const icons: Record<CTFCategory, string> = {
    web: "Globe",
    crypto: "Lock",
    forensics: "Search",
    pwn: "Skull",
    misc: "Puzzle",
    reverse: "Binary",
    osint: "Eye",
  };
  return icons[category];
}

/**
 * Gets a human-readable label for a category.
 */
export function getCategoryLabel(category: CTFCategory): string {
  const labels: Record<CTFCategory, string> = {
    web: "Web Exploitation",
    crypto: "Cryptography",
    forensics: "Digital Forensics",
    pwn: "Binary Exploitation",
    misc: "Miscellaneous",
    reverse: "Reverse Engineering",
    osint: "Open Source Intelligence",
  };
  return labels[category];
}

/**
 * All available CTF categories.
 */
export const CTF_CATEGORIES: CTFCategory[] = [
  "web",
  "crypto",
  "forensics",
  "pwn",
  "reverse",
  "osint",
  "misc",
];

/**
 * Creates a new CTF challenge with generated IDs for hints.
 */
export function createChallenge(
  params: Omit<CTFChallenge, "id"> & { id?: string },
): CTFChallenge {
  const id = params.id ?? crypto.randomUUID();

  // Ensure hints have IDs
  const hints = params.hints.map((hint, index) => ({
    ...hint,
    id: hint.id ?? `${id}-hint-${index}`,
  }));

  return {
    ...params,
    id,
    hints,
    solveCount: params.solveCount ?? 0,
  };
}

/**
 * Creates a submission record for a challenge attempt.
 */
export function createSubmission(
  challengeId: string,
  userId: string,
  correct: boolean,
  challenge: CTFChallenge,
  hintsUsed: string[],
): CTFSubmission {
  return {
    challengeId,
    userId,
    timestamp: new Date().toISOString(),
    correct,
    hintsUsed,
    pointsEarned: correct ? calculatePoints(challenge, hintsUsed) : 0,
  };
}

/**
 * Validates a challenge object has all required fields.
 */
export function isValidChallenge(
  challenge: Partial<CTFChallenge>,
): challenge is CTFChallenge {
  return (
    typeof challenge.id === "string" &&
    typeof challenge.title === "string" &&
    typeof challenge.category === "string" &&
    CTF_CATEGORIES.includes(challenge.category as CTFCategory) &&
    typeof challenge.points === "number" &&
    challenge.points >= 0 &&
    typeof challenge.description === "string" &&
    Array.isArray(challenge.hints) &&
    typeof challenge.flag === "string"
  );
}
