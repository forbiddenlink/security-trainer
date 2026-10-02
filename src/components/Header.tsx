import React, { useEffect, useRef, useState, memo, useCallback } from "react";
import { useGameStore } from "../store/gameStore";
import { useAuthStore } from "../store/authStore";
import { LogIn, LogOut, ChevronDown, Menu, Search } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { StreakIndicator } from "./StreakIndicator";
import { ThemeToggle } from "./ThemeToggle";
import { Button, Progress } from "./ui";
import { isSupabaseConfigured } from "../lib/supabase";
import { getSafeAvatarUrl } from "../utils/urlValidation";
import { getNextLevelXp } from "../utils/gameUtils";
import { useLocation } from "react-router-dom";
import { MODULES } from "../data/modules";
import { getPathById } from "../data/learningPaths";
import { openCommandPalette } from "../lib/paletteEvents";

const isMac =
  typeof navigator !== "undefined" &&
  /Mac|iPhone|iPad/.test(navigator.platform);

const ROUTE_TITLES: Record<string, string> = {
  "": "Mission Control",
  modules: "Modules",
  profile: "Profile",
  challenge: "Final Exam",
  leaderboard: "Leaderboard",
  paths: "Learning Paths",
  reviews: "Intel Review",
  ctf: "CTF Challenges",
  privacy: "Privacy & Terms",
};

interface HeaderProps {
  onMenuClick?: () => void;
}

/**
 * Main header with user stats, level progress, and auth controls
 */
export const Header: React.FC<HeaderProps> = memo(({ onMenuClick }) => {
  const { pathname } = useLocation();
  const [, section = "", detailId] = pathname.split("/");
  const routeTitle = ROUTE_TITLES[section] ?? "SecTrainer";
  const detailTitle =
    section === "modules" && detailId
      ? MODULES.find((m) => m.id === detailId)?.title
      : section === "paths" && detailId
        ? getPathById(detailId)?.title
        : undefined;

  // Use selectors for better performance - only re-render when specific values change
  const xp = useGameStore((state) => state.xp);
  const level = useGameStore((state) => state.level);
  const syncStatus = useGameStore((state) => state.syncStatus);
  const checkStreak = useGameStore((state) => state.checkStreak);
  const checkDailyChallenge = useGameStore(
    (state) => state.checkDailyChallenge,
  );

  // Auth store selectors
  const user = useAuthStore((state) => state.user);
  const profile = useAuthStore((state) => state.profile);
  const loading = useAuthStore((state) => state.loading);
  const openAuthModal = useAuthStore((state) => state.openAuthModal);
  const signOut = useAuthStore((state) => state.signOut);
  const initialize = useAuthStore((state) => state.initialize);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  // Initialize auth, then check streak/challenge (avoid race condition)
  useEffect(() => {
    const init = async () => {
      if (isSupabaseConfigured()) {
        await initialize();
      }
      // Check streak and daily challenge after auth is ready
      checkStreak();
      checkDailyChallenge();
    };
    init();
  }, [initialize, checkStreak, checkDailyChallenge]);

  // Close menu on outside click
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setShowUserMenu(false);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const nextLevelXp = getNextLevelXp(level);
  // Memoize sign out handler
  const handleSignOut = useCallback(() => {
    setShowUserMenu(false);
    signOut();
  }, [signOut]);

  const displayName =
    profile?.display_name || user?.email?.split("@")[0] || "Agent";
  const avatarInitial = displayName[0]?.toUpperCase() || "A";

  return (
    <header className="sticky top-0 z-20 h-16 border-b border-border bg-background/88 backdrop-blur-md px-4 md:px-6 flex items-center justify-between gap-3">
      <div className="flex items-center gap-3 min-w-0">
        <button
          type="button"
          onClick={onMenuClick}
          className="lg:hidden grid h-10 w-10 place-items-center rounded-[var(--radius-sm)] border border-border text-foreground hover:border-foreground"
          aria-label="Open navigation menu"
        >
          <Menu className="w-5 h-5" aria-hidden="true" />
        </button>
        <nav aria-label="Breadcrumb" className="min-w-0">
          <ol className="flex items-center gap-2 font-mono text-caption uppercase tracking-[0.12em] min-w-0">
            <li className="hidden sm:block text-muted-foreground">
              SecTrainer
            </li>
            <li
              className="hidden sm:block text-muted-foreground"
              aria-hidden="true"
            >
              /
            </li>
            <li
              className={
                detailTitle
                  ? "text-muted-foreground truncate"
                  : "text-foreground truncate"
              }
              aria-current={detailTitle ? undefined : "page"}
            >
              {routeTitle}
            </li>
            {detailTitle && (
              <>
                <li
                  className="hidden md:block text-muted-foreground"
                  aria-hidden="true"
                >
                  /
                </li>
                <li
                  className="hidden md:block text-foreground truncate max-w-[28ch]"
                  aria-current="page"
                >
                  {detailTitle}
                </li>
              </>
            )}
          </ol>
        </nav>
      </div>

      <div className="flex items-center gap-2 md:gap-3">
        <button
          type="button"
          onClick={openCommandPalette}
          className="hidden md:flex h-10 w-56 lg:w-64 items-center gap-2 rounded-[var(--radius-sm)] border border-border bg-card px-3 text-body-sm text-muted-foreground hover:border-foreground hover:text-foreground"
          aria-label="Search modules, paths and challenges"
          aria-keyshortcuts="Meta+K Control+K"
        >
          <Search className="w-4 h-4" aria-hidden="true" />
          <span className="flex-1 text-left">Jump to…</span>
          <kbd className="kbd">{isMac ? "⌘K" : "Ctrl K"}</kbd>
        </button>
        <button
          type="button"
          onClick={openCommandPalette}
          className="md:hidden grid h-10 w-10 place-items-center rounded-[var(--radius-sm)] border border-border text-foreground"
          aria-label="Search"
        >
          <Search className="w-4 h-4" aria-hidden="true" />
        </button>

        <div
          className="hidden xl:flex flex-col justify-center gap-1.5 w-40"
          aria-live="polite"
        >
          <div className="flex items-baseline justify-between font-mono text-[11px] tabular-nums">
            <span className="text-foreground font-semibold">L{level}</span>
            <span className="text-muted-foreground">
              {xp.toLocaleString()} / {nextLevelXp.toLocaleString()} XP
            </span>
          </div>
          <Progress
            value={xp}
            min={0}
            max={nextLevelXp}
            aria-label={`${xp} of ${nextLevelXp} XP to next level`}
          />
        </div>

        <StreakIndicator />

        <ThemeToggle />

        {user && syncStatus !== "idle" && (
          <span
            className={`ui-chip hidden sm:inline-flex ${
              syncStatus === "synced"
                ? "border-accent/50 text-accent"
                : syncStatus === "error"
                  ? "border-destructive/50 text-destructive"
                  : "border-warning/50 text-warning"
            }`}
            aria-live="polite"
          >
            {syncStatus === "syncing" || syncStatus === "retrying"
              ? "Syncing"
              : syncStatus === "synced"
                ? "Synced"
                : "Sync error"}
          </span>
        )}

        {isSupabaseConfigured() ? (
          loading ? (
            <div className="h-10 w-10 rounded-[var(--radius-sm)] bg-muted animate-pulse" />
          ) : user ? (
            <div className="relative" ref={menuRef}>
              <button
                type="button"
                onClick={() => setShowUserMenu(!showUserMenu)}
                className="flex h-10 items-center gap-2 rounded-[var(--radius-sm)] border border-border pl-1 pr-2 hover:border-foreground"
                aria-label="User menu"
                aria-expanded={showUserMenu}
              >
                {getSafeAvatarUrl(profile?.avatar_url) ? (
                  <img
                    src={getSafeAvatarUrl(profile?.avatar_url)}
                    alt=""
                    className="w-8 h-8 rounded-[2px] object-cover"
                  />
                ) : (
                  <div className="w-8 h-8 rounded-[2px] bg-muted flex items-center justify-center font-mono text-foreground text-sm font-semibold">
                    {avatarInitial}
                  </div>
                )}
                <ChevronDown className="w-4 h-4 text-muted-foreground" />
              </button>

              <AnimatePresence>
                {showUserMenu && (
                  <motion.div
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 6 }}
                    transition={{ duration: 0.16 }}
                    className="absolute right-0 mt-2 w-56 ui-card ui-card-elevated !p-0 overflow-hidden"
                  >
                    <div className="p-3 border-b border-border">
                      <p className="font-medium text-foreground truncate">
                        {displayName}
                      </p>
                      <p className="text-sm text-muted-foreground truncate">
                        {user.email}
                      </p>
                    </div>
                    <div className="p-1.5">
                      <button
                        type="button"
                        onClick={handleSignOut}
                        className="w-full flex items-center gap-2 px-3 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-muted rounded-[var(--radius-sm)] transition-colors"
                      >
                        <LogOut className="w-4 h-4" />
                        Sign Out
                      </button>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          ) : (
            <Button
              onClick={() => openAuthModal("login")}
              variant="outline"
              className="h-10"
            >
              <LogIn className="w-4 h-4" aria-hidden="true" />
              <span className="hidden sm:inline">Sign in</span>
            </Button>
          )
        ) : null}
      </div>
    </header>
  );
});

Header.displayName = "Header";
