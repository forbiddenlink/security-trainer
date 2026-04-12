import React, { useEffect, useRef, useState, memo, useCallback } from "react";
import { useGameStore } from "../store/gameStore";
import { useAuthStore } from "../store/authStore";
import { Trophy, LogIn, LogOut, ChevronDown, Menu } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { StreakIndicator } from "./StreakIndicator";
import { ThemeToggle } from "./ThemeToggle";
import { Button, Progress } from "./ui";
import { isSupabaseConfigured } from "../lib/supabase";
import { getSafeAvatarUrl } from "../utils/urlValidation";
import { getNextLevelXp } from "../utils/gameUtils";

interface HeaderProps {
  onMenuClick?: () => void;
}

/**
 * Main header with user stats, level progress, and auth controls
 */
export const Header: React.FC<HeaderProps> = memo(({ onMenuClick }) => {
  // Use selectors for better performance - only re-render when specific values change
  const xp = useGameStore((state) => state.xp);
  const level = useGameStore((state) => state.level);
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
    <header
      className="sticky top-0 z-20 h-16 border-b border-border/70 bg-card/82 backdrop-blur-md px-4 md:px-6 flex items-center justify-between"
      role="banner"
    >
      <div className="flex items-center gap-3">
        <button
          onClick={onMenuClick}
          className="lg:hidden grid h-9 w-9 place-items-center rounded-[var(--radius-sm)] text-muted-foreground hover:text-foreground hover:bg-muted/60"
          aria-label="Open navigation menu"
        >
          <Menu className="w-5 h-5" aria-hidden="true" />
        </button>
        <h1 className="text-h4 tracking-tight text-foreground">
          Mission Control
        </h1>
      </div>

      <div className="flex items-center gap-2 md:gap-3" aria-label="User stats">
        <div
          className="hidden xl:flex flex-col items-end rounded-[var(--radius-sm)] border border-border/70 bg-background/40 px-3 py-2 group cursor-help min-w-[190px]"
          aria-live="polite"
        >
          <div className="flex items-center gap-2 text-xs font-medium text-foreground">
            <Trophy className="w-3.5 h-3.5 text-warning" aria-hidden="true" />
            <span>Level {level}</span>
            <span className="text-muted-foreground font-normal">|</span>
            <span className="text-muted-foreground">{xp} XP</span>
          </div>
          <Progress
            className="mt-1 w-full"
            value={xp}
            min={0}
            max={nextLevelXp}
            aria-label={`${xp} of ${nextLevelXp} XP to next level`}
            indicatorClassName="bg-linear-to-r from-primary to-accent"
          />
          <span
            className="text-caption text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity mt-1"
            aria-hidden="true"
          >
            {xp} / {nextLevelXp} XP
          </span>
          <span className="sr-only">
            {xp} of {nextLevelXp} XP to next level
          </span>
        </div>

        <StreakIndicator />

        <ThemeToggle />

        {isSupabaseConfigured() ? (
          loading ? (
            <div className="h-9 w-9 rounded-full bg-muted animate-pulse" />
          ) : user ? (
            <div className="relative" ref={menuRef}>
              <button
                onClick={() => setShowUserMenu(!showUserMenu)}
                className="flex items-center gap-2 rounded-full border border-border/80 bg-background/40 py-0.5 pl-0.5 pr-2 hover:bg-muted/55"
                aria-label="User menu"
                aria-expanded={showUserMenu}
              >
                {getSafeAvatarUrl(profile?.avatar_url) ? (
                  <img
                    src={getSafeAvatarUrl(profile?.avatar_url)}
                    alt=""
                    className="w-8 h-8 rounded-full object-cover border border-primary/20"
                  />
                ) : (
                  <div className="w-8 h-8 rounded-full bg-gradient-to-br from-primary to-accent border border-primary/30 flex items-center justify-center text-primary-foreground text-sm font-bold">
                    {avatarInitial}
                  </div>
                )}
                <ChevronDown className="w-4 h-4 text-muted-foreground" />
              </button>

              <AnimatePresence>
                {showUserMenu && (
                  <motion.div
                    initial={{ opacity: 0, y: 8, scale: 0.95 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: 8, scale: 0.95 }}
                    className="absolute right-0 mt-2 w-56 ui-card ui-card-elevated overflow-hidden"
                  >
                    <div className="p-3 border-b border-border/70">
                      <p className="font-medium text-foreground truncate">
                        {displayName}
                      </p>
                      <p className="text-sm text-muted-foreground truncate">
                        {user.email}
                      </p>
                    </div>
                    <div className="p-2">
                      <button
                        onClick={handleSignOut}
                        className="w-full flex items-center gap-2 px-3 py-2 text-sm text-muted-foreground hover:bg-muted rounded-[var(--radius-sm)] transition-colors"
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
              className="inline-flex items-center gap-2"
            >
              <LogIn className="w-4 h-4" />
              <span className="hidden sm:inline">Sign In</span>
            </Button>
          )
        ) : (
          <div
            className="w-9 h-9 rounded-full bg-gradient-to-br from-primary to-accent border border-primary/20"
            role="img"
            aria-label="User avatar"
          />
        )}
      </div>
    </header>
  );
});

Header.displayName = "Header";
