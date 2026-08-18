import React, { useEffect } from "react";
import { Trophy, Medal, Crown, User } from "lucide-react";
import { motion } from "framer-motion";
import { useAuthStore } from "../store/authStore";
import { Button, Skeleton } from "../components/ui";
import { isSupabaseConfigured } from "../lib/supabase";
import { getSafeAvatarUrl } from "../utils/urlValidation";

export const Leaderboard: React.FC = () => {
  const {
    user,
    leaderboard,
    leaderboardLoading,
    userRank,
    profile,
    fetchLeaderboard,
    openAuthModal,
  } = useAuthStore();

  useEffect(() => {
    if (isSupabaseConfigured()) {
      fetchLeaderboard();
    }
  }, [fetchLeaderboard]);

  const getRankIcon = (rank: number) => {
    switch (rank) {
      case 1:
        return <Crown className="w-6 h-6 text-warning" />;
      case 2:
        return <Medal className="w-6 h-6 text-muted-foreground" />;
      case 3:
        return <Medal className="w-6 h-6 text-warning" />;
      default:
        return (
          <span className="w-6 h-6 flex items-center justify-center text-muted-foreground font-bold">
            {rank}
          </span>
        );
    }
  };

  const getRankBgClass = (rank: number, isCurrentUser: boolean) => {
    if (isCurrentUser) {
      return "bg-primary/10 border-primary/30";
    }
    switch (rank) {
      case 1:
        return "bg-warning/10 border-warning/30";
      case 2:
        return "bg-muted/30 border-border";
      case 3:
        return "bg-warning/5 border-warning/20";
      default:
        return "bg-card border-border";
    }
  };

  if (!isSupabaseConfigured()) {
    return (
      <div className="max-w-4xl mx-auto animate-in fade-in duration-500">
        <div className="ui-card ui-card-lg ops-briefing range-panel range-ticks relative overflow-hidden">
          <div className="relative z-10 text-center py-8">
            <div className="flex items-center justify-center gap-2 mb-4">
              <span className="range-dot" aria-hidden="true" />
              <span className="range-readout">
                INTEL FEED // CLEARANCE REQUIRED
              </span>
            </div>
            <div className="p-5 rounded-full bg-primary/8 border border-primary/20 inline-flex mb-6">
              <Trophy className="w-14 h-14 text-primary" aria-hidden="true" />
            </div>
            <h2 className="text-h2 mb-3">Rankings Classified</h2>
            <p className="text-body text-muted-foreground max-w-sm mx-auto">
              Agent rankings require database clearance. Configure Supabase to
              access the global leaderboard.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div
      className="max-w-4xl mx-auto animate-in fade-in duration-500"
      role="main"
    >
      <section className="ui-card ui-card-lg ops-briefing relative overflow-hidden mb-8">
        <div className="relative z-10">
          <div className="flex items-center gap-3 mb-2">
            <Trophy className="w-8 h-8 text-warning" />
            <h1 className="text-h1">Leaderboard</h1>
          </div>
          <p className="text-muted-foreground text-body">
            Top security agents ranked by experience points
          </p>
        </div>
      </section>

      {user && profile && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8 ui-card ui-card-md border-primary/30"
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="w-12 h-12 rounded-full border border-primary/40 bg-muted flex items-center justify-center text-foreground font-semibold text-body">
                {profile.display_name?.[0]?.toUpperCase() || "A"}
              </div>
              <div>
                <h3 className="text-h4">{profile.display_name || "Agent"}</h3>
                <p className="text-muted-foreground text-body-sm">
                  Your current standing
                </p>
              </div>
            </div>
            <div className="text-right">
              <p className="text-h1 text-primary">#{userRank || "-"}</p>
              <p className="text-muted-foreground text-body-sm">
                {profile.xp.toLocaleString()} XP
              </p>
            </div>
          </div>
        </motion.div>
      )}

      {/* Not logged in prompt */}
      {!user && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8 ui-card ui-card-md bg-muted/40 text-center"
        >
          <User className="w-12 h-12 mx-auto text-muted-foreground mb-3" />
          <h3 className="text-h4 mb-2">Join the Leaderboard</h3>
          <p className="text-muted-foreground text-body mb-4">
            Sign in to save your progress and compete with other agents.
          </p>
          <Button onClick={() => openAuthModal("login")} className="px-5">
            Sign In
          </Button>
        </motion.div>
      )}

      <div className="space-y-3">
        {leaderboardLoading && leaderboard.length === 0 ? (
          <div className="space-y-3" aria-hidden="true">
            {Array.from({ length: 5 }).map((_, i) => (
              <Skeleton
                key={i}
                className="h-16 w-full rounded-[var(--radius-md)]"
              />
            ))}
          </div>
        ) : leaderboard.length === 0 ? (
          <div className="text-center py-12 text-muted-foreground">
            <Trophy className="w-12 h-12 mx-auto mb-3 opacity-50" />
            <p>No agents on the leaderboard yet. Be the first!</p>
          </div>
        ) : (
          leaderboard.map((entry, index) => {
            const isCurrentUser = user?.id === entry.id;
            return (
              <motion.div
                key={entry.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.05 }}
                className={`flex items-center gap-4 p-4 rounded-[var(--radius-md)] border ${getRankBgClass(entry.rank || index + 1, isCurrentUser)} transition-all duration-150 hover:border-primary/50`}
              >
                {/* Rank */}
                <div className="w-10 flex justify-center">
                  {getRankIcon(entry.rank || index + 1)}
                </div>

                {/* Avatar */}
                <div
                  className={`w-10 h-10 rounded-full flex items-center justify-center font-bold ${
                    entry.rank === 1
                      ? "bg-warning text-card"
                      : entry.rank === 2
                        ? "bg-muted text-muted-foreground"
                        : entry.rank === 3
                          ? "bg-warning/70 text-card"
                          : "bg-primary text-primary-foreground"
                  }`}
                >
                  {getSafeAvatarUrl(entry.avatar_url) ? (
                    <img
                      src={getSafeAvatarUrl(entry.avatar_url)}
                      alt={`${entry.display_name || "Agent"}'s avatar`}
                      className="w-full h-full rounded-full object-cover"
                    />
                  ) : (
                    entry.display_name?.[0]?.toUpperCase() || "A"
                  )}
                </div>

                {/* Name */}
                <div className="flex-1">
                  <h3
                    className={`font-semibold ${isCurrentUser ? "text-primary" : ""}`}
                  >
                    {entry.display_name || "Anonymous Agent"}
                    {isCurrentUser && (
                      <span className="ml-2 text-xs text-primary">(You)</span>
                    )}
                  </h3>
                  <p className="text-sm text-muted-foreground">
                    Level {entry.level}
                  </p>
                </div>

                {/* XP */}
                <div className="text-right">
                  <p className="text-h4">{entry.xp.toLocaleString()}</p>
                  <p className="ui-label">XP</p>
                </div>
              </motion.div>
            );
          })
        )}
      </div>
    </div>
  );
};
