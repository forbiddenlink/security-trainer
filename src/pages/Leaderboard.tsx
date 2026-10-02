import React, { useEffect } from "react";
import { clsx } from "clsx";
import { useAuthStore } from "../store/authStore";
import { useGameStore } from "../store/gameStore";
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
  const localXp = useGameStore((st) => st.xp);
  const localLevel = useGameStore((st) => st.level);
  const localBadges = useGameStore((st) => st.badges.length);

  useEffect(() => {
    if (isSupabaseConfigured()) {
      fetchLeaderboard();
    }
  }, [fetchLeaderboard]);

  const header = (
    <header className="border-b border-border pb-8 mb-8">
      <p className="range-readout mb-3">
        <span className="range-dot" aria-hidden="true" />
        Service record · ranked by XP
      </p>
      <h1 className="text-display">Leaderboard</h1>
      <p className="mt-4 text-muted-foreground max-w-[60ch]">
        Top security agents ranked by experience points.
      </p>
    </header>
  );

  if (!isSupabaseConfigured()) {
    // No shared database in this deployment: show the learner's own record
    // instead of a dead end.
    return (
      <div className="max-w-4xl">
        {header}
        <section className="border border-dashed border-border rounded-[var(--radius-md)] p-6 md:p-8">
          <p className="ui-label mb-2">Rankings offline</p>
          <h2 className="text-h2 mb-3">Rankings Classified</h2>
          <p className="text-muted-foreground max-w-[56ch]">
            Global rankings need the shared database, which is not configured
            for this deployment. Your progress still saves on this device.
          </p>
          <dl className="mt-8 grid grid-cols-3 gap-6 border-t border-border pt-6">
            {[
              ["Your XP", localXp.toLocaleString()],
              ["Level", localLevel],
              ["Badges", localBadges],
            ].map(([label, value]) => (
              <div key={label}>
                <dt className="ui-label">{label}</dt>
                <dd className="mt-1 font-display text-h1 font-extrabold [font-stretch:75%] tabular-nums leading-none">
                  {value}
                </dd>
              </div>
            ))}
          </dl>
        </section>
      </div>
    );
  }

  return (
    <div className="max-w-4xl">
      {header}

      {user && profile && (
        <section
          className="mb-8 flex items-center justify-between gap-4 border-l-[3px] border-primary pl-4"
          aria-label="Your standing"
        >
          <div>
            <p className="ui-label">Your current standing</p>
            <p className="text-h4 mt-1">{profile.display_name || "Agent"}</p>
          </div>
          <div className="text-right">
            <p className="font-display text-h1 font-extrabold [font-stretch:75%] tabular-nums leading-none">
              #{userRank || "-"}
            </p>
            <p className="mt-1 font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground tabular-nums">
              {profile.xp.toLocaleString()} XP
            </p>
          </div>
        </section>
      )}

      {!user && (
        <section className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border border-dashed border-border rounded-[var(--radius-md)] p-5">
          <div>
            <h2 className="text-h4">Join the Leaderboard</h2>
            <p className="text-muted-foreground text-body-sm mt-1">
              Sign in to save your progress and compete with other agents.
            </p>
          </div>
          <Button onClick={() => openAuthModal("login")} variant="outline">
            Sign In
          </Button>
        </section>
      )}

      {leaderboardLoading && leaderboard.length === 0 ? (
        <div
          className="space-y-2"
          role="status"
          aria-busy="true"
          aria-label="Loading rankings"
        >
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-14 w-full" />
          ))}
        </div>
      ) : leaderboard.length === 0 ? (
        <p className="py-12 text-muted-foreground">
          No agents on the leaderboard yet. Be the first!
        </p>
      ) : (
        <ol className="border-t border-border" aria-label="Rankings">
          {leaderboard.map((entry, index) => {
            const rank = entry.rank || index + 1;
            const isCurrentUser = user?.id === entry.id;
            const avatar = getSafeAvatarUrl(entry.avatar_url);
            return (
              <li
                key={entry.id}
                className={clsx(
                  "flex items-center gap-4 border-b border-border py-3 pl-3",
                  isCurrentUser &&
                    "bg-muted shadow-[inset_3px_0_0_var(--color-primary)]",
                )}
              >
                <span
                  className={clsx(
                    "w-10 font-display font-extrabold [font-stretch:75%] tabular-nums",
                    rank <= 3 ? "text-h3" : "text-h4 text-muted-foreground",
                  )}
                >
                  {String(rank).padStart(2, "0")}
                </span>
                <span className="grid h-9 w-9 shrink-0 place-items-center overflow-hidden rounded-[var(--radius-xs)] border border-border font-mono text-caption font-semibold">
                  {avatar ? (
                    <img
                      src={avatar}
                      alt={`${entry.display_name || "Agent"}'s avatar`}
                      className="h-full w-full object-cover"
                    />
                  ) : (
                    entry.display_name?.[0]?.toUpperCase() || "A"
                  )}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="truncate font-semibold">
                    {entry.display_name || "Anonymous Agent"}
                    {isCurrentUser && (
                      <span className="ml-2 font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground">
                        (You)
                      </span>
                    )}
                  </p>
                  <p className="font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground">
                    Level {entry.level}
                  </p>
                </div>
                <p className="pr-3 text-right font-mono tabular-nums">
                  {entry.xp.toLocaleString()}
                  <span className="ml-1 text-[11px] text-muted-foreground">
                    XP
                  </span>
                </p>
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
};
