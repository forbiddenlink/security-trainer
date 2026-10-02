import React, { useEffect, useState } from "react";
import { useGameStore } from "../store/gameStore";
import { useAuthStore } from "../store/authStore";
import { BadgeList } from "../components/BadgeList";
import { MODULES } from "../data/modules";
import { Pencil, AlertTriangle, Loader2, Snowflake } from "lucide-react";
import { Progress } from "../components/ui";
import { RuledSection } from "../components/RuledSection";
import { useNavigate } from "react-router-dom";
import { Certificate } from "../components/Certificate";
import { ProfileEditModal } from "../components/ProfileEditModal";
import { RoleSelector } from "../components/RoleSelector";
import { ActivityHeatmap } from "../components/ActivityHeatmap";
import { getRank } from "../lib/rank";

const ROLE_LABELS: Record<string, string> = {
  developer: "Developer / Engineer",
  devops: "DevOps / IT Admin",
  manager: "Manager / Executive",
  general: "General Staff",
  skipped: "Not set",
};

export const Profile: React.FC = () => {
  const xp = useGameStore((s) => s.xp);
  const level = useGameStore((s) => s.level);
  const streakDays = useGameStore((s) => s.streakDays);
  const completedModules = useGameStore((s) => s.completedModules);
  const completedPaths = useGameStore((s) => s.completedPaths);
  const userRole = useGameStore((s) => s.userRole);
  const streakFreezeCount = useGameStore((s) => s.streakFreezeCount);
  const { profile, user, loading, deleteAccount } = useAuthStore();
  const displayName = profile?.display_name || "Agent";
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [showRolePicker, setShowRolePicker] = useState(false);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const navigate = useNavigate();

  const handleDeleteAccount = async () => {
    const { error } = await deleteAccount();
    if (!error) {
      useGameStore.getState().resetProgress();
      navigate("/");
    }
  };

  useEffect(() => {
    // Use getState to ensure we always get the latest function reference
    useGameStore.getState().checkStreak();
  }, []);

  const nextLevelXp = level * 1000;
  const rank = getRank(completedModules.length, completedPaths.length);
  const progress = Math.min((xp / nextLevelXp) * 100, 100);
  const trainingPct = Math.round(
    (completedModules.length / MODULES.length) * 100,
  );

  const stats: [string, React.ReactNode][] = [
    ["Total XP", xp.toLocaleString()],
    ["Missions", `${completedModules.length}/${MODULES.length}`],
    ["Training Complete", `${trainingPct}%`],
    ["Day Streak", streakDays],
    [
      "Freezes",
      <span key="f" className="inline-flex items-center gap-1">
        <Snowflake className="w-5 h-5 text-info" aria-hidden="true" />
        {streakFreezeCount}
      </span>,
    ],
  ];

  return (
    <div className="space-y-12">
      <header className="grid gap-8 pb-2 lg:grid-cols-[auto_minmax(0,1fr)] lg:items-end">
        <div className="flex items-center gap-5">
          <span
            className="grid h-20 w-20 shrink-0 place-items-center rounded-[var(--radius-md)] border border-foreground font-display text-h1 font-extrabold [font-stretch:75%] select-none"
            aria-hidden="true"
          >
            {displayName[0]?.toUpperCase() ?? "A"}
          </span>
          <div>
            <p className="range-readout mb-2">
              <span className="range-dot" aria-hidden="true" />
              Agent dossier
            </p>
            <div className="flex items-center gap-2">
              <h1 className="text-display leading-none">{displayName}</h1>
              {user && (
                <button
                  type="button"
                  onClick={() => setIsEditModalOpen(true)}
                  className="grid h-10 w-10 place-items-center rounded-[var(--radius-sm)] border border-border text-muted-foreground hover:text-foreground hover:border-foreground"
                  aria-label="Edit profile"
                >
                  <Pencil className="w-4 h-4" />
                </button>
              )}
            </div>
            <p className="mt-2 font-mono text-caption uppercase tracking-[0.14em] text-muted-foreground">
              Level {level} · {rank.current.name}
            </p>
          </div>
        </div>

        <div className="lg:pl-8 lg:border-l lg:border-border">
          <div className="flex justify-between font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground mb-2 tabular-nums">
            <span>Security clearance</span>
            <span>
              {xp.toLocaleString()} / {nextLevelXp.toLocaleString()} XP
            </span>
          </div>
          <Progress
            value={xp}
            min={0}
            max={nextLevelXp}
            aria-label={`${Math.round(progress)}% to level ${level + 1}`}
          />
          <p className="mt-2 font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground tabular-nums">
            {(nextLevelXp - xp).toLocaleString()} XP needed for Level{" "}
            {level + 1}
          </p>
          <div className="mt-6 flex justify-between font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground mb-2 tabular-nums">
            <span>Field rank · {rank.current.name}</span>
            <span>{rank.next ? `Next: ${rank.next.name}` : "Top rank"}</span>
          </div>
          <Progress
            value={Math.round(rank.progress * 100)}
            min={0}
            max={100}
            aria-label={
              rank.next
                ? `${Math.round(rank.progress * 100)}% toward ${rank.next.name} rank`
                : "Top rank reached"
            }
          />
          {rank.next && (
            <p className="mt-2 font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground tabular-nums">
              Needs {rank.next.modules} missions
              {rank.next.paths > 0 &&
                ` and ${rank.next.paths} certified path${rank.next.paths > 1 ? "s" : ""}`}
            </p>
          )}
        </div>

        <dl className="lg:col-span-2 grid grid-cols-2 gap-6 sm:grid-cols-5">
          {stats.map(([label, value]) => (
            <div key={label}>
              <dt className="ui-label">{label}</dt>
              <dd className="mt-1 font-display text-h1 font-extrabold [font-stretch:75%] tabular-nums leading-none">
                {value}
              </dd>
            </div>
          ))}
        </dl>
      </header>

      <RuledSection
        index="01"
        label="Service record"
        id="badges-heading"
        title="Service Ribbons & Badges"
      >
        <BadgeList />
      </RuledSection>

      <RuledSection
        index="02"
        label="Focus"
        id="focus-heading"
        title="Training Focus"
        aside={
          <button
            type="button"
            onClick={() => setShowRolePicker((prev) => !prev)}
            className="font-mono text-caption uppercase tracking-[0.12em] text-muted-foreground underline underline-offset-4 hover:text-foreground"
            aria-expanded={showRolePicker}
          >
            {showRolePicker ? "Close" : "Change focus"}
          </button>
        }
      >
        {showRolePicker ? (
          <RoleSelector />
        ) : (
          <p className="text-muted-foreground">
            Current role:{" "}
            <span className="text-foreground font-semibold">
              {ROLE_LABELS[userRole ?? ""] ?? "Not set"}
            </span>
          </p>
        )}
      </RuledSection>

      <RuledSection
        index="03"
        label="Activity"
        id="activity-heading"
        title="Activity"
      >
        <ActivityHeatmap />
      </RuledSection>

      <RuledSection
        index="04"
        label="Credential"
        id="certificate-heading"
        title="Certificate"
      >
        <Certificate />
      </RuledSection>

      {user && (
        <section
          className="border border-destructive/40 rounded-[var(--radius-md)] p-6"
          aria-labelledby="danger-heading"
        >
          <h2
            id="danger-heading"
            className="text-h4 mb-2 flex items-center gap-2 text-destructive"
          >
            <AlertTriangle className="w-5 h-5" aria-hidden="true" /> Danger Zone
          </h2>
          <p className="text-body-sm text-muted-foreground mb-4 max-w-[60ch]">
            Delete your account and stored progress. This permanently removes
            your saved profile data and cannot be undone.
          </p>
          {confirmingDelete ? (
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-body-sm text-foreground">
                Are you sure? This is permanent.
              </span>
              <button
                type="button"
                onClick={handleDeleteAccount}
                disabled={loading}
                className="inline-flex items-center gap-2 h-10 px-4 rounded-[var(--radius-sm)] bg-destructive text-white font-medium hover:bg-destructive/90 disabled:opacity-60"
              >
                {loading && <Loader2 className="w-4 h-4 animate-spin" />}
                Yes, delete my account
              </button>
              <button
                type="button"
                onClick={() => setConfirmingDelete(false)}
                disabled={loading}
                className="h-10 px-4 rounded-[var(--radius-sm)] border border-border font-medium hover:bg-muted/70"
              >
                Cancel
              </button>
            </div>
          ) : (
            <button
              type="button"
              onClick={() => setConfirmingDelete(true)}
              className="h-10 px-4 rounded-[var(--radius-sm)] border border-destructive/50 text-destructive font-medium hover:bg-destructive/10"
            >
              Delete account
            </button>
          )}
        </section>
      )}

      {/* Profile Edit Modal */}
      <ProfileEditModal
        isOpen={isEditModalOpen}
        onClose={() => setIsEditModalOpen(false)}
      />
    </div>
  );
};
