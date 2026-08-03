import React, { useEffect, useState } from "react";
import { useGameStore } from "../store/gameStore";
import { useAuthStore } from "../store/authStore";
import { BadgeList } from "../components/BadgeList";
import { MODULES } from "../data/modules";
import {
  User,
  Shield,
  Trophy,
  Target,
  Award,
  Pencil,
  AlertTriangle,
  Loader2,
} from "lucide-react";
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import { Certificate } from "../components/Certificate";
import { ProfileEditModal } from "../components/ProfileEditModal";
import { RoleSelector } from "../components/RoleSelector";

const ROLE_LABELS: Record<string, string> = {
  developer: "Developer / Engineer",
  devops: "DevOps / IT Admin",
  manager: "Manager / Executive",
  general: "General Staff",
  skipped: "Not set",
};

export const Profile: React.FC = () => {
  const { xp, level, streakDays, completedModules, userRole } = useGameStore();
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
  const progress = Math.min((xp / nextLevelXp) * 100, 100);

  return (
    <div className="max-w-4xl mx-auto space-y-8 animate-in fade-in duration-500">
      <div className="flex flex-col md:flex-row gap-8 items-center md:items-start">
        <div className="ui-card ui-card-lg flex flex-col items-center gap-4 min-w-[250px]">
          <div className="w-32 h-32 rounded-full border-2 border-primary/40 p-1">
            <div className="w-full h-full rounded-full bg-muted flex items-center justify-center overflow-hidden">
              <User className="w-16 h-16 text-muted-foreground" />
            </div>
          </div>
          <div className="text-center">
            <div className="flex items-center justify-center gap-2">
              <h2 className="text-h2">{displayName}</h2>
              {user && (
                <button
                  onClick={() => setIsEditModalOpen(true)}
                  className="p-1.5 rounded-full hover:bg-muted/50 transition-colors text-muted-foreground hover:text-foreground"
                  aria-label="Edit profile"
                >
                  <Pencil className="w-4 h-4" />
                </button>
              )}
            </div>
            <p className="text-primary text-mono uppercase tracking-widest mt-1">
              Level {level} Operator
            </p>
          </div>
          <div className="w-full h-px bg-border/70 my-2" />
          <div className="grid grid-cols-2 gap-4 w-full text-center">
            <div>
              <p className="text-h2 text-foreground">{streakDays}</p>
              <p className="ui-label">Day Streak</p>
            </div>
            <div>
              <p className="text-h2 text-foreground">
                {completedModules.length}
              </p>
              <p className="ui-label">Missions</p>
            </div>
          </div>
        </div>

        <div className="flex-1 space-y-6 w-full">
          <div className="ui-card ui-card-lg">
            <h3 className="text-h4 mb-6 flex items-center gap-2">
              <Shield className="w-5 h-5 text-primary" /> Security Clearance
              Progress
            </h3>

            <div className="space-y-2 mb-2">
              <div className="flex justify-between text-body-sm">
                <span>Current XP</span>
                <span className="text-muted-foreground">
                  {xp} / {nextLevelXp} XP
                </span>
              </div>
              <div className="h-3 bg-muted rounded-full overflow-hidden relative">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${progress}%` }}
                  transition={{ duration: 1, ease: "easeOut" }}
                  className="h-full bg-primary"
                />
              </div>
              <p className="text-body-sm text-muted-foreground text-right">
                {nextLevelXp - xp} XP needed for Level {level + 1}
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="ui-card ui-card-md flex items-center gap-4">
              <div className="ui-icon-box bg-warning/12 text-warning">
                <Trophy className="w-5 h-5" />
              </div>
              <div>
                <p className="text-h4">{xp.toLocaleString()}</p>
                <p className="text-body-sm text-muted-foreground">Total XP</p>
              </div>
            </div>
            <div className="ui-card ui-card-md flex items-center gap-4">
              <div className="ui-icon-box bg-accent/12 text-accent">
                <Target className="w-5 h-5" />
              </div>
              <div>
                <p className="text-h4">
                  {Math.round((completedModules.length / MODULES.length) * 100)}
                  %
                </p>
                <p className="text-body-sm text-muted-foreground">
                  Training Complete
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="ui-card ui-card-lg">
        <h3 className="text-h4 mb-6 flex items-center gap-2">
          <Award className="w-5 h-5 text-primary" /> Service Ribbons & Badges
        </h3>
        <BadgeList />
      </div>

      <div className="ui-card ui-card-lg">
        <div className="flex items-center justify-between gap-4 mb-4">
          <h3 className="text-h4 flex items-center gap-2">
            <Target className="w-5 h-5 text-primary" /> Training Focus
          </h3>
          <button
            type="button"
            onClick={() => setShowRolePicker((prev) => !prev)}
            className="text-body-sm text-muted-foreground hover:text-foreground transition-colors"
            aria-expanded={showRolePicker}
          >
            {showRolePicker ? "Close" : "Change focus"}
          </button>
        </div>
        {showRolePicker ? (
          <RoleSelector />
        ) : (
          <p className="text-muted-foreground text-body-sm">
            Current role:{" "}
            <span className="text-foreground font-semibold">
              {ROLE_LABELS[userRole ?? ""] ?? "Not set"}
            </span>
          </p>
        )}
      </div>

      <div className="ui-card ui-card-lg">
        <Certificate />
      </div>

      {user && (
        <div className="ui-card ui-card-lg border border-destructive/30">
          <h3 className="text-h4 mb-2 flex items-center gap-2 text-destructive">
            <AlertTriangle className="w-5 h-5" /> Danger Zone
          </h3>
          <p className="text-body-sm text-muted-foreground mb-4">
            Delete your account and stored progress. This permanently removes
            your saved profile data and cannot be undone.
          </p>
          {confirmingDelete ? (
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-body-sm text-foreground">
                Are you sure? This is permanent.
              </span>
              <button
                onClick={handleDeleteAccount}
                disabled={loading}
                className="inline-flex items-center gap-2 h-10 px-4 rounded-[var(--radius-md)] bg-destructive text-white font-medium hover:bg-destructive/90 disabled:opacity-60"
              >
                {loading && <Loader2 className="w-4 h-4 animate-spin" />}
                Yes, delete my account
              </button>
              <button
                onClick={() => setConfirmingDelete(false)}
                disabled={loading}
                className="h-10 px-4 rounded-[var(--radius-md)] border border-border font-medium hover:bg-muted/70"
              >
                Cancel
              </button>
            </div>
          ) : (
            <button
              onClick={() => setConfirmingDelete(true)}
              className="h-10 px-4 rounded-[var(--radius-md)] border border-destructive/50 text-destructive font-medium hover:bg-destructive/10"
            >
              Delete account
            </button>
          )}
        </div>
      )}

      {/* Profile Edit Modal */}
      <ProfileEditModal
        isOpen={isEditModalOpen}
        onClose={() => setIsEditModalOpen(false)}
      />
    </div>
  );
};
