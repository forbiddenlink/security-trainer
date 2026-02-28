import React, { useEffect, useState } from "react";
import { useGameStore } from "../store/gameStore";
import { useAuthStore } from "../store/authStore";
import { BadgeList } from "../components/BadgeList";
import { MODULES } from "../data/modules";
import { User, Shield, Trophy, Target, Award, Pencil } from "lucide-react";
import { motion } from "framer-motion";
import { Certificate } from "../components/Certificate";
import { ProfileEditModal } from "../components/ProfileEditModal";

export const Profile: React.FC = () => {
  const { xp, level, streakDays, completedModules } = useGameStore();
  const { profile, user } = useAuthStore();
  const displayName = profile?.display_name || "Agent";
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);

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
          <div className="w-32 h-32 rounded-full bg-linear-to-br from-primary to-accent p-1">
            <div className="w-full h-full rounded-full bg-card flex items-center justify-center overflow-hidden">
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
                  className="h-full bg-linear-to-r from-primary to-accent"
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
        <Certificate />
      </div>

      {/* Profile Edit Modal */}
      <ProfileEditModal
        isOpen={isEditModalOpen}
        onClose={() => setIsEditModalOpen(false)}
      />
    </div>
  );
};
