import React from "react";
import { motion } from "framer-motion";
import { GraduationCap } from "lucide-react";
import { PathCard } from "../components/PathCard";
import { LEARNING_PATHS } from "../data/learningPaths";
import { useGameStore } from "../store/gameStore";

export const Paths: React.FC = () => {
  const { completedPaths } = useGameStore();

  return (
    <div
      className="space-y-8 max-w-6xl mx-auto animate-in fade-in duration-500"
      role="main"
    >
      {/* Header */}
      <section className="ui-card ui-card-lg ops-briefing relative overflow-hidden">
        <div className="relative z-10">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 rounded-[var(--radius-sm)] bg-primary/10 border border-primary/20 flex items-center justify-center">
              <GraduationCap className="w-5 h-5 text-primary" />
            </div>
            <div>
              <p className="ui-chip">Agent Specializations</p>
            </div>
          </div>
          <h1 className="text-h1 mb-2">Learning Paths</h1>
          <p className="text-muted-foreground max-w-2xl">
            Choose your mission track and earn certifications. Complete all
            modules in a path to become a certified specialist.
          </p>
          {completedPaths.length > 0 && (
            <p className="mt-2 text-sm text-accent font-medium">
              {completedPaths.length} certification
              {completedPaths.length !== 1 ? "s" : ""} earned
            </p>
          )}
        </div>
      </section>

      {/* Paths Grid */}
      <section aria-label="Learning paths">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {LEARNING_PATHS.map((path, index) => (
            <PathCard key={path.id} path={path} index={index} />
          ))}
        </div>
      </section>

      {/* Info */}
      <motion.section
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.4 }}
        className="text-center text-sm text-muted-foreground"
      >
        <p>
          Complete paths in any order. Some advanced paths require completing
          modules first.
        </p>
        <p className="mt-1">
          Certifications award bonus XP and appear on your profile.
        </p>
      </motion.section>
    </div>
  );
};
