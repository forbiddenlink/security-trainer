import React, { useState, useEffect, useMemo } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { Star, Clock, CheckCircle, ArrowRight } from "lucide-react";
import { Card } from "./ui";
import { useGameStore } from "../store/gameStore";

export const DailyChallenge: React.FC = () => {
  const { getDailyChallenge, dailyChallengeCompleted } = useGameStore();
  const [timeRemaining, setTimeRemaining] = useState("");

  const challenge = useMemo(() => getDailyChallenge(), [getDailyChallenge]);

  // Calculate time until midnight
  useEffect(() => {
    const updateTimer = () => {
      const now = new Date();
      const midnight = new Date();
      midnight.setHours(24, 0, 0, 0);

      const diff = midnight.getTime() - now.getTime();

      const hours = Math.floor(diff / (1000 * 60 * 60));
      const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
      const seconds = Math.floor((diff % (1000 * 60)) / 1000);

      setTimeRemaining(
        `${hours.toString().padStart(2, "0")}:${minutes.toString().padStart(2, "0")}:${seconds.toString().padStart(2, "0")}`,
      );
    };

    updateTimer();
    const interval = setInterval(updateTimer, 1000);

    return () => clearInterval(interval);
  }, []);

  if (!challenge) {
    return (
      <Card className="p-6">
        <div className="flex items-center gap-3 mb-4">
          <div className="h-9 w-9 grid place-items-center rounded-[var(--radius-sm)] bg-warning/10 text-warning">
            <Star className="w-5 h-5" />
          </div>
          <h3 className="text-lg font-semibold tracking-tight">
            Daily Challenge
          </h3>
        </div>
        <p className="text-muted-foreground">
          All lessons completed! Check back tomorrow for a new challenge.
        </p>
      </Card>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className={`ui-card relative overflow-hidden p-6 ${
        dailyChallengeCompleted
          ? "bg-accent/10 border-accent/30"
          : "bg-linear-to-br from-warning/10 to-warning/5 border-warning/30"
      }`}
    >
      {/* Decorative glow */}
      {!dailyChallengeCompleted && (
        <div className="absolute -top-10 -right-10 w-32 h-32 bg-yellow-500/20 blur-3xl rounded-full pointer-events-none" />
      )}

      <div className="relative z-10">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div
              className={`h-9 w-9 grid place-items-center rounded-[var(--radius-sm)] ${
                dailyChallengeCompleted
                  ? "bg-accent/10 text-accent"
                  : "bg-warning/10 text-warning"
              }`}
            >
              {dailyChallengeCompleted ? (
                <CheckCircle className="w-5 h-5" />
              ) : (
                <Star className="w-5 h-5" />
              )}
            </div>
            <div>
              <h3 className="text-lg font-semibold tracking-tight">
                Daily Challenge
              </h3>
              <p className="text-xs text-muted-foreground">
                {dailyChallengeCompleted ? "Completed!" : "+50 Bonus XP"}
              </p>
            </div>
          </div>

          {!dailyChallengeCompleted && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Clock className="w-4 h-4" />
              <span className="font-mono">{timeRemaining}</span>
            </div>
          )}
        </div>

        <div className="bg-background/50 rounded-lg p-4 mb-4">
          <p className="text-sm text-muted-foreground mb-1">
            {challenge.moduleTitle}
          </p>
          <p className="font-semibold">{challenge.lessonTitle}</p>
        </div>

        {dailyChallengeCompleted ? (
          <div className="flex items-center justify-center gap-2 py-2.5 px-4 bg-accent/20 text-accent rounded-[var(--radius-sm)] font-medium">
            <CheckCircle className="w-5 h-5" />
            Challenge Complete!
          </div>
        ) : (
          <Link
            to={`/modules/${challenge.moduleId}/${challenge.lessonId}`}
            className="group inline-flex h-10 w-full items-center justify-center gap-2 rounded-[var(--radius-sm)] bg-warning px-4 font-semibold text-black transition-colors hover:bg-warning/90"
          >
            Start Challenge
            <ArrowRight className="w-5 h-5 group-hover:translate-x-1 transition-transform" />
          </Link>
        )}
      </div>
    </motion.div>
  );
};
