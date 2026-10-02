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
      <Card className="ui-card-md">
        <p className="ui-label mb-2">Daily · +50 XP</p>
        <h3 className="text-h3 mb-2">Daily Challenge</h3>
        <p className="text-body-sm text-muted-foreground">
          All lessons completed! Check back tomorrow for a new challenge.
        </p>
      </Card>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.28, ease: [0.2, 0.8, 0.2, 1] }}
      className={`ui-card ui-card-md mission-card flex flex-col ${
        dailyChallengeCompleted ? "border-accent/50" : ""
      }`}
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="ui-label flex items-center gap-2">
            {dailyChallengeCompleted ? (
              <CheckCircle
                className="w-3.5 h-3.5 text-accent"
                aria-hidden="true"
              />
            ) : (
              <Star className="w-3.5 h-3.5" aria-hidden="true" />
            )}
            <span>
              {dailyChallengeCompleted ? "Completed!" : "+50 Bonus XP"}
            </span>
          </p>
          <h3 className="text-h3 mt-2">Daily Challenge</h3>
        </div>
        {!dailyChallengeCompleted && (
          <div
            className="flex items-center gap-1.5 font-mono text-caption tabular-nums text-muted-foreground"
            title="Time until a new daily challenge"
          >
            <Clock className="w-3.5 h-3.5" aria-hidden="true" />
            <span>{timeRemaining}</span>
          </div>
        )}
      </div>

      <div className="mt-5 border-t border-border pt-4 flex-1">
        <p className="font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground">
          {challenge.moduleTitle}
        </p>
        <p className="mt-1 text-h4">{challenge.lessonTitle}</p>
      </div>

      {dailyChallengeCompleted ? (
        <div className="mt-5 flex items-center gap-2 font-mono text-caption uppercase tracking-[0.12em] text-accent">
          <CheckCircle className="w-4 h-4" aria-hidden="true" />
          Challenge Complete!
        </div>
      ) : (
        <Link
          to={`/modules/${challenge.moduleId}/${challenge.lessonId}`}
          className="ui-button-secondary mt-5 self-start group"
        >
          Start Challenge
          <ArrowRight
            className="w-4 h-4 group-hover:translate-x-0.5 transition-transform"
            aria-hidden="true"
          />
        </Link>
      )}
    </motion.div>
  );
};
