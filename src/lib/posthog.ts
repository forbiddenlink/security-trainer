import posthog from "posthog-js";

let initialized = false;

/**
 * Respect the visitor's browser privacy signal. If Do-Not-Track or Global
 * Privacy Control is set we do not load analytics at all — no PostHog script,
 * no cookies, no pageview. This is the minimum for EU/CA visitors; a full
 * consent banner (opt-in) would layer on top of this.
 */
function privacySignalOptsOut(): boolean {
  const nav = navigator as Navigator & { globalPrivacyControl?: boolean };
  return (
    nav.doNotTrack === "1" ||
    (nav as unknown as { doNotTrack?: string }).doNotTrack === "yes" ||
    (window as unknown as { doNotTrack?: string }).doNotTrack === "1" ||
    nav.globalPrivacyControl === true
  );
}

export function initPostHog(): void {
  if (initialized || typeof window === "undefined") return;
  if (privacySignalOptsOut()) return;

  const key = import.meta.env.VITE_POSTHOG_KEY;
  const host = import.meta.env.VITE_POSTHOG_HOST || "https://us.i.posthog.com";

  if (key) {
    posthog.init(key, {
      api_host: host,
      person_profiles: "identified_only",
      capture_pageview: true,
      capture_pageleave: true,
      persistence: "localStorage+cookie",
      autocapture: {
        dom_event_allowlist: ["click", "submit"],
        element_allowlist: ["button", "a"],
      },
    });
    initialized = true;
  }
}

// Security training analytics events
export const trackSecurityEvent = {
  lessonStarted: (moduleId: string, lessonId: string, lessonType: string) => {
    posthog.capture("lesson_started", {
      module_id: moduleId,
      lesson_id: lessonId,
      lesson_type: lessonType,
    });
  },

  lessonCompleted: (moduleId: string, lessonId: string, xpEarned: number) => {
    posthog.capture("lesson_completed", {
      module_id: moduleId,
      lesson_id: lessonId,
      xp_earned: xpEarned,
    });
  },

  quizAnswered: (lessonId: string, correct: boolean, questionIndex: number) => {
    posthog.capture("quiz_answered", {
      lesson_id: lessonId,
      correct,
      question_index: questionIndex,
    });
  },

  labAttempted: (lessonId: string, success: boolean, attempts: number) => {
    posthog.capture("lab_attempted", {
      lesson_id: lessonId,
      success,
      attempts,
    });
  },

  moduleCompleted: (moduleId: string, totalXp: number) => {
    posthog.capture("module_completed", {
      module_id: moduleId,
      total_xp: totalXp,
    });
  },

  badgeEarned: (badgeId: string, badgeName: string) => {
    posthog.capture("badge_earned", {
      badge_id: badgeId,
      badge_name: badgeName,
    });
  },

  levelUp: (newLevel: number, totalXp: number) => {
    posthog.capture("level_up", {
      new_level: newLevel,
      total_xp: totalXp,
    });
  },

  struggleDetected: (moduleId: string, lessonId: string, failCount: number) => {
    posthog.capture("struggle_detected", {
      module_id: moduleId,
      lesson_id: lessonId,
      fail_count: failCount,
    });
  },

  missionBriefingPlayed: (moduleId: string) => {
    posthog.capture("mission_briefing_played", {
      module_id: moduleId,
    });
  },
};

export { posthog };
