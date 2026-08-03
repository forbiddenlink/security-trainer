import React from "react";
import { Link } from "react-router-dom";

/**
 * Lightweight privacy + terms page. SecTrainer is a free educational project;
 * this describes what the app actually collects so the disclosure is honest,
 * not boilerplate.
 */
export const Privacy: React.FC = () => {
  return (
    <div className="max-w-3xl mx-auto space-y-6 animate-in fade-in duration-500">
      <div>
        <h1 className="text-h1 mb-2">Privacy &amp; Terms</h1>
        <p className="text-muted-foreground text-body-sm">
          SecTrainer is a free, open-source security-training project. Here's
          exactly what it collects and how it's used.
        </p>
      </div>

      <section className="ui-card ui-card-lg space-y-3">
        <h2 className="text-h4">What's stored in your browser</h2>
        <p className="text-body-sm text-muted-foreground">
          Your progress (XP, levels, badges, streaks, completed lessons) is kept
          in this browser's local storage. If you don't create an account, it
          never leaves your device.
        </p>
      </section>

      <section className="ui-card ui-card-lg space-y-3">
        <h2 className="text-h4">If you create an account (optional)</h2>
        <p className="text-body-sm text-muted-foreground">
          Authentication and cloud progress sync are handled by Supabase. We
          store your email, a display name, and your training progress so you
          can sync across devices. You can delete your account and stored data
          at any time from your{" "}
          <Link to="/profile" className="text-primary hover:underline">
            profile page
          </Link>
          .
        </p>
      </section>

      <section className="ui-card ui-card-lg space-y-3">
        <h2 className="text-h4">Analytics</h2>
        <p className="text-body-sm text-muted-foreground">
          If analytics are enabled, anonymous product events (pages viewed,
          lessons started) are collected via PostHog to understand which
          material is useful. We honor your browser's Do-Not-Track and Global
          Privacy Control signals — if either is set, analytics never load.
        </p>
      </section>

      <section className="ui-card ui-card-lg space-y-3">
        <h2 className="text-h4">AI tutor</h2>
        <p className="text-body-sm text-muted-foreground">
          The optional Socratic hint feature sends the challenge context you're
          working on to Groq to generate a hint. It does not send your account
          details.
        </p>
      </section>

      <section className="ui-card ui-card-lg space-y-3">
        <h2 className="text-h4">Terms</h2>
        <p className="text-body-sm text-muted-foreground">
          SecTrainer is provided as-is, for educational purposes, with no
          warranty. Vulnerable code shown in lessons is intentional teaching
          material — don't run it against systems you don't own.
        </p>
      </section>

      <p className="text-caption text-muted-foreground">
        Questions or security reports:{" "}
        <a
          href="https://github.com/forbiddenlink/security-trainer/issues"
          target="_blank"
          rel="noopener noreferrer"
          className="text-primary hover:underline"
        >
          open an issue on GitHub
        </a>
        .
      </p>
    </div>
  );
};
