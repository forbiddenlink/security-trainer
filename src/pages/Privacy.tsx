import React from "react";
import { Link } from "react-router-dom";

/**
 * Lightweight privacy + terms page. SecTrainer is a free educational project;
 * this describes what the app actually collects so the disclosure is honest,
 * not boilerplate.
 */
export const Privacy: React.FC = () => {
  return (
    <div className="max-w-3xl">
      <header className="pb-8">
        <p className="range-readout mb-3">
          <span className="range-dot" aria-hidden="true" />
          Plain-language disclosure
        </p>
        <h1 className="text-display">Privacy &amp; Terms</h1>
        <p className="mt-4 text-muted-foreground max-w-[60ch]">
          SecTrainer is a free, open-source security-training project. Here's
          exactly what it collects and how it's used.
        </p>
      </header>

      <section className="grid gap-2 border-t border-border py-6 sm:grid-cols-[3rem_minmax(0,1fr)]">
        <span
          className="font-mono text-caption tabular-nums text-muted-foreground pt-1"
          aria-hidden="true"
        >
          01
        </span>
        <div className="space-y-2">
          <h2 className="text-h3">What's stored in your browser</h2>
          <p className="text-muted-foreground max-w-[62ch]">
            Your progress (XP, levels, badges, streaks, completed lessons) is
            kept in this browser's local storage. If you don't create an
            account, it never leaves your device.
          </p>
        </div>
      </section>

      <section className="grid gap-2 border-t border-border py-6 sm:grid-cols-[3rem_minmax(0,1fr)]">
        <span
          className="font-mono text-caption tabular-nums text-muted-foreground pt-1"
          aria-hidden="true"
        >
          02
        </span>
        <div className="space-y-2">
          <h2 className="text-h3">If you create an account (optional)</h2>
          <p className="text-muted-foreground max-w-[62ch]">
            Authentication and cloud progress sync are handled by Supabase. We
            store your email, a display name, and your training progress so you
            can sync across devices. You can delete your account and stored data
            at any time from your{" "}
            <Link
              to="/profile"
              className="text-foreground underline decoration-primary decoration-2 underline-offset-4"
            >
              profile page
            </Link>
            .
          </p>
        </div>
      </section>

      <section className="grid gap-2 border-t border-border py-6 sm:grid-cols-[3rem_minmax(0,1fr)]">
        <span
          className="font-mono text-caption tabular-nums text-muted-foreground pt-1"
          aria-hidden="true"
        >
          03
        </span>
        <div className="space-y-2">
          <h2 className="text-h3">Analytics</h2>
          <p className="text-muted-foreground max-w-[62ch]">
            If analytics are enabled, anonymous product events (pages viewed,
            lessons started) are collected via PostHog to understand which
            material is useful. We honor your browser's Do-Not-Track and Global
            Privacy Control signals — if either is set, analytics never load.
          </p>
        </div>
      </section>

      <section className="grid gap-2 border-t border-border py-6 sm:grid-cols-[3rem_minmax(0,1fr)]">
        <span
          className="font-mono text-caption tabular-nums text-muted-foreground pt-1"
          aria-hidden="true"
        >
          04
        </span>
        <div className="space-y-2">
          <h2 className="text-h3">AI tutor</h2>
          <p className="text-muted-foreground max-w-[62ch]">
            The optional Socratic hint feature sends the challenge context
            you're working on to Groq to generate a hint. It does not send your
            account details.
          </p>
        </div>
      </section>

      <section className="grid gap-2 border-t border-border py-6 sm:grid-cols-[3rem_minmax(0,1fr)]">
        <span
          className="font-mono text-caption tabular-nums text-muted-foreground pt-1"
          aria-hidden="true"
        >
          05
        </span>
        <div className="space-y-2">
          <h2 className="text-h3">Terms</h2>
          <p className="text-muted-foreground max-w-[62ch]">
            SecTrainer is provided as-is, for educational purposes, with no
            warranty. Vulnerable code shown in lessons is intentional teaching
            material — don't run it against systems you don't own.
          </p>
        </div>
      </section>

      <p className="border-t border-border pt-6 text-body-sm text-muted-foreground">
        Questions or security reports:{" "}
        <a
          href="https://github.com/forbiddenlink/security-trainer/issues"
          target="_blank"
          rel="noopener noreferrer"
          className="text-foreground underline decoration-primary decoration-2 underline-offset-4"
        >
          open an issue on GitHub
        </a>
        .
      </p>
    </div>
  );
};
