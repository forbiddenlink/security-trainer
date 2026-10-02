# Design upgrade report

Snapshot as of 2026-10-02. Branch `design/upgrade`, written against `a385eac`. Base: `86464db` on `main`. Nothing is merged.

## Summary

SecTrainer now uses one visual system, "Signal Range": a calibrated instrument or field manual. It has:

- hairline rules and numbered sections
- Archivo condensed display type over IBM Plex Sans and Plex Mono
- one lime signal color for the single primary action on each screen

The redesign covers every route, the app shell, overlays and toasts. Each change traces to `plan.md`.

Two pre-existing functional bugs were found and fixed along the way:

1. **CTF flags could never be accepted.** Challenges store a `hashFlagSync` digest, but submission compared against SHA-256. The e2e test hid the bug because `/Correct/i` also matches "Incorrect flag".
2. **Mermaid diagrams never rendered.** The render effect waited on a ref that only mounts after loading finishes, so it never ran.

## Before and after

All screenshots come from real Chrome via `design-research/tools/shoot.mjs`: desktop at 1440x900, mobile at 390x844. Before shots are in `shots/before/` and after shots are in `shots/after/`. Files marked `-returning` use a seeded learner (`tools/returning.json`).

| Template      | Before                             | After                                                                                               |
| ------------- | ---------------------------------- | --------------------------------------------------------------------------------------------------- |
| Dashboard     | `before/dashboard-desktop.png`     | `after/dash-desktop.png`, `after/dashboard-desktop-returning-full.png`                              |
| Modules       | `before/modules-desktop.png`       | `after/modules-desktop.png`, `after/modules-filtered-mobile-dark.png`                               |
| Lesson theory | `before/lesson-theory-desktop.png` | `after/lesson-theory-desktop.png`, `after/lesson-theory-desktop-full.png`                           |
| Lesson quiz   | `before/lesson-quiz-desktop.png`   | `after/lesson-quiz-desktop.png`, `after/lesson-quiz-mobile.png`                                     |
| Lesson lab    | `before/lesson-lab-desktop.png`    | `after/lesson-lab-desktop.png`, `after/lesson-lab-desktop-dark.png`                                 |
| Paths         | `before/paths-desktop.png`         | `after/paths-desktop.png`, `after/paths-desktop-dark-returning.png`                                 |
| Path detail   | `before/path-detail-desktop.png`   | `after/path-detail-desktop.png`, `after/path-detail-desktop-dark-returning.png`                     |
| CTF           | `before/ctf-desktop.png`           | `after/ctf-detail-desktop.png`, `after/ctf-desktop-dark.png`                                        |
| Intel Review  | `before/reviews-desktop.png`       | `after/reviews-desktop-returning.png`, `after/reviews-mobile.png`                                   |
| Leaderboard   | `before/leaderboard-desktop.png`   | `after/leaderboard-desktop-returning.png`                                                           |
| Profile       | `before/profile-desktop.png`       | `after/profile-desktop-returning-full.png`, `after/profile-desktop-dark.png`                        |
| Final exam    | `before/challenge-desktop.png`     | `after/challenge-desktop.png`, `after/challenge-run-desktop.png`, `after/challenge-end-desktop.png` |
| Privacy       | `before/privacy-desktop.png`       | `after/privacy-desktop.png`, `after/privacy-mobile.png`                                             |

## Features added

None of these needed approval. Each one reuses existing data, with no new services, keys or migrations.

1. **First-mission handoff.** The new-visitor hero links straight to the first lesson of the role's recommended path.
2. **Resume panel.** Returning learners get the next lesson, a progress bar and the time left.
3. **Time estimates and a "Covers" line.** Estimates are derived from content: 200 words per minute for theory, 2 minutes per quiz, 10 minutes per lab. They appear on modules, paths, path routes, the lesson bar and the review queue.
4. **Catalog filters kept in the URL.** Category, level, status and sort live in query params, so filtered views can be shared and restored. These are query params only; no route changed.
5. **Command palette.** Opens with Cmd/Ctrl+K or `/`. It searches pages, modules, paths and CTF challenges and deep-links to `?challenge=`.
6. **Random mission.** Available on the dashboard and the catalog.
7. **Lab debrief.** After a passing patch, a disclosure shows the reference fix. `solutionCode` already existed in the data, but the old UI never showed it.
8. **Lab overlap fix.** The workspace is now a fixed two-pane frame, and the Live Range panel sits below it.
9. **One h1 per page.** The header became a breadcrumb, and markdown `# Title` now renders as an h2.
10. **CTF board improvements.**
    - The selected challenge is stored in the URL, so the back button closes the detail view on mobile.
    - The flag form moved above the hints.
    - An inline confirm replaces the blocking `window.confirm` before a hint spends points.
11. **Final exam.**
    - The fail screen says whether the clock or a wrong answer ended the run.
    - A new "Try again" button starts a run with fresh questions.
    - The HUD shows a draining timer bar and question ticks.
12. **Review queue.** A "Start review queue" button and a time estimate are added. Empty states no longer claim "all fresh" to someone with no reviews.
13. **Leaderboard without Supabase.** It shows the learner's local record instead of a dead end.
14. **Live Range panels hidden off localhost.** In production they were dead `http://localhost` links.
15. **Path detail.** A route map with numbered stops, a resume link to the exact next lesson, and a certification panel.

## Rubric scores

These scores are my own assessment from screenshot review. That is rung 1 evidence: a judgment, not a measurement. Every template got at least one fix round, and each item scored under 4 was reworked before I moved on.

Columns: POV = point of view; Layout = layout and rhythm; Color = color and imagery; Audience = audience fit; Memory = memorability.

| Template      | POV | Type | Layout | Color | Motion | Audience | Memory | Craft |
| ------------- | --- | ---- | ------ | ----- | ------ | -------- | ------ | ----- |
| Dashboard     | 4.5 | 4.5  | 4      | 4     | 4      | 4        | 4      | 4     |
| Modules       | 4   | 4.5  | 4      | 4     | 4      | 4.5      | 4      | 4     |
| Lesson theory | 4   | 4.5  | 4      | 4     | 4      | 4.5      | 4      | 4     |
| Lesson quiz   | 4   | 4.5  | 4      | 4     | 4      | 4        | 4      | 4     |
| Lesson lab    | 4.5 | 4    | 4      | 4.5   | 4      | 4.5      | 4.5    | 4     |
| Paths         | 4   | 4.5  | 4      | 4     | 4      | 4        | 4      | 4     |
| Path detail   | 4.5 | 4.5  | 4.5    | 4     | 4      | 4.5      | 4      | 4     |
| CTF           | 4   | 4    | 4.5    | 4     | 4      | 4.5      | 4      | 4     |
| Intel Review  | 4   | 4.5  | 4      | 4     | 4      | 4        | 4      | 4     |
| Leaderboard   | 4   | 4.5  | 4      | 4     | 4      | 4        | 4      | 4     |
| Profile       | 4   | 4.5  | 4      | 4     | 4      | 4        | 4      | 4     |
| Final exam    | 4.5 | 4.5  | 4      | 4     | 4      | 4        | 4.5    | 4     |
| Privacy       | 4   | 4.5  | 4      | 4     | 4      | 4        | 4      | 4     |

All motion respects `prefers-reduced-motion` through `MotionConfig reducedMotion="user"` and the CSS guards.

## Verification (Phase 6)

| Check                  | Result                                                                                                                                                                                                   |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pnpm build`           | Pass. The only warning is chunk size, which existed before.                                                                                                                                              |
| `tsc -b`               | Clean                                                                                                                                                                                                    |
| `pnpm lint`            | 0 errors. 2 warnings in `Terminal.tsx`, which existed before.                                                                                                                                            |
| `pnpm biome:check`     | **Fails before it checks any file.** `biome.json` uses `organizeImports` and `ignore`, which the installed Biome 1.9.4 rejects. The tree before this work fails the same way (checked with `git stash`). |
| Unit tests             | 27 files, 391 tests pass. The run needs `--testTimeout=60000` because the machine's load average was about 79.                                                                                           |
| E2E tests              | 12/12 pass, in two consecutive runs                                                                                                                                                                      |
| Lighthouse, mobile `/` | Performance 0.61, accessibility 0.97, best practices 0.96, SEO 1.00. Production with the old design scored 0.60 and 0.96 under the same throttling.                                                      |
| Lighthouse, desktop    | `/modules` 0.56 and 0.97; lesson 0.55 and 0.96; CTF 0.56 and 0.96 (performance and accessibility)                                                                                                        |

Simulated FCP is a flat 6.0s on every route, but a real unthrottled load measured 239ms. The simulated number comes from two things production also has:

- the render-blocking Google Fonts stylesheet
- the shared lesson-content chunk

I clicked through these journeys in Chrome:

- Dashboard first mission, then theory to quiz. A quiz answer unlocks Next. The lab deploy shows a verdict.
- Command palette with Ctrl+K, Cmd+K and `/`; Enter navigates.
- Catalog filters restore from the URL.
- The path start link opens the first lesson.
- On mobile, the drawer opens CTF; selecting a challenge and pressing back closes the detail view.
- A CTF hint confirm, then a solve.
- A final exam fail, then a retry.
- The theme toggle.

The only console errors were the localhost Live Range probes (`ERR_CONNECTION_REFUSED`). That is expected when the Docker lab is not running.

## Blocked or untested

- **Leaderboard with Supabase.** The rankings list is restyled, but I could not run it because no Supabase is configured locally.
- **AuthModal and ProfileEditModal.** Restyled and covered by component tests, but I never opened them in a browser; they need Supabase.
- **ReviewModal.** Restyled and covered by tests, but not seen in a browser. It only opens when a due review is completed.
- **ErrorBoundary.** Restyled, but I did not trigger it in a browser.
- **Biome.** Its config is broken in a way unrelated to this work. I did not fix it because tooling config is out of scope.
- **Performance.** Unchanged from production. The biggest win would be self-hosting the three font families and preloading them, which drops the render-blocking third-party stylesheet. That is a non-destructive follow-up and was not done.

## Needs approval (full list)

None of these were done. The same list is in `needs-approval.md`.

1. **Social sign-in (GitHub, Google).** Needs Supabase OAuth provider config and new client IDs and secrets.
2. **OWASP Top 10 mapping and risk meters per module.** These add factual claims that need a human accuracy review.
3. **Community write-ups per lab or CTF.** Needs new tables, moderation and abuse handling.
4. **Team or business tier.** A business-model and billing change.
5. **Merge `design/upgrade` into `main`.** `main` deploys to production.
