# Design upgrade progress

Branch: `design/upgrade` (from `86464db`). Never merge to main from this work.
Dev server for screenshots: `pnpm dev --port 5199 --strictPort`.
Screenshot helper: `node design-research/tools/shoot.mjs <outDir> name=url ...` (env: `SCHEME=dark`, `FULL=0`, `WAIT=ms`; uses installed Chrome channel because the pinned Playwright browser build is missing).

Pre-existing uncommitted edits to `.husky/pre-commit` and `CLAUDE.md` belong to an earlier session. They are left unstaged on purpose.

## Phases

- [x] Phase 1: Understand the site (`profile.md`, `shots/before/`)
- [x] Phase 2: Research (`references.md`, `features.md`)
- [x] Phase 3: Decide (`plan.md`)
- [x] Phase 4: Foundation + homepage
- [ ] Phase 5: Roll out to every template
- [ ] Phase 6: Verify
- [ ] Phase 7: Report

## Template tracker

| Template                             | Status                                                                                                                                                                                                                                                                                                     |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Dashboard `/`                        | done: 2 rounds; final scores POV 4.5, type 4.5, layout 4, color 4, motion 4, audience 4, memorability 4, craft 4                                                                                                                                                                                           |
| Modules `/modules`                   | done: URL-state filters (category, level, status, sort), random mission, time estimates, ruled rows; 2 rounds; all rubric items >= 4                                                                                                                                                                       |
| Lesson theory                        | done: owned prose styles (no typography plugin was installed, so prose classes did nothing), outline rail, Mermaid render bug fixed; 2 rounds                                                                                                                                                              |
| Lesson quiz                          | done: lettered options, inset signal states, verdict rule; 1 round + fixes                                                                                                                                                                                                                                 |
| Lesson lab                           | done: overlap bug fixed (Live Range moved below workspace), framed editor/terminal, signal Monaco/xterm themes, reference-fix debrief; 2 rounds                                                                                                                                                            |
| Paths `/paths`                       | done: track cards with route ticks, time and bonus XP, ruled header stats; 1 round + fixes                                                                                                                                                                                                                 |
| Path detail                          | done: route map with numbered stops, resume deep link to next lesson, time left, certification panel, EmptyState for unknown path; 1 round                                                                                                                                                                 |
| CTF `/ctf`                           | done: full-bleed board, URL `?challenge=` selection (palette deep links, back button), category and difficulty pills, markdown briefs, flag form moved above hints, inline hint confirm replaces window.confirm, signal terminal; fixed flag validation bug (no flag could be accepted); 2 rounds          |
| Reviews `/reviews`                   | done: "Intel Review" h1 matches nav, review-queue CTA with time estimate, ruled due list, honest empty states; 1 round + copy fixes                                                                                                                                                                        |
| Leaderboard                          | partial: unconfigured state rebuilt with h1 and local record (verified in browser); configured rankings list restyled but UNTESTED (no Supabase locally)                                                                                                                                                   |
| Profile                              | done: dossier header with real h1, clearance meter, stat row, numbered ruled sections (shared RuledSection), restyled heatmap (label collision fixed) and certificate (no stray h1); 2 rounds                                                                                                              |
| Final exam `/challenge`              | done: briefing start screen with rules and reward, sticky HUD with draining timer bar and question ticks, failure reason plus new Try again (verified in browser), win screen; 2 rounds                                                                                                                    |
| Privacy                              | done: ruled numbered disclosure, readable measure; 1 round                                                                                                                                                                                                                                                 |
| Auth modal / toasts / error boundary | done: AuthModal, ProfileEditModal, ReviewModal, ui/Modal, toasts, ErrorBoundary, PageLoader, IntelRefresher, NextBadgePreview, StatRing restyled (149 component tests pass). Auth and review modals not opened in a browser: auth needs Supabase, review needs a due-review completion (UNTESTED visually) |

## Phase 4 notes (2026-10-02)

- Tokens, fonts (Archivo condensed display), global classes rewritten in `src/index.css`; shell (Sidebar, Header with breadcrumb + palette trigger, footer) rebuilt.
- New: `CommandPalette` (Cmd/Ctrl+K, `/`), `RangeInstrument`, `RangeMark`, `RandomMission`, `src/lib/moduleMeta.ts` (time estimates, next lesson, status), `src/lib/paletteSearch.ts`, `src/data/roles.ts`.
- Header no longer renders an H1 (pages own their H1). Empty avatar placeholder removed when Supabase is not configured.
- Returning-learner screenshots: `STORAGE=design-research/tools/returning.json SUFFIX=-returning node design-research/tools/shoot.mjs ...`.
- Known flake: under full-suite load, 4 LessonView tests sometimes hit the 5s timeout; they pass in isolation (pre-existing, not caused by this work).

- 2026-10-02: machine load average ~79 during test runs; unit tests that lazy-load LabView time out at the 5s default. Verify with `pnpm exec vitest run --testTimeout=60000`. LessonView passes 25/25 that way.
- Fixed pre-existing bug: `MermaidDiagram` waited on a ref that only mounts after loading, so no diagram ever rendered.
- Live Range sections now hide entirely off localhost (`src/lib/liveRange.ts`); the dashboard section would otherwise be an empty disclosure in production.
- Fixed pre-existing bug: CTF flags were stored with `hashFlagSync` but checked with SHA-256 `validateFlag`, so every correct flag was rejected. The e2e test passed falsely because `/Correct/i` matched "Incorrect flag". Store now uses `validateFlagSync`; regression test in `gameStore.test.ts`; e2e assertion tightened.
- Heading base styles moved into `@layer base` so component classes like `.ui-label` apply to headings.
