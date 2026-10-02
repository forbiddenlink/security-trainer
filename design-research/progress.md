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

| Template                             | Status                                                                                                           |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| Dashboard `/`                        | done: 2 rounds; final scores POV 4.5, type 4.5, layout 4, color 4, motion 4, audience 4, memorability 4, craft 4 |
| Modules `/modules`                   | pending                                                                                                          |
| Lesson theory                        | pending                                                                                                          |
| Lesson quiz                          | pending                                                                                                          |
| Lesson lab                           | pending                                                                                                          |
| Paths `/paths`                       | pending                                                                                                          |
| Path detail                          | pending                                                                                                          |
| CTF `/ctf`                           | pending                                                                                                          |
| Reviews `/reviews`                   | pending                                                                                                          |
| Leaderboard                          | pending                                                                                                          |
| Profile                              | pending                                                                                                          |
| Final exam `/challenge`              | pending                                                                                                          |
| Privacy                              | pending                                                                                                          |
| Auth modal / toasts / error boundary | pending                                                                                                          |

## Phase 4 notes (2026-10-02)

- Tokens, fonts (Archivo condensed display), global classes rewritten in `src/index.css`; shell (Sidebar, Header with breadcrumb + palette trigger, footer) rebuilt.
- New: `CommandPalette` (Cmd/Ctrl+K, `/`), `RangeInstrument`, `RangeMark`, `RandomMission`, `src/lib/moduleMeta.ts` (time estimates, next lesson, status), `src/lib/paletteSearch.ts`, `src/data/roles.ts`.
- Header no longer renders an H1 (pages own their H1). Empty avatar placeholder removed when Supabase is not configured.
- Returning-learner screenshots: `STORAGE=design-research/tools/returning.json SUFFIX=-returning node design-research/tools/shoot.mjs ...`.
- Known flake: under full-suite load, 4 LessonView tests sometimes hit the 5s timeout; they pass in isolation (pre-existing, not caused by this work).
