# Design upgrade progress

Branch: `design/upgrade` (from `86464db`). Never merge to main from this work.
Dev server for screenshots: `pnpm dev --port 5199 --strictPort`.
Screenshot helper: `node design-research/tools/shoot.mjs <outDir> name=url ...` (env: `SCHEME=dark`, `FULL=0`, `WAIT=ms`; uses installed Chrome channel because the pinned Playwright browser build is missing).

Pre-existing uncommitted edits to `.husky/pre-commit` and `CLAUDE.md` belong to an earlier session. They are left unstaged on purpose.

## Phases

- [x] Phase 1: Understand the site (`profile.md`, `shots/before/`)
- [ ] Phase 2: Research (`references.md`, `features.md`)
- [ ] Phase 3: Decide (`plan.md`)
- [ ] Phase 4: Foundation + homepage
- [ ] Phase 5: Roll out to every template
- [ ] Phase 6: Verify
- [ ] Phase 7: Report

## Template tracker

| Template                             | Status  |
| ------------------------------------ | ------- |
| Dashboard `/`                        | pending |
| Modules `/modules`                   | pending |
| Lesson theory                        | pending |
| Lesson quiz                          | pending |
| Lesson lab                           | pending |
| Paths `/paths`                       | pending |
| Path detail                          | pending |
| CTF `/ctf`                           | pending |
| Reviews `/reviews`                   | pending |
| Leaderboard                          | pending |
| Profile                              | pending |
| Final exam `/challenge`              | pending |
| Privacy                              | pending |
| Auth modal / toasts / error boundary | pending |
