# Session: security-trainer-design-build

Updated: 2026-07-29T21:48:00-04:00

## Goal

Expert-level spy/ops visual language + ship remaining product roadmap. Done when paths work, labs have tutor, modules searchable, CTF mobile-ready, live lab targets linked, e2e expanded, Socratic API available.

## State

- Done (this mega-pass):
  - Design token overhaul + anti-slop polish
  - Path ID fixes; RoleSelector deep-links; Sidebar clearance + Intel Review
  - Socratic tutor in LabView + lab-specific terminal
  - Modules search + per-lesson progress bars
  - UI primitives: Chip, EmptyState, Skeleton, Modal
  - CTF mobile master-detail + ops-grid empty state
  - LiveLabTargets → Dashboard, LessonView, web CTFs (ports 3333/3334/3335)
  - Mermaid+video on IDOR, JWT, path traversal, SSRF, cmdi, session
  - `/api/socratic-hint` (Vercel) + Vite middleware; GROQ_API_KEY in .env.example
  - e2e/flows.spec.ts expanded
  - 353 unit tests passing
  - AUDIT PASS 2026-08-02: e2e VERIFIED GREEN (12/12, 7.7s). Fixed:
    - useSocraticTutor 2 eslint errors (ref-in-render + setState-in-effect) → lint 0 errors
    - playwright webServer IPv6 bug (bound ::1, polled 127.0.0.1 → 120s timeout, 0 tests) → `pnpm exec vite preview --host`
    - API input caps: prompt ≤4000, dev body ≤16KB, output clamped (api/socratic-hint.ts + vite.socratic-plugin.ts)
    - LiveLabTargets: gate probe to localhost (prod mixed-content = always "Offline") → shows "Local"
    - Modal: useId() for aria-describedby (was hardcoded dup id)
    - CLAUDE.md module count 24→42; removed dead eslint-disable in LabView
- Now: All green (tests 353, e2e 12, tsc clean, lint 0-err, build OK). Uncommitted, ready to commit.
- Next (decisions for Liz):
  1. 🔴 /api/socratic-hint STILL has no rate limit — open Groq proxy. Add Upstash/Vercel KV limiter before real key ships to prod.
  2. Merge remote branches: dependabot ×2, release-please. Delete stale backup-local-24f3c0d.
  3. Commit the mega-pass (use /commit).
  4. (polish) Wire Modal into AuthModal; path certificates; more mermaid.

## Working Set

- Key: `src/pages/Modules.tsx`, `LabView.tsx`, `CTFChallenges.tsx`, `LiveLabTargets.tsx`, `api/socratic-hint.ts`, `e2e/flows.spec.ts`
- Companion: `../security-lab` docker compose
- Test: `pnpm test:run` · E2E: `pnpm test:e2e` · Dev: `pnpm dev`
