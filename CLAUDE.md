# Security Trainer

Gamified, hands-on cybersecurity training platform (spy/agent theme, XP,
levels, badges, streaks). 40+ modules covering OWASP Top 10, auth/session
flaws, injection, cloud/container/API security, compliance basics (GDPR,
HIPAA, PCI-DSS, SOC 2), phishing/social engineering, and AI security.
Live: https://security-trainer.vercel.app

## Stack

- Vite 8 + React 19 + React Router 7, TypeScript 6
- State: Zustand 5, persisted to localStorage
- Styling: Tailwind CSS 4
- Animation: Framer Motion; Editor: Monaco (`@monaco-editor/react`);
  Terminal: xterm.js; Diagrams: Mermaid
- Backend/auth: Supabase (`@supabase/supabase-js`)
- AI: Groq (`llama-3.1-8b-instant`) via a rate-limited serverless endpoint
  (`api/socratic-hint.ts`), rate-limited with `@upstash/ratelimit` +
  `@upstash/redis`
- Testing: Vitest + Testing Library (unit), Playwright (e2e)
- Analytics: PostHog (optional, respects Do-Not-Track / GPC)
- Lint/format: Prettier formats (husky/lint-staged runs it on commit) and
  ESLint lints. Biome 2 runs as a second linter only: its formatter and
  import sorting are off in `biome.json` so it never fights Prettier.
  `pnpm lint` and `pnpm biome:check` both pass with 0 errors.
- Fonts: self-hosted via `@fontsource` (Archivo variable, IBM Plex Sans and
  Mono), imported in `src/main.tsx`. No Google Fonts request.
- pnpm (`pnpm@10.34.5`)

## Commands

```bash
pnpm dev              # vite dev server
pnpm build            # tsc -b && vite build
pnpm lint             # eslint .
pnpm biome:check      # biome check .
pnpm biome:fix        # biome check . --write
pnpm preview          # vite preview
pnpm test             # vitest (watch)
pnpm test:run         # vitest run
pnpm test:coverage    # vitest run --coverage
pnpm test:e2e         # playwright test
```

The repo pins `packageManager: pnpm@10.34.5` and ships `pnpm-lock.yaml`; use pnpm (the stale
handoff doc that showed npm was removed 2026-09-19).

## Layout

- `src/components/`: reusable UI components
- `src/pages/`: route page components
- `src/layouts/`: layout wrappers
- `src/store/gameStore.ts`: Zustand state (XP, levels, badges, streaks)
- `src/data/modules/`: static lesson content (42 modules); each exports
  `theory`, `quiz`, or `lab` lesson types, added to `src/data/modules/index.ts`
- `src/types/`: TypeScript interfaces
- `src/utils/labVerification.ts`: statically-defined lab verification
  registry (no dynamic code execution)
- `src/data/owaspTop10.ts`: module to OWASP Top 10:2025 mapping. Only map a
  module when its core CWE is listed on that category's owasp.org page.
- `src/lib/`: external service clients (Supabase) and pure helpers with
  unit tests next to them: `moduleMeta` (time estimates, next lesson),
  `weeklyGoal` (rolling 7-day XP tiers), `rank` (field rank from modules
  and paths), `paletteSearch` (Cmd+K), `liveRange` (local Docker targets,
  localhost only)
- `design-research/`: the 2026-10 design upgrade (plan, report,
  before/after screenshots, `needs-approval.md`)
- `api/socratic-hint.ts`: serverless endpoint for the Socratic AI tutor
- `supabase/schema.sql`, `supabase/migrations/`: DB schema and migrations
- `e2e/`: Playwright specs

## Conventions

- Add a module: create a file in `src/data/modules/`, export it and add it
  to `index.ts`; if it has a lab, add a verifier to
  `src/utils/labVerification.ts` keyed by lab ID.
- Zustand: transient UI state (toasts) lives in the store but is excluded
  from persistence via `partialize`; trigger side effects (confetti,
  toasts) inside store actions, not React effects.
- Never add dynamic code execution for lab verification; use the
  registry pattern.
- Design system "Signal Range": tokens on `:root` in `src/index.css`;
  reuse `btn-signal` (the one primary action per screen), `btn-ghost-rule`,
  `filter-pill`, `ui-card`, `ui-chip`, `ui-label`, `range-readout` and the
  `RuledSection` component before writing new styles.
- Shareable view state lives in query params, not new routes:
  `/modules?q=&cat=&level=&status=&sort=`, `/ctf?challenge=&hide=solved`.
- New persisted store fields need a default in `INITIAL_STATE` and an entry
  in `partialize`; old saves load without them, so read them defensively.

## Env vars

Client (`VITE_` prefix, all optional, app runs with reduced functionality
without them):

- `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY`
- `VITE_POSTHOG_KEY`, `VITE_POSTHOG_HOST` (PostHog is loaded lazily)
- `VITE_AUTH_GITHUB`: set to `true` only after the GitHub provider is
  enabled in Supabase Auth; the GitHub sign-in button stays hidden otherwise

Server (`api/socratic-hint.ts`, the AI tutor endpoint):

- `GROQ_API_KEY`, `AI_DISABLED`, `AI_DAILY_BUDGET`
- `UPSTASH_REDIS_REST_URL`, `UPSTASH_REDIS_REST_TOKEN`
- `HINTS_ALLOW_NO_RATELIMIT`

`API_KEY`, `ENCRYPTION_KEY`, `VAULT_TOKEN` also appear in
`process.env.*` calls, but only inside `src/data/modules/*.ts` lesson
content and its tests: fake vulnerable-code examples for the lessons, not
real config.

## Gotchas

- `.gitleaks.toml` allowlists all of `src/data/**`: lesson/CTF content
  deliberately contains fake credentials (sample JWTs, API keys, demo
  flags) as teaching material. Do not "fix" these as real leaks.
- `pnpm.overrides` in `package.json` pins several transitive deps for
  security advisories (vite, rollup, undici, dompurify, etc.); check why
  before removing.
- CTF flags are stored as `hashFlagSync` digests and must be checked with
  `validateFlagSync`. Mixing in SHA-256 rejects every correct flag (this
  shipped once; `gameStore.test.ts` now guards it). In e2e, assert on exact
  success text ("Challenge Completed!"), because `/Correct/i` also
  matches "Incorrect flag".
- Mermaid, its parser and layout engines, and xterm must stay out of the
  eager `vendor` chunk (see `manualChunks` in `vite.config.ts`); forcing
  Mermaid into a named chunk causes a circular-import crash.
- Unit tests can time out on a loaded machine; use
  `pnpm exec vitest run --testTimeout=60000`.
