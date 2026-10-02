# Site profile: SecTrainer

Snapshot as of 2026-10-02, branch `design/upgrade` (from `86464db`).

## One sentence

SecTrainer is a free, browser-based, gamified trainer where developers learn application security by reading short briefings, answering quizzes, fixing vulnerable code in labs, and capturing CTF flags.

## Audience and main action

- **Who:** developers and CS students first (the role picker also offers DevOps/IT, managers, general staff). The content depth (code labs, OWASP, injection, JWT, SSRF) targets people who write code.
- **Main action:** start a module and finish it. Secondary: come back daily (streak, daily challenge, spaced-repetition review), climb levels, capture flags.
- **No signup needed.** Progress lives in localStorage; Supabase sign-in syncs it and enables the leaderboard.

## Unknowns (best reading used)

- No stated business model. Reading: free portfolio/education project by forbiddenlink. No pricing, no team plans.
- Real traffic and which pages convert: unknown (PostHog is optional and off without a key).
- Whether the Live Range docker targets are used in practice: unknown; they only work on localhost.
- Whether dark or light is the intended default: code follows system preference; `theme-color` meta defines both.

## Routes and templates (src/App.tsx)

All routes render inside `MainLayout` (sidebar + header + footer).

| Route                            | Template                                                          | File                                                  |
| -------------------------------- | ----------------------------------------------------------------- | ----------------------------------------------------- |
| `/`                              | Dashboard ("Mission Control")                                     | `src/pages/Dashboard.tsx`                             |
| `/modules`                       | Module catalog ("Active Operations") with search + category chips | `src/pages/Modules.tsx`                               |
| `/modules/:moduleId(/:lessonId)` | Lesson player: theory, quiz, lab variants                         | `src/pages/LessonView.tsx`, `src/components/lesson/*` |
| `/paths`                         | Learning paths list                                               | `src/pages/Paths.tsx`                                 |
| `/paths/:pathId`                 | Path detail                                                       | `src/pages/PathDetail.tsx`                            |
| `/ctf`                           | CTF master/detail board                                           | `src/pages/CTFChallenges.tsx`                         |
| `/reviews`                       | Spaced-repetition review ("Intel Review")                         | `src/pages/Reviews.tsx`                               |
| `/leaderboard`                   | Leaderboard                                                       | `src/pages/Leaderboard.tsx`                           |
| `/profile`                       | Agent profile, badges, heatmap, certificate                       | `src/pages/Profile.tsx`                               |
| `/challenge`                     | Final exam (sidebar label "Final Exam")                           | `src/pages/Challenge.tsx`                             |
| `/privacy`                       | Privacy and terms                                                 | `src/pages/Privacy.tsx`                               |
| `*`                              | Redirect to `/`                                                   |                                                       |

Overlays: `AuthModal`, `ProfileEditModal`, `ReviewModal`, `LevelUpToast`, `AchievementToast`, `ErrorBoundary` fallback, lazy `PageLoader` spinner.

## Shared components

- Shell: `Sidebar` (8 nav items + status card), `Header` (page title, level/XP pill, streak pill, theme toggle, avatar/auth), footer inline in `MainLayout`.
- Primitives (`src/components/ui`): Button, Card, Chip, EmptyState, Input, Modal, Progress, Skeleton.
- Domain: StatRing, StreakIndicator, BadgeList, NextBadgePreview, DailyChallenge, RoleSelector, PathCard, LiveLabTargets, ActivityHeatmap, IntelRefresher, Certificate, CodeEditor (Monaco), Terminal (xterm), MermaidDiagram, VideoEmbed (privacy-mode YouTube facade).
- Most styling flows through global classes in `src/index.css`: `ui-card` (46 uses), `ui-card-lg`, `ui-label`, `ui-chip`, `mission-card`, `ops-briefing`, `range-*`, `text-h1..h4`, `text-body-sm`, `text-caption`. Changing these tokens restyles the whole app.

## Design tokens today (src/index.css)

- Fonts: Space Grotesk (display), IBM Plex Sans (body), IBM Plex Mono (labels, numbers). Loaded from Google Fonts in `index.html`.
- Type scale: 40/32/24/20/16/15/13/11 px (minor third). Small: body is 15px, captions 11px.
- Light: warm "dossier paper" `#f4f1eb`, steel navy primary `#1e4a8c`, teal accent, brass stamp. Dark: near-black `#0b0d10`, brass primary `#c9a227`, phosphor green accent.
- Radius 4 to 16px, restrained shadows, 8px spacing scale, ease-out-quart motion, MotionConfig `reducedMotion="user"`.

## Content types

- Module (42 exported from `src/data/modules/index.ts`): id, title, difficulty, category, XP, lessons.
- Lesson: theory (59), quiz (75), lab (25). Labs verified by `src/utils/labVerification.ts` registry.
- Learning paths: 6. CTF challenges: 29 across categories. Badges: defined in `src/data/badges.ts`.

## Features and journeys

1. **First visit:** dashboard hero "Learn web security by doing", role picker, stats (0 XP), daily challenge, live range, achievements grid.
2. **Learn:** Modules catalog, search, chip filter, "Start Mission" card, lesson stepper (Step 1 of 3), theory with video facade and Mermaid, quiz, lab with Monaco + terminal + Socratic AI hints, complete mission, XP toast, badge toast.
3. **Paths:** pick a path, see ordered modules.
4. **Practice:** CTF board with category groups, filters, flag submission, hints.
5. **Retain:** daily challenge (+50 XP, countdown), Intel Review spaced repetition, streak with freezes.
6. **Prove:** final exam, certificate, profile badges, heatmap, leaderboard (needs sign-in).

## Observed issues in current build (from the before screenshots)

- Lab template: the Live Range panel overlaps the code editor on 1440x900 (`shots/before/lesson-lab-desktop.png`). Layout bug.
- Dashboard is a long stack of same-weight cards; hero, role picker, stats, daily challenge, live range and achievements all compete. No single primary action above the fold.
- Header avatar is an empty circle when signed out; the level pill container clips its progress bar.
- Type is small (15px body, 11px captions) and the page title in the header duplicates the H1.
- Locked badges render as eight near-identical grey lock tiles: low information, low motivation.
- The theme reads as "warm SaaS with ops labels" rather than a committed point of view; ops labels ("CLASSIFIED", "OP-01") are sprinkled without a system.

## Screenshots (before)

`design-research/shots/before/<template>-desktop.png`, `-desktop-full.png`, `-mobile.png` for: dashboard, modules, lesson-theory, lesson-quiz, lesson-lab, paths, path-detail, challenge, ctf, leaderboard, profile, reviews, privacy. Captured with headless Chrome at 1440x900 and 390x844 (system light scheme).
