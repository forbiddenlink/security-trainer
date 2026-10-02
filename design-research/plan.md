# Plan: SecTrainer design upgrade

Written against: `f310453` (design/upgrade, 2026-10-02). Frozen once Phase 4 starts; live state goes in `progress.md`.

## 1. Design direction: "Signal Range"

**Point of view.** SecTrainer is a calibrated instrument, not a SaaS dashboard. Every page reads like a field manual printed on a test card: hairline rules, a left label rail, monospace readouts, condensed headlines, and one signal color that only lights up where the learner should act. The current build gestures at "ops" with scattered labels (CLASSIFIED, OP-01) on generic rounded cards. The new system turns that gesture into a grammar: numbered sections, ruled panels, readouts, and reticle line art.

**References it draws from** (see `references.md`; main list is Siteinspire-confirmed):

- Whole Earth Index: structure from 1px rules and numbered cells instead of cards. Source of the numbered section grammar and the ruled module index.
- Beats in Space: dense metadata rows (IDs, durations, tags in small tabular caps) with one acid-yellow bar marking the active item. Source of the module row pattern and the single-signal-color rule.
- Pear: blueprint tick rail, crosshair markers, mono-caps CTAs. Source of the reticle mark, tick-ruler progress, and button labels.
- KieranTimberlake and CcType Foundry: hairline grids and label rails. Source of the left label rail.
- Bakken & Baeck: real technical artifacts (timelines, spec overlays) instead of illustration. Source of the range instrument in the hero.
- Supplementary (not gallery-confirmed, see references.md): Grilli Type test-card line art, Herzog & de Meuron two-tier filter pills, Ghostty framed terminal, CryptoHack/TryHackMe catalog density, Linear/Raycast command palette pattern.

**Type system**

- Display: Archivo, condensed width (`font-stretch: 75%`), weight 700 to 800, tight tracking (-0.02em). Mixed case for headings. It gives the stencilled field-manual voice without novelty fonts.
- Body: IBM Plex Sans (kept; already loaded, excellent technical legibility).
- Mono: IBM Plex Mono for labels, readouts, numbers, code. Labels are uppercase, 0.12em tracking, 11 to 12px.
- Scale (1.25 major third, body raised from 15 to 16px): display 64 (clamp 40 to 64), h1 44 (clamp 32 to 44), h2 30, h3 22, h4 18, body 16, body-sm 14, caption 12.

**Color.** Two themes, one grammar. Neutrals carry 95% of the surface; signal marks action and progress; alert marks vulnerabilities and errors.

- Dark ("night range", default when system is dark): ink `#0c0d0b`, panel `#121410`, rule `#2a2d26`, text `#ecebe4`, muted `#9a9a8f`, signal `#d7f75b` (acid chartreuse, text on it is ink), alert `#ff6a3d`, ok `#7ad69a`, info `#8fb8ff`.
- Light ("printed manual"): paper `#f3f2ec`, panel `#fbfbf7`, rule `#cfcdc2`, ink `#12130f`, muted `#5d5d54`, signal fill `#d7f75b` with ink text (buttons are ink with paper text; signal highlights progress and the active state), alert `#c2410c`, ok `#1f7a43`, info `#1d4ed8`.
- All text pairs checked for WCAG AA (4.5:1 body, 3:1 large and UI).

**Spacing and layout**

- 4px base; steps 4, 8, 12, 16, 24, 32, 48, 64, 96.
- Content max width 1240px. 12-column grid; on wide screens sections use a 3-column label rail (section number + mono label) and a 9-column body.
- Sections are separated by full-width 1px rules and numbered `01`, `02` in mono. Panels have 1px rules and 2px radius (instrument housing), not floating rounded cards with shadows.
- Mobile: rail collapses above the section, 16px gutters, no horizontal scroll, bottom-safe sticky actions in lessons.

**Imagery.** No stock photos, no gradients, no glow. Imagery is generated SVG line art in the reference style: reticles, tick rulers, signal bars, and a test-card "range instrument" in the hero that displays real numbers (modules, lessons, flags, paths). Line weight 1px, color = rule/muted, with one signal element.

**Motion rules**

- Purposeful only: progress bars fill, readout numbers settle, one scan line crosses the hero instrument once on load, panels reveal 8px up with 180ms ease-out.
- Durations 120 / 180 / 320ms; easing `cubic-bezier(0.2, 0.8, 0.2, 1)`. No bounce, no infinite loops except the live-status dot.
- `prefers-reduced-motion`: all reveals and the scan line disabled (MotionConfig already set to `user`; CSS gets a matching media query).

## 2. Feature list (ranked by impact on "start and finish a module")

| #   | Feature                                                                                                                                             | Peers with it                     | Approval?                                                                         |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- | --------------------------------------------------------------------------------- |
| 1   | First-mission handoff: new visitors get one primary CTA straight into lesson 1 of a recommended module (based on role pick when set)                | Duolingo, Brilliant               | no                                                                                |
| 2   | Time estimate and "you will cover" outline on every module card and lesson header, derived from lesson count, type and content length (no new data) | Snyk, Hacksplaining, HTB          | no                                                                                |
| 3   | Resume panel: returning learners see the exact next lesson, module progress, and one Continue button                                                | THM, HTB, Duolingo                | no                                                                                |
| 4   | Catalog filters: difficulty, status (new / in progress / done), sort; state kept in URL query params so links are shareable                         | Snyk, HTB, PortSwigger, Exercism  | no                                                                                |
| 5   | Command palette (Cmd/Ctrl+K and `/`) to jump to any module, path, CTF or page                                                                       | Linear, Raycast (product pattern) | no                                                                                |
| 6   | Lab debrief: after a lab is completed, reveal the reference fix (`solutionCode` already exists, unused in UI)                                       | THM, HTB, PortSwigger, Exercism   | no                                                                                |
| 7   | Random mission button on the catalog ("assign me something")                                                                                        | PortSwigger                       | no                                                                                |
| 8   | Fix lab layout bug: Live Range panel overlaps the editor at 1440x900                                                                                | n/a (bug)                         | no                                                                                |
| 9   | Single H1 per page (header currently renders an H1 plus the page H1) and route-aware document titles for all routes                                 | n/a (a11y)                        | no                                                                                |
| 10  | Social sign-in (GitHub/Google)                                                                                                                      | 6 of 10                           | **needs-approval** (Supabase provider config, OAuth keys)                         |
| 11  | OWASP Top 10 mapping and risk meters on module headers                                                                                              | Hacksplaining                     | **needs-approval** (new content claims per module; must be reviewed for accuracy) |
| 12  | Community write-ups / forum                                                                                                                         | 6 of 10                           | **needs-approval** (database tables, moderation)                                  |
| 13  | Team tier                                                                                                                                           | 7 of 10                           | out of scope (business model change)                                              |

## 3. Page-by-page plan

- **Shell (all pages):** new sidebar as an instrument rail (wordmark, numbered nav groups Learn / Practice / Record, status readout with level meter), header with breadcrumb instead of a duplicate H1, a palette trigger, compact level and streak readouts, real sign-in affordance or initials. New footer with rule and mono captions.
- **Dashboard `/`:** new-visitor hero (condensed headline, one primary CTA into the first lesson, secondary browse link, range instrument SVG with live counts), compact role calibration row. Returning: resume panel + readout strip (XP, level, missions, streak) in one ruled row. Then "Today" (daily challenge + review due) in two columns, next badge, achievements strip, live range collapsed into a disclosure.
- **Modules `/modules`:** section header with counts, search, two-tier filter chips (category outlined; difficulty and status filled), sort, random mission. Module rows as ruled entries: index number, title, difficulty, lesson mix, time estimate, progress meter, action.
- **Lesson (theory/quiz/lab):** sticky lesson bar with module title, step ticks, time left; theory body at 68ch measure with larger type; quiz options as lettered rows with clear correct/incorrect states; lab with fixed two-pane workspace (brief left, editor/terminal right) and Live Range moved below the workspace, debrief panel after completion.
- **Paths / Path detail:** paths as ruled route cards with stop count and total time; detail as a vertical route line with numbered stops and status.
- **CTF:** keep master/detail; restyle list rows as ruled entries with points readout; empty detail state uses the reticle illustration.
- **Reviews:** queue readout (due now / later), card-style review entries.
- **Leaderboard:** ruled table with mono ranks, current user highlighted with the signal, sign-in empty state.
- **Profile:** dossier layout: identity block in the rail, readouts, badge grid with earned badges prominent and locked ones as a compact tally, heatmap, certificate.
- **Final exam `/challenge`:** briefing screen, progress ticks, result screen with score readout.
- **Privacy:** long-form manual layout with label rail and 68ch measure.
- **States everywhere:** loading (skeletons shaped like the content), empty (reticle + one action), error (ErrorBoundary restyled with reload action), success (toasts restyled as readout slips).
