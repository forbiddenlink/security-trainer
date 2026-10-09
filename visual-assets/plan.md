# Visual Assets Plan: SecTrainer (Signal Range)

## 1. Context and Visual Direction

SecTrainer uses the "Signal Range" visual design system: a calibrated field manual and instrument aesthetic.
Key principles:

- Calibrated neutrals: deep field dark (`#0c0d0b`, `#121410`, `#2c2f27`) and paper light (`#f3f2ec`, `#fbfbf7`, `#cfcdc2`).
- Electric lime signal accent (`#d7f75b` / `var(--color-signal)`): reserved for primary actions, cleared states, and telemetry quadrant.
- Brand mark: `RangeMark`, a 32x32 reticle with crosshairs, concentric target rings, and a signal quadrant.
- Typography: Archivo condensed bold headings with IBM Plex Sans and IBM Plex Mono.
- Hairline rules and instrument housings instead of generic rounded pill cards.

## 2. Asset Inventory and Action Plan

### Asset 1: Vector Favicon (`public/favicon.svg`)

- Current status: Outdated generic blue/emerald gradient shield with keyhole.
- Action: Replace with the official `RangeMark` reticle brand mark.
- Enhancements: Add CSS media query for `prefers-color-scheme` so strokes adapt to dark and light browser chrome while retaining the electric lime signal quadrant (`#d7f75b`).
- Consumers: Modern desktop and mobile browsers via `<link rel="icon" type="image/svg+xml" href="/favicon.svg" />`.

### Asset 2: Raster App Icons and Favicons (`public/favicon-*.png`, `public/icon-*.png`, `public/apple-touch-icon.png`)

- Files:
  - `public/favicon-16x16.png` (16x16)
  - `public/favicon-32x32.png` (32x32)
  - `public/favicon.png` (64x64)
  - `public/apple-touch-icon.png` (180x180)
  - `public/icon-192.png` (192x192)
  - `public/icon-512.png` (512x512)
  - `public/icon.png` (512x512)
- Current status: Outdated neon green circuit shield in a glassy squircle.
- Action: Replace with high-precision renders of the `RangeMark` instrument reticle on calibrated dark background (`#0c0d0b`) with hairline concentric rings and `#d7f75b` signal quadrant.

### Asset 3: Social Preview Image (`public/og-image.png`)

- Current status: 594KB bloated PNG with blurry cyan lens flares, rounded terminal `>_` prompt, and outdated 2024 neon styling.
- Action: Replace with a pristine 1200x630 OpenGraph / Twitter card adhering strictly to the Signal Range system:
  - Background: Deep field slate (`#0c0d0b`) with hairline grid and coordinate ticks.
  - Header: RangeMark emblem and `SECTRAINER // FIELD MANUAL & RANGE`.
  - Core message: Condensed bold title "Break it here. Fix it at work."
  - Platform metrics readout: "42 MODULES · 255 LESSONS · 41 CODE LABS · 29 CTF FLAGS".
  - Signal accent: Lime highlight pill for "HANDS-ON CYBERSECURITY TRAINING".
  - Optimization: Crisp PNG under 120KB (over 75% file size reduction).

### Asset 4: Offline Fallback Page (`public/offline.html`)

- Current status: Blue `#3b82f6` rounded button and generic typography.
- Action: Align with the Signal Range system:
  - RangeMark emblem header.
  - Monospace diagnostic badge `STATUS: SATELLITE LINK LOST // LOCAL CACHE ACTIVE`.
  - Archivo headline and field manual copy.
  - Lime signal retry button (`#d7f75b`).

### Asset 5: Service Ribbons and Achievement Badges (`src/components/BadgeList.tsx` and `src/components/NextBadgePreview.tsx`)

- Current status: Every unlocked badge renders the exact same generic `Award` ribbon icon, ignoring `badge.icon`.
- Action: Introduce tactical badge iconography mapping each achievement (`Database`, `Code`, `Flag`, `Skull`, `Crown`, `Target`, `Trophy`) with lime signal badge styling for unlocked states and tactical dashed frame for locked states.

### Asset 6: Learning Path Track Insignias (`src/components/PathCard.tsx`)

- Current status: All 6 tracks show plain text without their configured path icons (`Shield`, `Server`, `Target`, `Users`, `FileCheck`, `Cloud`).
- Action: Render a tactical track insignia icon alongside "Track 01" to provide immediate visual identity for each track.

### Asset 7: Calibrated Empty States (`src/components/ui/EmptyState.tsx`)

- Current status: Rounded pill bubble with generic mail `Inbox` icon, conflicting with the instrument design system.
- Action: Redesign with a calibrated instrument housing, hairline corner brackets, and a reticle/radar target icon.

### Asset 8: CTF Target Range Visual (`src/pages/CTFChallenges.tsx`)

- Current status: Large empty right pane when no challenge is selected.
- Action: Add a subtle tactical radar/target reticle visual element matching `RangeInstrument` to ground the CTF range experience.
