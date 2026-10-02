# SecTrainer design references (Phase 2A)

Snapshot 2026-10-02. 13 live sites screenshotted at 1440x900 and 390x844 (shots in `shots/refs/<slug>-desktop.png` and `-mobile.png`) and the desktop shot viewed. Source note: the 5 out-of-industry sites came from the `inspo` archive (a screenshot index of shipped sites). The 8 in-industry sites are picks from the devtools and security-training canon; I did not verify them against Awwwards, Godly, SiteInspire or Land-book listings, so treat "source" as "inspo" or "curated". Mobile shots were captured but not reviewed.

## Out of industry

### 1. Grilli Type (type foundry)

- URL: https://grillitype.com | Source: inspo | Industry: type foundry | Out
- Shots: `shots/refs/grilli-desktop.png`, `grilli-mobile.png`
- Hero is a technical test-card diagram: thin olive and pink line art, tiny mono labels ("LOOKING FOR SIGNAL"), progress bars, crosshair circles. This is the best "mission control" illustration language seen: schematic, not skeuomorphic.
- Left label column ("Retail typefaces") beside a content column, divided by 1px rules. A ready Swiss grid for lesson and dossier pages.
- Type-specimen rows with hairline dividers work as a module list.
- Do not copy: the white background and the olive and pink palette. Take the line-art vocabulary into dark mode.

### 2. Herzog & de Meuron (architecture)

- URL: https://herzogdemeuron.com | Source: inspo | Industry: architecture | Out
- Shots: `shots/refs/herzog-desktop.png`, `herzog-mobile.png`
- Monospace body and UI text ("Search for something...") with a heavy grotesk wordmark. Mono is used for everything functional, tastefully.
- Pill filter chips in two tiers: outlined (primary sections) and filled gray (secondary). Direct fit for module category filters (OWASP, Cloud, AI).
- A single acid-yellow ticker bar at the bottom is the only accent. One loud element on a calm page.
- Do not copy: image-led layout. SecTrainer has no photography.

### 3. Construction Desourdy (construction)

- URL: https://www.constructiondesourdy.com/en/services | Source: inspo | Industry: construction | Out
- Shots: `shots/refs/desourdy-desktop.png`, `desourdy-mobile.png`
- Oversized black grotesk display at 3 lines, tight leading, hairline rule, then a two-column split with a vertical divider. Strong page-title pattern for path and module headers.
- Small bold section labels ("Services", "Construction") pinned to column edges like form-field captions, which suits a dossier look.
- Do not copy: scale. Hero-size type would eat the dashboard fold.

### 4. Heatherwick Studio (architecture)

- URL: https://heatherwick.com | Source: inspo | Industry: architecture | Out
- Shots: `shots/refs/heatherwick-desktop.png`, `heatherwick-mobile.png`
- Light high-contrast serif wordmark over a darkened full-bleed image, tiny letterspaced caps nav (PROJECTS STUDIO / SEARCH). Shows how a serif display can sit on dark with restraint.
- Idea for the classified feel: serif title plus tracked mono caps for metadata.
- Do not copy: the full-bleed video hero. It is content-free for an app.

### 5. Thrill Jockey (music label)

- URL: https://thrilljockey.com | Source: inspo | Industry: music | Out
- Shots: `shots/refs/thrilljockey-desktop.png`, `thrilljockey-mobile.png`
- Dense uniform cover grid, bold sans captions, section headers in caps ("PRE-ORDERS", "OUT NOW"). A model for a badge or module catalogue: equal tiles, one-line captions, no card chrome.
- Do not copy: bright blue logotype, white page, thin hierarchy between tiles.

## In industry (devtools, security, education)

### 6. Linear

- URL: https://linear.app | Source: curated | Industry: devtools | In
- Shots: `shots/refs/linear-desktop.png`, `linear-mobile.png`
- Near-black page with the real app UI shown in a framed panel: left nav, issue title, properties column, activity feed. Shows dashboard density without clutter; low-contrast gray hierarchy (3 text tones).
- Status icons carry meaning without color overload (amber half-circle for in-progress). Use for lab and module state.
- Do not copy: product screenshot as hero. SecTrainer should be the app.

### 7. Raycast

- URL: https://www.raycast.com | Source: curated | Industry: devtools | In
- Shots: `shots/refs/raycast-desktop.png`, `raycast-mobile.png`
- Single saturated red on near-black, with a monospace install line ("Install via Homebrew") under the CTA. Mono microcopy as a trust cue.
- Do not copy: the glowing diagonal gradient hero. That is the generic effect this brief avoids.

### 8. Ghostty

- URL: https://ghostty.org | Source: curated | Industry: terminal emulator | In
- Shots: `shots/refs/ghostty-desktop.png`, `ghostty-mobile.png`
- Hero is a real terminal window (traffic lights, title bar) with an ASCII logo in two colors. The most tasteful terminal aesthetic found: one framed window, nothing else, quiet outlined buttons.
- Use for the briefing intro or empty states: ASCII crest in a window frame.
- Do not copy: the full-page sparseness. A dashboard needs density.

### 9. CryptoHack

- URL: https://cryptohack.org | Source: curated | Industry: security training | In
- Shots: `shots/refs/cryptohack-desktop.png`, `cryptohack-mobile.png`
- Closest direct competitor to the product shape. Monospace caps for nav and headings, persistent left rail with icons, a live "Recent solves" table (user, time) on the right. Live activity feeds make gamified platforms feel populated.
- Single warm yellow-orange on navy.
- Do not copy: the cartoon mascots and flat sticker illustration; they clash with a spy theme.

### 10. TryHackMe

- URL: https://tryhackme.com | Source: curated | Industry: security training | In
- Shots: `shots/refs/tryhackme-desktop.png`, `tryhackme-mobile.png`
- Icon-over-label top nav (Learn, Practice, Compete) maps cleanly to learning paths and CTF. Lime CTA on navy is high contrast and readable.
- Do not copy: astronaut mascot, wireframe-wave footer, and the light section drop below the dark hero (two themes on one page).

### 11. Zed

- URL: https://zed.dev | Source: curated | Industry: devtools | In
- Shots: `shots/refs/zed-desktop.png`, `zed-mobile.png`
- Light mode done well: faint blueprint grid with registration-mark crosshairs at intersections, italic serif headline, keycap badges on buttons (D, C, S). Keycaps are a cheap, on-theme micro-detail.
- Three-column feature strip with hairline dividers.
- Do not copy: the pale blue wash; use the registration marks in the light theme only.

### 12. Resend

- URL: https://resend.com | Source: curated | Industry: devtools | In
- Shots: `shots/refs/resend-desktop.png`, `resend-mobile.png`
- Serif display (tight, high-contrast) against a Geist-like sans on pure black. Serif plus sans on dark is the editorial pairing most relevant to the redesign.
- Do not copy: the 3D cube render and gradient-on-text effect.

### 13. Exercism

- URL: https://exercism.org | Source: curated | Industry: education | In
- Shots: `shots/refs/exercism-desktop.png`, `exercism-mobile.png`
- Hexagon badges per language are a strong, ownable badge shape; yellow highlighter on one word in the headline.
- Do not copy: pastel illustration style or the purple primary. This is the generic friendly-edtech look the redesign should avoid.

## Patterns across references

- Mono is for function, serif or grotesk is for voice. Herzog, CryptoHack, Raycast and Zed all use monospace only for UI chrome, metadata and commands, never for paragraphs.
- Dark pages use 3 gray tones plus exactly one accent (Linear, Raycast, CryptoHack, Herzog's yellow). No second accent.
- Hairline rules and column labels beat cards. Grilli, Desourdy and Zed build structure from 1px lines and left-edge captions.
- Framed terminal window is the single permitted skeuomorph (Ghostty); everything else stays flat.
- Live activity (CryptoHack recent solves) and status icons (Linear) carry the gamified feel better than mascots.
- Schematic line art (Grilli test card, Zed registration marks) gives a classified-dossier tone without stock "hacker" imagery.
- Serif display on dark (Resend, Heatherwick) is a differentiator from the all-grotesk devtools norm.
- Keycaps, tickers and tiny tracked caps are cheap micro-details with high identity return.

## Blocked

- Hack The Box (https://www.hackthebox.com): Cookiebot consent modal covers the hero in the desktop shot; page content not assessable. Not described.

## Loaded but not cited

Vercel (light, product-less hero), Bandcamp and ArchDaily (loaded, not viewed; weak fit).
