# SecTrainer competitor and feature research (Phase 2B)

Snapshot: 2026-10-02. Shots in `design-research/shots/competitors/` (`<slug>-desktop.png` and `-mobile.png`, above the fold only). Evidence tags: [seen] = on a loaded screenshot or extracted page text; [prior] = general knowledge of the product, not verified in this pass. Matrix uses Y / N / P (partial) / ? (not verified).

## Competitors

### 1. TryHackMe (https://tryhackme.com)

Loaded: home, /paths, /pricing. Shots: `tryhackme-home`, `tryhackme-paths`, `tryhackme-pricing`.

- Top nav: Learn, Practice, Compete, AI Upskilling, Education, Business, Pricing, Certifications, plus a search icon [seen].
- Learning paths as illustrated cards with difficulty tag (Easy/Intermediate) [seen]. Rooms are the unit of content [prior].
- Free tier: limited paths, free rooms only, 1 hr/day AttackBox (browser Linux VM) [seen].
- Premium (about $10.50/mo annual): full beginner paths, completion certificate per path, unlimited AttackBox, 15% cert discount. MAX: advanced and cloud paths, persistent AttackBox, Recent Threats labs, private King of the Hill games [seen].
- Compete section, king-of-the-hill games, hacking challenges [seen in plan table]. Streaks, badges, leaderboards, leagues [prior].
- Google one-click signup, "Beginner-friendly" and "Guides and challenges" trust chips [seen].
- Annual toggle with "5 months free", coupon field, business plans tab [seen].

### 2. Hack The Box Academy (https://academy.hackthebox.com)

Loaded: home, /catalogue. Shots: `htb-home`, `htb-catalog`.

- Nav: Certifications, Paths, Modules, Business, FAQ, News [seen].
- Hero promises guided training plus industry certifications; two cards (get certified, master skills) [seen].
- Catalogue cards show tier tags (Fundamental, Easy), track tags (Offensive, General) and section count (for example "20 Sections") [seen].
- Modules combine reading with embedded lab targets; cubes (in-app currency) unlock modules [prior]. Skill assessments and exams in browser VM [prior].
- Banner promotion for a new certification (HTB COAE) [seen].

### 3. PortSwigger Web Security Academy (https://portswigger.net/web-security)

Loaded: home, /all-materials, /sql-injection, /all-labs. Shots: `portswigger-home`, `-all`, `-sqli`, `-labs`.

- Fully free, "from the creators of Burp Suite" [seen]. Sub-nav: Dashboard, Learning paths, Latest topics, All content, Hall of Fame, Get started, Get certified [seen].
- Left sidebar topic tree with close button; "All labs" page grouped by vulnerability (SQLi, XSS, CSRF, SSRF, and 20+ more) [seen].
- Labs carry a difficulty badge (Apprentice, Practitioner, Expert) [seen].
- "Mystery lab challenge": random lab with title hidden, to train recon [seen].
- Persistent bottom Sign up / Login bar for logged-out users [seen].
- Progress tracking on dashboard, certification exam, Hall of Fame, solution write-ups per lab [prior except Hall of Fame and dashboard nav, seen].

### 4. Snyk Learn (https://learn.snyk.io)

Loaded: home, /catalog. Shots: `snyk-home`, `snyk-catalog`.

- Catalog has search, filter by Type (product training 64, security education 128), Format (learning paths 18, lessons 174) and Categories by language/topic (AI/ML, C#, C++, General...) [seen].
- Cards show LEARNING PATH label and duration ("-1hr 15mins") [seen].
- Browse-topics dropdown in header; "Start learning" single CTA [seen].
- Lessons interleave short explanation, code, and a quiz or fix-the-code step [prior]. Free account to track progress [prior].

### 5. Hacksplaining (https://www.hacksplaining.com)

Loaded: home, /lessons, /lessons/sql-injection. Shots: `hacksplaining-home`, `-lessons`, `-sqli`.

- Catalog: search box plus filter chips (All, LLM, OWASP Top 10, PCI DSS); "New" badges; 45 lessons [seen].
- Lesson landing page: time estimate (25-35 min), "Updated Sep 2026" stamp, named author, video explainer, Prevalence / Exploitability / Impact meters, "What you'll learn" checklist, mapping to OWASP A05 and PCI DSS clauses, "this includes" list (lab, prevention guide, 3-question quiz, sources), related lessons [seen].
- Primary CTAs: "Preview this lesson" (no signup) and "Sign up free to start the lab" [seen].
- Lab runs in-browser against a real database; passing the quiz marks lesson complete [seen].
- "Train your team" B2B CTA [seen].

### 6. OWASP Juice Shop (https://owasp-juice.shop)

Loaded: project home. Shot: `juice-home`. Demo app BLOCKED (503).

- Project site nav: Overview, Challenges, CTF, Learning, News [seen]. Badges for flagship status, GitHub stars, OpenSSF gold [seen].
- App itself (not loaded): score board of hacking challenges with difficulty stars, hints, CTF mode, flag codes, self-hosted via Docker [prior].

### 7. picoCTF / CyLab Security Academy (https://picoctf.org)

Loaded: home only. Shot: `picoctf-home`. Content BLOCKED.

- picoCTF.org now redirects to CMU "CyLab Security Academy" notice; legacy logins preserved, "Coming soon: picoCTF.com" [seen].
- Free platform positioned as "learn, compete, and grow" [seen]. Practice gym, annual CTF, scoreboards [prior].

### 8. Duolingo (https://www.duolingo.com) (gamification benchmark)

Loaded: home. Shot: `duolingo-home`.

- Single dominant CTA "Get started" with a low-commitment secondary "I already have an account" [seen].
- Mascot-led brand; course switcher strip (languages, chess, math) [seen].
- Product mechanics [prior]: daily streak with freeze, XP, leagues with weekly promotion, hearts, daily quests, friend streaks, short 3-5 minute lessons, onboarding that picks goal and level before signup wall.

### 9. Brilliant (https://brilliant.org)

Loaded: home, /courses. Shots: `brilliant-home`, `brilliant-courses`.

- Courses page is a set of "Learning Paths" shown as linked node chains with per-card grade band and "NEW" tag [seen].
- Interactive problems with immediate feedback, daily streaks, personalized course picks [prior].

### 10. Exercism (https://exercism.org)

Loaded: home, /tracks. Shots: `exercism-home`, `exercism-tracks`.

- Track catalog: search, Filter by, Sort by, "Showing all 83 tracks", per-track exercise counts, language tags, "Learning Mode" badge [seen].
- Free, human mentors, in-browser editor with tests, concept tree, badges and reputation [prior].

## Feature matrix

Columns: THM TryHackMe, HTB Hack The Box Academy, PS PortSwigger, SNK Snyk Learn, HKS Hacksplaining, JS Juice Shop, PCO picoCTF, DUO Duolingo, BRL Brilliant, EXE Exercism, ST SecTrainer (current).

| Feature                                      | THM | HTB | PS               | SNK | HKS | JS            | PCO | DUO | BRL | EXE | ST                                                                 |
| -------------------------------------------- | --- | --- | ---------------- | --- | --- | ------------- | --- | --- | --- | --- | ------------------------------------------------------------------ |
| Free tier usable without paying              | P   | P   | Y                | P   | P   | Y             | Y   | Y   | P   | Y   | Y                                                                  |
| Preview a lesson without signup              | ?   | ?   | Y                | ?   | Y   | Y             | N   | ?   | ?   | ?   | partial (guest works via localStorage)                             |
| Catalog text search                          | Y   | ?   | ?                | Y   | Y   | N             | ?   | N   | N   | Y   | Y (verified: Modules search box)                                   |
| Catalog filters (type, topic, level)         | P   | Y   | Y                | Y   | Y   | P             | ?   | N   | N   | Y   | P (verified: category chips only, no difficulty/type filter)       |
| Difficulty labels on cards                   | Y   | Y   | Y                | ?   | P   | Y             | Y   | N   | P   | N   | Y (verified)                                                       |
| Time estimate per lesson                     | N   | ?   | N                | Y   | Y   | N             | N   | ?   | ?   | N   | N (verified: no field in Module type)                              |
| Learning paths                               | Y   | Y   | Y                | Y   | N   | N             | N   | Y   | Y   | Y   | Y                                                                  |
| In-browser code editor                       | N   | N   | N                | ?   | N   | N             | N   | N   | N   | Y   | Y                                                                  |
| In-browser terminal / VM                     | Y   | Y   | N                | N   | N   | N             | N   | N   | N   | N   | Y (xterm, simulated)                                               |
| Hands-on labs                                | Y   | Y   | Y                | Y   | Y   | Y             | Y   | N   | N   | Y   | Y                                                                  |
| CTF challenges                               | Y   | Y   | N                | N   | N   | Y             | Y   | N   | N   | N   | Y                                                                  |
| AI hint tutor                                | ?   | ?   | N                | N   | N   | N             | N   | ?   | ?   | ?   | Y                                                                  |
| Quizzes                                      | Y   | Y   | N                | Y   | Y   | N             | N   | Y   | Y   | N   | Y                                                                  |
| Spaced repetition reviews                    | N   | N   | N                | N   | N   | N             | N   | Y   | N   | N   | Y                                                                  |
| Daily challenge / quests                     | Y   | ?   | N                | N   | N   | N             | N   | Y   | Y   | N   | Y                                                                  |
| XP and levels                                | Y   | Y   | N                | N   | N   | N             | N   | Y   | N   | N   | Y                                                                  |
| Badges                                       | Y   | Y   | N                | N   | N   | N             | Y   | Y   | Y   | Y   | Y                                                                  |
| Streaks                                      | Y   | ?   | N                | N   | N   | N             | N   | Y   | Y   | Y   | Y                                                                  |
| Leaderboard / leagues                        | Y   | Y   | Y (Hall of Fame) | N   | N   | N             | Y   | Y   | N   | P   | Y                                                                  |
| Activity heatmap                             | N   | N   | N                | N   | N   | N             | N   | N   | N   | Y   | Y                                                                  |
| Certificates                                 | Y   | Y   | Y                | Y   | N   | N             | N   | N   | N   | N   | Y                                                                  |
| Progress dashboard                           | Y   | Y   | Y                | Y   | Y   | Y             | Y   | Y   | Y   | Y   | Y                                                                  |
| Standards mapping (OWASP, PCI) on lesson     | N   | N   | N                | P   | Y   | Y             | N   | N   | N   | N   | partial (modules by topic)                                         |
| Vulnerability risk meters / "why it matters" | N   | N   | N                | N   | Y   | N             | N   | N   | N   | N   | N                                                                  |
| "What you'll learn" outcomes list            | Y   | Y   | N                | Y   | Y   | N             | N   | N   | N   | N   | N (verified)                                                       |
| Hint / solution write-ups                    | Y   | Y   | Y                | N   | N   | Y             | Y   | N   | N   | Y   | P (Socratic hints; labs carry solutionCode)                        |
| Random / mystery challenge                   | N   | N   | Y                | N   | N   | N             | N   | N   | N   | N   | N                                                                  |
| Video explainer                              | Y   | N   | Y                | N   | Y   | N             | N   | N   | N   | N   | Y (verified: VideoEmbed on several modules)                        |
| Mentor / community / forum                   | Y   | Y   | Y                | N   | N   | Y             | Y   | Y   | N   | Y   | N                                                                  |
| Social sign-in (Google, GitHub)              | Y   | Y   | N                | Y   | ?   | n/a           | ?   | Y   | Y   | Y   | N (email via Supabase)                                             |
| Gentle onboarding (goal, level pick)         | P   | P   | N                | N   | N   | N             | N   | Y   | Y   | P   | P (verified: role selector, no level pick or first-module handoff) |
| Light and dark theme                         | N   | N   | N                | N   | N   | Y (dark)      | N   | N   | N   | N   | Y                                                                  |
| Works offline / no account                   | N   | N   | N                | N   | N   | Y (self-host) | N   | N   | N   | N   | Y                                                                  |
| Team / business tier                         | Y   | Y   | Y                | Y   | Y   | N             | N   | N   | Y   | N   | N                                                                  |

## Gaps: features peers have that SecTrainer lacks

Ranked by peer count (of 10), then by likely impact on start-and-complete-a-module.

1. **Catalog filters beyond category** (difficulty, lesson type, duration, status): SecTrainer already has text search and category chips (verified), so the gap is difficulty/status/duration filtering. Snyk, Hacksplaining, Exercism are the clean models.
2. **Time estimate and "what you'll learn" outcome list on each module card and landing view**: Hacksplaining (25-35 min, three outcomes), Snyk (1hr 15mins), HTB (section counts). Lowers commitment cost before click, supports completion.
3. **Preview before signup** (Hacksplaining "Preview this lesson", PortSwigger open materials): reduces the signup wall. SecTrainer works as a guest already, so the gap is surfacing it: a visible "Try without account" start.
4. **Guided onboarding that picks goal and level, then lands on a first module** (Duolingo, Brilliant): no equivalent today. Directly targets first-module start rate.
5. **Standards mapping and risk context on module header** (Hacksplaining OWASP/PCI badge plus Prevalence / Exploitability / Impact meters; Juice Shop OWASP framing): gives motivation and credibility to developers and compliance-driven learners.
6. **Social sign-in** (Google or GitHub; 6 of 10): cuts signup friction for the optional auth path.
7. **Community, write-ups, and solutions after completion** (THM, HTB, PortSwigger, Juice Shop, picoCTF, Exercism): peers close the loop on stuck labs. A "show solution walkthrough" after lab completion is the low-cost slice.
8. **Mystery or random challenge mode** (PortSwigger): extends the daily challenge idea into replayable recon practice; low peer count (1) but cheap given the existing lab set.
9. Video explainer (THM, PortSwigger, Hacksplaining): costs production time, defer.
10. Team / business tier (7 of 10): out of scope for a free individual product unless monetization changes.

SecTrainer strengths relative to peers: the only entrant here combining AI Socratic hints, spaced repetition, and offline-capable guest use on a free tier; heatmap parity with Exercism; XP/streak parity with Duolingo.

## Blocked

- Secure Code Warrior (https://www.securecodewarrior.com): homepage loaded (`scw-home`), enterprise-only "Book a demo" funnel, no public catalog or lab; `/platform` returned 404 (`scw-pricing`). Not scored in matrix.
- OWASP Juice Shop demo app (https://demo.owasp-juice.shop): HTTP 503 "Application Error". Score board and challenge UI not seen.
- picoCTF play site (https://play.picoctf.org): DNS did not resolve; main domain now shows a CyLab Security Academy notice only.
- Not loaded behind login across all peers: lab runtimes, dashboards, in-lesson UI for THM, HTB, PortSwigger lab, Snyk lesson, Duolingo/Brilliant lesson flow. Items tagged [prior] or "?" come from general product knowledge, not this pass.
- Firecrawl credits exhausted; page text was extracted with local Playwright instead (TryHackMe pricing, Hacksplaining SQLi, PortSwigger, Snyk).
- SecTrainer column: rows marked "verified" were checked against the code on 2026-10-02 (`src/types/index.ts`, `src/pages/Modules.tsx`, `src/components/lesson/VideoEmbed.tsx`). Remaining cells come from the requester's feature list.
