# Visual Assets Coverage Ledger

| Area / Page Family                                  | Status             | Notes                                                                                                                 |
| --------------------------------------------------- | ------------------ | --------------------------------------------------------------------------------------------------------------------- |
| Brand Identity / Favicons                           | Improved           | Vector SVG favicon with dark/light scheme, raster 16/32/64/180/192/512 PNGs aligned with RangeMark reticle            |
| Social Preview (OG / Twitter)                       | Improved           | 1200x630 social card redesigned into Signal Range system, file size reduced >90% (53KB vs 580KB)                      |
| Offline Fallback (`offline.html`)                   | Improved           | Upgraded to Signal Range field manual aesthetic with lime action button and RangeMark reticle                         |
| Manifest & Metadata (`manifest.json`, `index.html`) | Improved           | Color scheme, SVG icon link, and metadata aligned with dark theme (#0c0d0b)                                           |
| Achievement Toasts (`AchievementToast.tsx`)         | Improved           | Added tactical insignia emblems (`Flame`, `CheckCircle2`, `Target`, `Award`) in calibrated housings                   |
| Promotion Toasts (`LevelUpToast.tsx`)               | Improved           | Added rank promotion chevron insignia in warning/gold tactical housing                                                |
| Clearance Certificate (`Certificate.tsx`)           | Improved           | Added security clearance guilloche watermark with reticle rings and signal quadrant                                   |
| Learning Paths (`/paths`)                           | Improved           | `PathCard` upgraded with tactical track insignia badges (`Shield`, `Server`, `Target`, `Users`, `FileCheck`, `Cloud`) |
| Path Detail (`/paths/:id`)                          | Improved           | `PathDetail` header upgraded with matching track insignia badge and cleaned status copy                               |
| CTF Challenges (`/ctf`)                             | Improved           | Unselected detail pane upgraded with tactical radar/target range grid visual                                          |
| Empty States (`EmptyState.tsx`)                     | Improved           | Replaced rounded pill inbox with calibrated instrument housing and reticle target                                     |
| Dashboard (`/`)                                     | Reviewed Unchanged | Hero `RangeInstrument` test card and telemetry grid are already high quality                                          |
| Next Badge Preview (`NextBadgePreview.tsx`)         | Improved           | Progress ring now reveals target badge insignia with tactical padlock indicator                                       |
| Profile Badges (`/profile`)                         | Improved           | `BadgeList` upgraded to render distinct insignia icons per badge instead of repeated generic ribbon                   |
| Lesson Views (`/modules/:id/:lessonId`)             | Reviewed Unchanged | Theory, Quiz, Lab with Monaco editor and Mermaid diagrams render correctly                                            |
| Final Exam (`/challenge`)                           | Reviewed Unchanged | HUD timer and question ticks already adhere to Signal Range                                                           |
| Leaderboard (`/leaderboard`)                        | Reviewed Unchanged | Clean tabular layout with local learner fallback                                                                      |
| Privacy & Terms (`/privacy`)                        | Reviewed Unchanged | Clean legal text with mono headings                                                                                   |
