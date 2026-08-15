# Security Trainer

> A gamified, hands-on cybersecurity training platform. Spy/agent theme, XP and levels, badges, streaks, and interactive code labs, not just reading material.

[![Live Demo](https://img.shields.io/badge/Live_Demo-000?style=for-the-badge&logo=vercel&logoColor=white)](https://security-trainer.vercel.app)
![React](https://img.shields.io/badge/React_19-000?style=flat-square&logo=react&logoColor=white)
![Vite](https://img.shields.io/badge/Vite-646CFF?style=flat-square&logo=vite&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white)
![Tailwind CSS](https://img.shields.io/badge/Tailwind-06B6D4?style=flat-square&logo=tailwindcss&logoColor=white)

## What It Does

Security Trainer teaches web security vulnerabilities and defensive coding through interactive lessons, in-browser code labs, quizzes, and CTF-style challenges, spread across 40+ modules covering the OWASP Top 10, auth and session flaws, injection attacks, cloud/container/API security, compliance basics (GDPR, HIPAA, PCI-DSS, SOC 2), phishing/social engineering, and AI security.

## Features

- Lesson modules with theory, quiz, and lab lesson types (`src/data/modules/`), covering topics from SQL injection and XSS to OAuth, JWT, GraphQL, race conditions, and supply chain security
- In-browser terminal simulator (xterm.js) for command-line style exercises
- Monaco-based code editor for hands-on labs, with a statically-defined verification registry (no dynamic code execution) in `src/utils/labVerification.ts`
- Mermaid diagrams for visualizing attack flows and architecture inside lessons
- CTF challenges page with flag hashing/validation utilities
- Gamification: XP, levels, badges/achievements, and streaks (`src/store/gameStore.ts`)
- Learning paths, a dashboard, leaderboard, and profile pages
- A Socratic-method AI tutor (Groq `llama-3.1-8b`, served by `api/socratic-hint.ts`) that nudges toward answers instead of giving them outright
- Supabase-backed auth and persistence, with Zustand + localStorage for local game state
- PostHog analytics (optional, enabled via env var, and skipped when the browser sends Do-Not-Track / Global Privacy Control)

## Getting Started

```bash
git clone https://github.com/forbiddenlink/security-trainer
cd security-trainer
pnpm install
pnpm dev
```

Copy `.env.example` to `.env.local` and fill in the values you need (Supabase, Groq, PostHog are all optional; the app runs without them, with reduced functionality).

### Scripts

```bash
pnpm dev              # Start dev server (Vite)
pnpm build            # Type-check and build for production
pnpm preview           # Preview the production build
pnpm lint             # ESLint
pnpm test             # Vitest (watch mode)
pnpm test:run         # Vitest (single run)
pnpm test:coverage    # Vitest with coverage
pnpm test:e2e         # Playwright end-to-end tests
```

## Tech Stack

- **Framework:** Vite + React 19 + React Router
- **Language:** TypeScript
- **Styling:** Tailwind CSS
- **State:** Zustand (persisted to localStorage)
- **Animation:** Framer Motion
- **Editor:** Monaco Editor (`@monaco-editor/react`)
- **Terminal:** xterm.js
- **Diagrams:** Mermaid
- **Backend/Auth:** Supabase
- **AI:** Groq (`llama-3.1-8b-instant`) via a rate-limited serverless endpoint
- **Testing:** Vitest + Testing Library, Playwright (e2e)
- **Analytics:** PostHog (optional, privacy-signal aware)
