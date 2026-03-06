# Security Trainer

A gamified web-based interactive learning platform for teaching web security vulnerabilities and defensive coding practices. Features a spy/agent theme with XP, levels, badges, and hands-on code labs.

**Live Demo:** [securitytrainer.vercel.app](https://securitytrainer.vercel.app)

## Features

- **29 Security Modules** - OWASP Top 10, API Security, OAuth 2.0, GraphQL, AI Security, Supply Chain, Container/K8s, Social Engineering, and more
- **Learning Paths** - 3 certification tracks: Web Fundamentals, API/Backend Security, Advanced Threats
- **Spaced Repetition** - SM-2 algorithm "Intel Refresher" system for 150% better retention
- **Hands-on Labs** - Interactive code editor with real-time verification
- **Gamification** - XP system, levels, daily challenges, streaks, and achievements
- **Leaderboard** - Compete with other security agents (requires Supabase)
- **Cloud Sync** - Save progress across devices (requires Supabase)
- **Dark/Light Mode** - System preference detection with manual override
- **Mobile Responsive** - Works on desktop and mobile devices
- **Accessibility** - WCAG compliant with ARIA labels, keyboard navigation

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm run dev

# Open http://localhost:5173
```

## Commands

| Command            | Description              |
| ------------------ | ------------------------ |
| `npm run dev`      | Start development server |
| `npm run build`    | Build for production     |
| `npm run preview`  | Preview production build |
| `npm run test`     | Run tests in watch mode  |
| `npm run test:run` | Run tests once           |
| `npm run lint`     | Run ESLint               |

## Tech Stack

- **Frontend:** React 19 + TypeScript 5.9
- **Build:** Vite 7.2
- **State:** Zustand (with localStorage persistence)
- **Styling:** Tailwind CSS 4.1
- **Animations:** Framer Motion
- **Code Editor:** Monaco Editor
- **Testing:** Vitest + Testing Library

## Optional: Cloud Features (Supabase)

To enable user authentication, cloud sync, and leaderboards:

### 1. Create a Supabase Project

1. Go to [supabase.com](https://supabase.com) and create a free project
2. Go to **Settings > API** and copy your Project URL and anon key

### 2. Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env` with your Supabase credentials:

```env
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your-anon-key
```

### 3. Set Up the Database

1. Go to **SQL Editor** in your Supabase dashboard
2. Run the contents of `supabase/schema.sql`

### 4. Enable Google OAuth (Optional)

1. Go to **Authentication > Providers**
2. Enable Google and add your OAuth credentials

## Project Structure

```
src/
├── components/    # Reusable UI components
├── pages/         # Route page components
├── layouts/       # Layout wrappers
├── store/         # Zustand state management
├── data/          # Static module/lesson content
├── types/         # TypeScript interfaces
├── utils/         # Utility functions (lab verification)
├── lib/           # External service clients
```

## Adding New Modules

1. Create a new file in `src/data/modules/` (e.g., `my-module.ts`)
2. Export a module definition following the existing pattern
3. Import and add it to the `MODULES` array in `src/data/modules/index.ts`
4. For labs, add a verifier to `src/utils/labVerification.ts`

## License

MIT
