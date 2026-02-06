# Security Trainer - Project Guidelines

## Project Overview
A gamified web-based interactive learning platform for teaching web security vulnerabilities and defensive coding practices. Features a spy/agent theme with XP, levels, badges, and hands-on code labs.

## Tech Stack
- **Frontend**: React 19 + TypeScript 5.9
- **Build**: Vite 7.2
- **State**: Zustand (with localStorage persistence)
- **Styling**: Tailwind CSS 4.1
- **Animations**: Framer Motion
- **Editor**: Monaco Editor (for code labs)

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
```

## Key Patterns

### Lab Verification
Lab exercises are verified using a secure registry pattern in `src/utils/labVerification.ts`:
- All verification functions are statically defined (no dynamic code execution)
- Add new lab verifiers by lab ID to the `labVerifiers` object
- Each verifier receives the user's code string and returns boolean

### State Management
- Use Zustand store in `src/store/gameStore.ts`
- Transient UI state (like toasts) should be in store but excluded from persistence via `partialize`
- Trigger side effects (confetti, toasts) within store actions, not React effects

### Adding Modules
1. Add module definition to `src/data/modules.ts`
2. For labs, add corresponding verifier to `src/utils/labVerification.ts`
3. Use existing lesson types: `theory`, `quiz`, `lab`

## Commands
```bash
npm run dev      # Development server
npm run build    # Production build
npm run lint     # ESLint check
npm run preview  # Preview production build
```

## Code Standards
- Use React functional components with hooks
- Avoid dynamic code execution patterns - use the verification registry
- Follow existing Tailwind class naming conventions
- Use Lucide icons for consistency
