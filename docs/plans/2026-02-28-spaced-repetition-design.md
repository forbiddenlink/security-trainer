# Spaced Repetition System Design

**Date:** 2026-02-28
**Status:** Approved

## Overview

Add an "Intel Refresher" system using SM-2 spaced repetition to help users retain security knowledge. Reviews appear on the dashboard as gentle reminders.

## Algorithm: SM-2

After completing a lesson, schedule reviews at increasing intervals:

- First review: 1 day
- Second review: 3 days
- Third review: 7 days
- Fourth+: 14, 30, 60 days (capped)

User rates recall after reviewing:

- **Easy** (5): Interval × 2.5, +20 XP
- **Good** (3): Interval × ease factor, +15 XP
- **Hard** (1): Reset to 1 day, +10 XP

## Data Structure

```typescript
interface LessonReview {
  lessonId: string;
  lastReviewDate: string; // ISO date
  nextReviewDate: string; // ISO date
  interval: number; // days
  easeFactor: number; // default 2.5
  reviewCount: number;
}

// Added to UserState
lessonReviews: Record<string, LessonReview>;
```

## UI Components

### Dashboard Section

- "Intel Refresher" card below daily challenge
- Shows lessons due for review (sorted by most overdue)
- Empty state shows next upcoming review

### Review Modal

- Appears after viewing a lesson that's due
- "Mission Debrief" themed
- Three buttons: Hard | Good | Easy
- Shows XP reward on selection

## Files to Modify

- `src/types/index.ts` - Add LessonReview type, extend UserState
- `src/store/gameStore.ts` - Add review state and actions
- `src/types/database.ts` - Add review fields for Supabase sync
- `src/pages/Dashboard.tsx` - Add IntelRefresher component

## Files to Create

- `src/utils/spacedRepetition.ts` - SM-2 calculations
- `src/components/IntelRefresher.tsx` - Dashboard section
- `src/components/ReviewModal.tsx` - Rating modal

## Implementation Phases

1. Types and algorithm utility
2. Store updates with actions
3. IntelRefresher dashboard component
4. ReviewModal component
5. Integration and testing
