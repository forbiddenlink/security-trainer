/**
 * User-related utility functions
 */

import type { Profile } from "../types/database";
import type { User } from "@supabase/supabase-js";

/**
 * Get display name from profile or user, with fallback
 */
export function getDisplayName(
  profile?: Profile | null,
  user?: User | null,
): string {
  if (profile?.display_name) {
    return profile.display_name;
  }
  if (user?.email) {
    return user.email.split("@")[0];
  }
  return "Agent";
}

/**
 * Get user initials for avatar display
 */
export function getUserInitials(
  profile?: Profile | null,
  user?: User | null,
): string {
  const name = getDisplayName(profile, user);
  return name.charAt(0).toUpperCase();
}
