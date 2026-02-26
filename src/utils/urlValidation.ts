/**
 * URL validation utilities for security-sensitive contexts
 */

/** Allowed domains for avatar URLs */
const ALLOWED_AVATAR_DOMAINS = [
  "lh3.googleusercontent.com", // Google profile pictures
  "avatars.githubusercontent.com", // GitHub profile pictures
  "gravatar.com", // Gravatar
  "www.gravatar.com",
  "i.pravatar.cc", // Pravatar (test avatars)
  "api.dicebear.com", // DiceBear avatars
  "images.unsplash.com", // Unsplash
  "supabase.co", // Supabase storage
  "supabase.com",
];

/**
 * Validates that a URL is safe to use as an avatar image.
 * Only allows HTTPS URLs from trusted domains.
 *
 * @param url - The URL to validate
 * @returns true if the URL is safe, false otherwise
 */
export function isValidAvatarUrl(url: string | null | undefined): boolean {
  if (!url) return false;

  try {
    const parsed = new URL(url);

    // Only allow HTTPS
    if (parsed.protocol !== "https:") {
      return false;
    }

    // Check against allowed domains
    const domain = parsed.hostname.toLowerCase();
    return ALLOWED_AVATAR_DOMAINS.some(
      (allowed) => domain === allowed || domain.endsWith("." + allowed),
    );
  } catch {
    // Invalid URL format
    return false;
  }
}

/**
 * Returns a sanitized avatar URL or undefined if invalid.
 * Use this when rendering user-provided avatar URLs.
 *
 * @param url - The URL to sanitize
 * @returns The URL if valid, undefined otherwise
 */
export function getSafeAvatarUrl(
  url: string | null | undefined,
): string | undefined {
  return isValidAvatarUrl(url) ? url! : undefined;
}
