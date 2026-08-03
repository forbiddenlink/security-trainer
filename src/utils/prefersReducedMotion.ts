/** True when the user has asked the OS to reduce motion. Guards non-Framer
 *  animations (e.g. canvas-confetti) that MotionConfig can't reach. */
export function prefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.matchMedia === "function" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
}
