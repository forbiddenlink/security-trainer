import { useEffect, useRef, useCallback } from "react";

/**
 * A hook that traps focus within a container element.
 * Useful for modals, dialogs, and other overlay components.
 *
 * @param isActive - Whether the focus trap is active
 * @param onEscape - Optional callback when Escape key is pressed
 * @returns A ref to attach to the container element
 */
export function useFocusTrap<T extends HTMLElement = HTMLDivElement>(
  isActive: boolean,
  onEscape?: () => void,
) {
  const containerRef = useRef<T>(null);
  const previousActiveElement = useRef<HTMLElement | null>(null);

  // Get all focusable elements within container
  const getFocusableElements = useCallback(() => {
    if (!containerRef.current) return [];

    const focusableSelectors = [
      "button:not([disabled])",
      "input:not([disabled])",
      "select:not([disabled])",
      "textarea:not([disabled])",
      "a[href]",
      "[tabindex]:not([tabindex='-1'])",
    ].join(", ");

    return Array.from(
      containerRef.current.querySelectorAll<HTMLElement>(focusableSelectors),
    ).filter((el) => el.offsetParent !== null); // Filter out hidden elements
  }, []);

  // Handle tab key to trap focus
  const handleKeyDown = useCallback(
    (event: KeyboardEvent) => {
      if (!isActive || !containerRef.current) return;

      // Handle Escape key
      if (event.key === "Escape" && onEscape) {
        event.preventDefault();
        onEscape();
        return;
      }

      // Handle Tab key
      if (event.key !== "Tab") return;

      const focusableElements = getFocusableElements();
      if (focusableElements.length === 0) return;

      const firstElement = focusableElements[0];
      const lastElement = focusableElements[focusableElements.length - 1];

      // Shift + Tab on first element -> focus last
      if (event.shiftKey && document.activeElement === firstElement) {
        event.preventDefault();
        lastElement.focus();
        return;
      }

      // Tab on last element -> focus first
      if (!event.shiftKey && document.activeElement === lastElement) {
        event.preventDefault();
        firstElement.focus();
        return;
      }

      // If focus is outside container, bring it back
      if (!containerRef.current.contains(document.activeElement)) {
        event.preventDefault();
        firstElement.focus();
      }
    },
    [isActive, onEscape, getFocusableElements],
  );

  // Set up focus trap when activated
  useEffect(() => {
    if (!isActive) return;

    // Store current focused element to restore later
    previousActiveElement.current = document.activeElement as HTMLElement;

    // Only auto-focus if focus is not already inside the container
    // This prevents stealing focus from inputs during tests or rapid interactions
    const focusableElements = getFocusableElements();
    if (
      focusableElements.length > 0 &&
      containerRef.current &&
      !containerRef.current.contains(document.activeElement)
    ) {
      // Small delay to ensure modal is rendered
      requestAnimationFrame(() => {
        // Double-check focus hasn't moved into container during the frame
        if (
          containerRef.current &&
          !containerRef.current.contains(document.activeElement)
        ) {
          focusableElements[0].focus();
        }
      });
    }

    // Add keydown listener
    document.addEventListener("keydown", handleKeyDown);

    // Cleanup
    return () => {
      document.removeEventListener("keydown", handleKeyDown);

      // Restore focus to previous element
      if (previousActiveElement.current?.focus) {
        previousActiveElement.current.focus();
      }
    };
  }, [isActive, getFocusableElements, handleKeyDown]);

  return containerRef;
}
